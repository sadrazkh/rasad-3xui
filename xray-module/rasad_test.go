package dispatcher

import (
    "context"
    "encoding/json"
    "os"
    "path/filepath"
    "testing"
    "time"
    "github.com/xtls/xray-core/common/buf"
    "github.com/xtls/xray-core/common/net"
    "github.com/xtls/xray-core/common/protocol"
    "github.com/xtls/xray-core/common/session"
    "github.com/xtls/xray-core/transport"
)

type rasadTestReader struct {}
func (*rasadTestReader) ReadMultiBuffer() (buf.MultiBuffer,error) {
    b:=buf.New(); _,_=b.Write([]byte("12345")); return buf.MultiBuffer{b},nil
}
type rasadTestWriter struct {}
func (*rasadTestWriter) WriteMultiBuffer(mb buf.MultiBuffer) error { buf.ReleaseMulti(mb); return nil }

func TestRasadCountsAndRevokes(t *testing.T) {
    h:=&rasadHub{rows:make(map[string]*rasadRow)}
    h.policy.Store(&rasadPolicy{Enabled:true,Expires:time.Now().Unix()+60,Users:map[string]int64{"alice":1}})
    row:=h.row("alice","example.com",1)
    reader:=&rasadReader{&rasadTestReader{},row,h}
    writer:=&SizeStatWriter{Counter:&rasadDownCounter{nil,row,h},Writer:&rasadTestWriter{}}
    mb,_:=reader.ReadMultiBuffer(); _=writer.WriteMultiBuffer(mb)
    if row.up.Load()!=5 || row.down.Load()!=5 { t.Fatal("incorrect payload counts") }
    h.policy.Store(&rasadPolicy{Enabled:false,Expires:time.Now().Unix()+60,Users:map[string]int64{"alice":1}})
    mb,_=reader.ReadMultiBuffer(); _=writer.WriteMultiBuffer(mb)
    if row.up.Load()!=5 || row.down.Load()!=5 { t.Fatal("disabled policy still counts") }
    h.policy.Store(&rasadPolicy{Enabled:true,Expires:time.Now().Unix()+60,Users:map[string]int64{"alice":2}})
    mb,_=reader.ReadMultiBuffer(); _=writer.WriteMultiBuffer(mb)
    if row.up.Load()!=5 || row.down.Load()!=5 { t.Fatal("revoked generation still counts") }
}

type rasadTestCounter struct { value int64 }
func (c *rasadTestCounter) Add(v int64) int64 { old:=c.value;c.value+=v;return old }
func (c *rasadTestCounter) Value() int64 { return c.value }
func (c *rasadTestCounter) Set(v int64) int64 { old:=c.value;c.value=v;return old }

func TestRasadNativeSpliceCounterPreservesPanelStats(t *testing.T) {
    h:=&rasadHub{rows:make(map[string]*rasadRow)}
    h.policy.Store(&rasadPolicy{Enabled:true,Expires:time.Now().Unix()+60,Users:map[string]int64{"alice":1}})
    row:=h.row("alice","example.com",1)
    original:=&rasadTestCounter{}
    combined:=&rasadDownCounter{original,row,h}
    combined.Add(1024) // same call made by native CopyRawConn splice
    if original.Value()!=1024 || row.down.Load()!=1024 { t.Fatal("splice or user stats dropped/double counted") }
    combined.Set(0)
    if original.Value()!=0 || row.down.Load()!=1024 { t.Fatal("panel reset must preserve destination telemetry") }
}

func TestRasadCardinalityLimit(t *testing.T) {
    h:=&rasadHub{rows:make(map[string]*rasadRow)}
    for i:=0;i<8192;i++ { h.rows[string(rune(i))]=&rasadRow{} }
    if h.row("alice","overflow.example",1)!=nil || h.dropped.Load()!=1 { t.Fatal("limit must fail open for traffic, closed for recording") }
}

func TestRasadDestinationClassification(t *testing.T) {
    for _,test:=range []struct{ target net.Destination;want string }{
        {net.TCPDestination(net.DomainAddress("Example.COM."),443),"example.com"},
        {net.TCPDestination(net.ParseAddress("127.0.0.1"),443),"__unknown_tcp__"},
        {net.UDPDestination(net.DomainAddress("sniffed.example"),443),"__unknown_udp__"},
        {net.UDPDestination(net.ParseAddress("127.0.0.1"),443),"__unknown_udp__"},
    } {
        if got:=rasadDestinationDomain(test.target);got!=test.want { t.Fatalf("got %s, want %s",got,test.want) }
    }
}

type rasadTestTimeoutReader struct { rasadTestReader }
func (r *rasadTestTimeoutReader) ReadMultiBufferTimeout(time.Duration) (buf.MultiBuffer,error) { return r.ReadMultiBuffer() }

func TestRasadWrapPreservesTimeoutAndNativeWriter(t *testing.T) {
    h:=&rasadHub{rows:make(map[string]*rasadRow)}
    h.policy.Store(&rasadPolicy{Enabled:true,Expires:time.Now().Unix()+60,Users:map[string]int64{"alice":1}})
    previous:=rasad;rasad=h;defer func(){rasad=previous}()
    original:=&rasadTestCounter{}
    link:=&transport.Link{Reader:&rasadTestTimeoutReader{},Writer:&SizeStatWriter{Counter:original,Writer:&rasadTestWriter{}}}
    ctx:=session.ContextWithInbound(context.Background(),&session.Inbound{User:&protocol.MemoryUser{Email:"alice"}})
    target:=net.TCPDestination(net.DomainAddress("sniffed.example"),443)
    ctx=rasadWrap(ctx,link,target)
    reader,ok:=link.Reader.(buf.TimeoutReader)
    if !ok { t.Fatal("timeout capability lost") }
    writer,ok:=link.Writer.(*SizeStatWriter)
    if !ok { t.Fatal("native splice writer type lost") }
    mb,err:=reader.ReadMultiBufferTimeout(0);if err!=nil {t.Fatal(err)}
    if err=writer.WriteMultiBuffer(mb);err!=nil {t.Fatal(err)}
    row:=h.rows["alice\x00sniffed.example"]
    if row.up.Load()!=5 || row.down.Load()!=5 || original.Value()!=5 {t.Fatal("first payload counted incorrectly")}
    sameReader,sameWriter:=link.Reader,link.Writer
    rasadWrap(ctx,link,target)
    if sameReader!=link.Reader || sameWriter!=link.Writer || row.connections.Load()!=1 {t.Fatal("nested dispatch double wrapped")}
    h.policy.Store(&rasadPolicy{Enabled:false,Expires:time.Now().Unix()+60,Users:map[string]int64{"alice":1}})
    writer.Counter.Add(7)
    if row.down.Load()!=5 || original.Value()!=12 {t.Fatal("disable changed panel stats or kept collecting")}
}

func TestRasadUsersAndFirstSnapshotTimestamps(t *testing.T) {
    now:=time.Now().Unix()
    h:=&rasadHub{rows:make(map[string]*rasadRow),startedAt:now,metricsPath:filepath.Join(t.TempDir(),"metrics.json")}
    h.policy.Store(&rasadPolicy{Enabled:true,Expires:now+60,Users:map[string]int64{"alice":1,"bob":2}})
    alice,bob:=h.row("alice","example.com",1),h.row("bob","example.com",2)
    alice.up.Add(17);bob.down.Add(29);h.flush()
    raw,err:=os.ReadFile(h.metricsPath);if err!=nil {t.Fatal(err)}
    var snapshot struct { StartedAt int64 `json:"started_at"`;TS int64 `json:"ts"`;Rows []rasadSnapshotRow `json:"rows"` }
    if err=json.Unmarshal(raw,&snapshot);err!=nil {t.Fatal(err)}
    if snapshot.StartedAt!=now || len(snapshot.Rows)!=2 {t.Fatal("first snapshot metadata missing")}
    for _,row:=range snapshot.Rows {
        if row.FirstTS<snapshot.StartedAt || row.FirstTS>snapshot.TS {t.Fatal("invalid first timestamp")}
        if row.Email=="alice" && (row.Up!=17 || row.Down!=0) || row.Email=="bob" && (row.Up!=0 || row.Down!=29) {t.Fatal("user totals mixed")}
    }
    replacement:=h.row("alice","example.com",3)
    if replacement==alice || replacement.up.Load()!=0 || replacement.firstTS<now {t.Fatal("new consent generation reused old metrics")}
}

func TestRasadPolicyBoundsFailClosed(t *testing.T) {
    root:=t.TempDir()
    h:=&rasadHub{rows:make(map[string]*rasadRow),policyPath:filepath.Join(root,"policy.json")}
    for _,payload:=range []string{
        `{"enabled":true,"expires":9999999999,"users":{"alice":0}}`,
        `{"enabled":true,"expires":9999999999,"users":{"alice":1}`, // invalid JSON
        string(make([]byte,1024*1024+1)),
    } {
        if err:=os.WriteFile(h.policyPath,[]byte(payload),0600);err!=nil {t.Fatal(err)}
        h.refresh()
        if h.policy.Load().Enabled {t.Fatal("invalid or oversized policy enabled recording")}
    }
}

func TestRasadSnapshotDoesNotFollowPredictableTempSymlink(t *testing.T) {
    root:=t.TempDir()
    victim:=filepath.Join(root,"unrelated-file")
    expected:=[]byte("must stay unchanged")
    if err:=os.WriteFile(victim,expected,0600);err!=nil {t.Fatal(err)}
    h:=&rasadHub{rows:make(map[string]*rasadRow),metricsPath:filepath.Join(root,"metrics.json"),startedAt:time.Now().Unix()}
    h.policy.Store(&rasadPolicy{})
    if err:=os.Symlink(victim,h.metricsPath+".tmp");err!=nil {t.Skip("symlinks unavailable:",err)}
    h.flush()
    got,err:=os.ReadFile(victim);if err!=nil {t.Fatal(err)}
    if string(got)!=string(expected) {t.Fatal("snapshot overwrote predictable symlink target")}
    if _,err=os.Stat(h.metricsPath);err!=nil {t.Fatal("atomic snapshot not written:",err)}
}

func TestRasadDeletedPolicyCannotReactivateDetachedFlow(t *testing.T) {
    now:=time.Now().Unix()
    h:=&rasadHub{rows:make(map[string]*rasadRow),policyPath:filepath.Join(t.TempDir(),"policy.json")}
    active:=&rasadPolicy{Enabled:true,Expires:now+60,Users:map[string]int64{"alice":1}}
    h.policy.Store(active)
    old:=h.row("alice","example.com",1)
    h.refresh() // absent policy retires all existing flow references
    h.policy.Store(active) // dashboard returns with the same consent generation
    if h.active(old) {t.Fatal("detached flow reactivated without an exported row")}
    fresh:=h.row("alice","example.com",1)
    if fresh==old || !h.active(fresh) {t.Fatal("reconnected flow did not resume recording")}
}
