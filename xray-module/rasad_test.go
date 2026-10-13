package dispatcher

import (
    "testing"
    "time"
    "github.com/xtls/xray-core/common/buf"
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
