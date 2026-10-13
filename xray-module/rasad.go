// Optional Rasad dispatcher telemetry. No network requests or payload copies.
// Added to app/dispatcher in a pinned upstream checkout by apply.py.
package dispatcher

import (
    "context"
    "crypto/rand"
    "encoding/hex"
    "encoding/json"
    "io"
    "os"
    "path/filepath"
    "strings"
    "sync"
    "sync/atomic"
    "time"

    "github.com/xtls/xray-core/common"
    "github.com/xtls/xray-core/common/buf"
    "github.com/xtls/xray-core/common/net"
    "github.com/xtls/xray-core/common/session"
    "github.com/xtls/xray-core/features/stats"
    "github.com/xtls/xray-core/transport"
)

type rasadPolicy struct {
    Enabled bool `json:"enabled"`
    Expires int64 `json:"expires"`
    Users map[string]int64 `json:"users"`
}
type rasadRow struct {
    email, domain string
    generation int64
    firstTS int64
    up, down, connections atomic.Int64
    retired atomic.Bool
}
type rasadHub struct {
    mu sync.Mutex
    policy atomic.Pointer[rasadPolicy]
    rows map[string]*rasadRow
    dropped atomic.Int64
    boot, policyPath, metricsPath string
    startedAt int64
}
var rasad *rasadHub

func init() {
    policy, metrics := os.Getenv("RASAD_POLICY"), os.Getenv("RASAD_METRICS")
    if policy == "" || metrics == "" { return }
    h := &rasadHub{rows:make(map[string]*rasadRow),policyPath:policy,metricsPath:metrics,startedAt:time.Now().Unix()}
    id := make([]byte,16)
    if _,err := rand.Read(id); err != nil { return }
    h.boot = hex.EncodeToString(id)
    h.policy.Store(&rasadPolicy{})
    rasad = h
    go func() {
        ticker := time.NewTicker(5*time.Second)
        defer ticker.Stop()
        cycles := 0
        for range ticker.C {
            h.refresh()
            cycles++
            if cycles%3 == 0 { h.flush() }
        }
    }()
}

func (h *rasadHub) refresh() {
    // Bound the read itself; rejecting a huge file after ReadFile is too late.
    file,err := os.Open(h.policyPath)
    var raw []byte
    if err==nil {
        raw,err=io.ReadAll(io.LimitReader(file,1024*1024+1))
        _=file.Close()
    }
    p := &rasadPolicy{}
    if err == nil && len(raw) <= 1024*1024 {
        if json.Unmarshal(raw,p) != nil || p.Expires < time.Now().Unix() || len(p.Users)>1024 { p = &rasadPolicy{} }
        for email,generation := range p.Users {
            if email=="" || len(email)>320 || generation<=0 { p=&rasadPolicy{};break }
        }
    }
    h.policy.Store(p) // fail closed when the dashboard/policy is unavailable
    h.mu.Lock()
    for key,row := range h.rows {
        if p.Users[row.email] != row.generation { row.retired.Store(true);delete(h.rows,key) }
    }
    h.mu.Unlock()
}

func (h *rasadHub) active(row *rasadRow) bool {
    p := h.policy.Load()
    return !row.retired.Load() && p != nil && p.Enabled && p.Expires >= time.Now().Unix() && p.Users[row.email]==row.generation
}

func (h *rasadHub) row(email,domain string,generation int64) *rasadRow {
    key := email+"\x00"+domain
    h.mu.Lock()
    defer h.mu.Unlock()
    if row := h.rows[key]; row != nil {
        if row.generation==generation { return row }
        row.retired.Store(true)
        delete(h.rows,key)
    }
    // Global hard cap; omitted flows are counted explicitly, never fabricated.
    if len(h.rows)>=8192 { h.dropped.Add(1); return nil }
    row := &rasadRow{email:email,domain:domain,generation:generation,firstTS:time.Now().Unix()}
    h.rows[key]=row
    return row
}

type rasadSnapshotRow struct {
    Email string `json:"email"`
    Domain string `json:"domain"`
    Generation int64 `json:"generation"`
    Up int64 `json:"up"`
    Down int64 `json:"down"`
    Connections int64 `json:"connections"`
    FirstTS int64 `json:"first_ts"`
}

func (h *rasadHub) flush() {
    p := h.policy.Load()
    rows := make([]rasadSnapshotRow,0)
    h.mu.Lock()
    for _,r := range h.rows {
        if p != nil && p.Users[r.email]==r.generation {
            rows=append(rows,rasadSnapshotRow{r.email,r.domain,r.generation,r.up.Load(),r.down.Load(),r.connections.Load(),r.firstTS})
        }
    }
    h.mu.Unlock()
    payload := struct {
        Version int `json:"version"`
        Boot string `json:"boot"`
        TS int64 `json:"ts"`
        Dropped int64 `json:"dropped_flows"`
        Rows []rasadSnapshotRow `json:"rows"`
        StartedAt int64 `json:"started_at"`
    }{1,h.boot,time.Now().Unix(),h.dropped.Load(),rows,h.startedAt}
    raw,err := json.Marshal(payload)
    if err != nil || len(raw)>4*1024*1024 { return }
    // Xray may run as root while the shared directory belongs to rasad.
    // O_EXCL temporary creation avoids following a predictable symlink.
    temp,err:=os.CreateTemp(filepath.Dir(h.metricsPath),".rasad-metrics-*")
    if err!=nil { return }
    name:=temp.Name()
    defer os.Remove(name)
    if err=temp.Chmod(0640);err!=nil { _=temp.Close();return }
    _,writeErr:=temp.Write(raw)
    closeErr:=temp.Close()
    if writeErr!=nil || closeErr!=nil { return }
    _=os.Rename(name,h.metricsPath)
}

type rasadReader struct { buf.Reader; row *rasadRow; hub *rasadHub }
func (r *rasadReader) ReadMultiBuffer() (buf.MultiBuffer,error) {
    mb,err := r.Reader.ReadMultiBuffer()
    if r.hub.active(r.row) { r.row.up.Add(int64(mb.Len())) }
    return mb,err
}
func (r *rasadReader) Interrupt() { common.Interrupt(r.Reader) }
func (r *rasadReader) Close() error { return common.Close(r.Reader) }

// Preserve first-payload batching for outbounds that use TimeoutReader.
// Only expose this interface when the underlying reader already supports it.
type rasadTimeoutReader struct { *rasadReader; timeoutReader buf.TimeoutReader }
func (r *rasadTimeoutReader) ReadMultiBufferTimeout(timeout time.Duration) (buf.MultiBuffer,error) {
    mb,err:=r.timeoutReader.ReadMultiBufferTimeout(timeout)
    if r.hub.active(r.row) { r.row.up.Add(int64(mb.Len())) }
    return mb,err
}

func rasadDestinationDomain(destination net.Destination) string {
    // A UDP link may carry many per-buffer endpoints, including XUDP. Its
    // initial sniffed name alone cannot label all of those bytes reliably.
    if destination.Network != net.Network_TCP { return "__unknown_udp__" }
    if destination.Address==nil || !destination.Address.Family().IsDomain() { return "__unknown_tcp__" }
    domain:=strings.TrimSuffix(strings.ToLower(destination.Address.Domain()),".")
    if domain=="" || len(domain)>253 || strings.ContainsAny(domain," /\\\t\r\n\x00:") { return "__unknown_tcp__" }
    return domain
}

// Keep the native SizeStatWriter type so Xray's zero-copy splice path can
// update the destination counter without disabling splice or missing bytes.
type rasadDownCounter struct { upstream stats.Counter; row *rasadRow; hub *rasadHub }
func (c *rasadDownCounter) Add(value int64) int64 {
    old := c.row.down.Load()
    if value>0 && c.hub.active(c.row) { old=c.row.down.Add(value)-value }
    if c.upstream!=nil { return c.upstream.Add(value) }
    return old
}
func (c *rasadDownCounter) Value() int64 {
    if c.upstream!=nil { return c.upstream.Value() }
    return c.row.down.Load()
}
func (c *rasadDownCounter) Set(value int64) int64 {
    // Resetting the panel's user counter must not reset independent telemetry.
    if c.upstream!=nil { return c.upstream.Set(value) }
    return c.row.down.Load()
}

type rasadContextKey struct{}
func rasadWrap(ctx context.Context,link *transport.Link,destination net.Destination) context.Context {
    h := rasad
    if h==nil || ctx.Value(rasadContextKey{}) != nil { return ctx }
    inbound := session.InboundFromContext(ctx)
    if inbound==nil || inbound.User==nil || inbound.User.Email=="" { return ctx }
    email := inbound.User.Email
    p := h.policy.Load()
    if p==nil || !p.Enabled || p.Expires<time.Now().Unix() { return ctx }
    generation,ok := p.Users[email]
    if !ok || generation<=0 || len(email)>320 { return ctx }
    // This hook runs after existing sniffing, so destination also contains a
    // routeOnly domain while Target/OriginalTarget retain the actual IP.
    // Mux's outer carrier is not a destination; its inner dispatcher does the counting.
    if destination.Address!=nil && destination.Address.Family().IsDomain() && strings.EqualFold(strings.TrimSuffix(destination.Address.Domain(),"."),"v1.mux.cool") { return ctx }
    domain := rasadDestinationDomain(destination)
    row := h.row(email,domain,generation)
    if row==nil { return ctx }
    row.connections.Add(1)
    reader:=&rasadReader{link.Reader,row,h}
    if timeoutReader,ok:=link.Reader.(buf.TimeoutReader);ok {
        link.Reader=&rasadTimeoutReader{reader,timeoutReader}
    } else { link.Reader=reader }
    if native,ok := link.Writer.(*SizeStatWriter); ok {
        link.Writer=&SizeStatWriter{Counter:&rasadDownCounter{native.Counter,row,h},Writer:native.Writer}
    } else {
        link.Writer=&SizeStatWriter{Counter:&rasadDownCounter{nil,row,h},Writer:link.Writer}
    }
    return context.WithValue(ctx,rasadContextKey{},true)
}
