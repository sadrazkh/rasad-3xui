// Optional Rasad dispatcher telemetry. No network requests or payload copies.
// Added to app/dispatcher in a pinned upstream checkout by apply.py.
package dispatcher

import (
    "context"
    "crypto/rand"
    "encoding/hex"
    "encoding/json"
    "os"
    "strings"
    "sync"
    "sync/atomic"
    "time"

    "github.com/xtls/xray-core/common"
    "github.com/xtls/xray-core/common/buf"
    "github.com/xtls/xray-core/common/net"
    "github.com/xtls/xray-core/common/session"
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
    up, down, connections atomic.Int64
}
type rasadHub struct {
    mu sync.Mutex
    policy atomic.Pointer[rasadPolicy]
    rows map[string]*rasadRow
    dropped atomic.Int64
    boot, policyPath, metricsPath string
}
var rasad *rasadHub

func init() {
    policy, metrics := os.Getenv("RASAD_POLICY"), os.Getenv("RASAD_METRICS")
    if policy == "" || metrics == "" { return }
    h := &rasadHub{rows:make(map[string]*rasadRow),policyPath:policy,metricsPath:metrics}
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
    raw,err := os.ReadFile(h.policyPath)
    p := &rasadPolicy{}
    if err == nil && len(raw) <= 1024*1024 {
        if json.Unmarshal(raw,p) != nil || p.Expires < time.Now().Unix() || len(p.Users)>1024 { p = &rasadPolicy{} }
    }
    h.policy.Store(p) // fail closed when the dashboard/policy is unavailable
    h.mu.Lock()
    for key,row := range h.rows {
        if p.Users[row.email] != row.generation { delete(h.rows,key) }
    }
    h.mu.Unlock()
}

func (h *rasadHub) active(row *rasadRow) bool {
    p := h.policy.Load()
    return p != nil && p.Enabled && p.Expires >= time.Now().Unix() && p.Users[row.email]==row.generation
}

func (h *rasadHub) row(email,domain string,generation int64) *rasadRow {
    key := email+"\x00"+domain
    h.mu.Lock()
    defer h.mu.Unlock()
    if row := h.rows[key]; row != nil && row.generation==generation { return row }
    // Global hard cap; omitted flows are counted explicitly, never fabricated.
    if len(h.rows)>=8192 { h.dropped.Add(1); return nil }
    row := &rasadRow{email:email,domain:domain,generation:generation}
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
}

func (h *rasadHub) flush() {
    p := h.policy.Load()
    rows := make([]rasadSnapshotRow,0)
    h.mu.Lock()
    for _,r := range h.rows {
        if p != nil && p.Users[r.email]==r.generation {
            rows=append(rows,rasadSnapshotRow{r.email,r.domain,r.generation,r.up.Load(),r.down.Load(),r.connections.Load()})
        }
    }
    h.mu.Unlock()
    payload := struct {
        Version int `json:"version"`
        Boot string `json:"boot"`
        TS int64 `json:"ts"`
        Dropped int64 `json:"dropped_flows"`
        Rows []rasadSnapshotRow `json:"rows"`
    }{1,h.boot,time.Now().Unix(),h.dropped.Load(),rows}
    raw,err := json.Marshal(payload)
    if err != nil || len(raw)>4*1024*1024 { return }
    temp := h.metricsPath+".tmp"
    if err=os.WriteFile(temp,raw,0640); err != nil { return }
    _=os.Rename(temp,h.metricsPath)
}

type rasadReader struct { buf.Reader; row *rasadRow; hub *rasadHub }
func (r *rasadReader) ReadMultiBuffer() (buf.MultiBuffer,error) {
    mb,err := r.Reader.ReadMultiBuffer()
    if r.hub.active(r.row) { r.row.up.Add(int64(mb.Len())) }
    return mb,err
}
func (r *rasadReader) Interrupt() { common.Interrupt(r.Reader) }
func (r *rasadReader) Close() error { return common.Close(r.Reader) }

type rasadWriter struct { buf.Writer; row *rasadRow; hub *rasadHub }
func (w *rasadWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
    // Count payload passed through dispatch, matching Xray's SizeStatWriter
    // basis. These are not physical-link bytes or confirmed delivered bytes.
    if w.hub.active(w.row) { w.row.down.Add(int64(mb.Len())) }
    return w.Writer.WriteMultiBuffer(mb)
}
func (w *rasadWriter) Interrupt() { common.Interrupt(w.Writer) }
func (w *rasadWriter) Close() error { return common.Close(w.Writer) }

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
    if !ok { return ctx }
    domain := "__unknown_tcp__"
    if destination.Address.Family().IsDomain() {
        domain=strings.TrimSuffix(strings.ToLower(destination.Address.Domain()),".")
    }
    // Mux's outer carrier is not a destination; its inner dispatcher does the counting.
    if domain=="v1.mux.cool" { return ctx }
    // UDP per-buffer destinations can differ from the dispatch target. Do not
    // label all of those bytes as a single website.
    if destination.Network != net.Network_TCP { domain="__unknown_udp__" }
    if len(domain)>253 { domain="__unknown_tcp__" }
    row := h.row(email,domain,generation)
    if row==nil { return ctx }
    row.connections.Add(1)
    link.Reader=&rasadReader{link.Reader,row,h}
    link.Writer=&rasadWriter{link.Writer,row,h}
    return context.WithValue(ctx,rasadContextKey{},true)
}
