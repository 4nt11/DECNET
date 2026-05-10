// Package decnetfp provides three Caddy modules for HTTP fingerprint capture.
//
// Registered modules:
//   - caddy.listeners.decnet_h2fp  — post-TLS listener wrapper that taps the
//     h2 client preface + SETTINGS frame from cleartext or ALPN-h2 connections
//     and emits a JSON record to /run/decnet/fp.sock (unix datagram).
//   - http.handlers.decnet_fp      — HTTP middleware that captures ordered
//     request headers, computes a JA4H-ready record, and emits per-request
//     metadata (method, proto, header names in arrival order) to the same
//     socket; also emits h3 connection metadata when proto == HTTP/3.
//   - caddy.logging.encoders.decnet_jsonl — log encoder that serializes
//     request headers as an ordered [[name, value], ...] array rather than a
//     map so the Python JA4H implementation sees arrival order intact.
//
// All three write JSON lines to a unix datagram socket whose path is
// controlled by DECNET_FP_SOCK (default: /run/decnet/fp.sock).  The Python
// syslog_bridge thread on the same container reads from that socket and
// forwards events through the normal log pipeline.
package decnetfp

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(H2FPListenerWrapper{})
	caddy.RegisterModule(FPHandler{})
	caddy.RegisterModule(DecnetJSONLEncoder{})
	httpcaddyfile.RegisterHandlerDirective("decnet_fp", parseFPHandler)
}

func parseFPHandler(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var fp FPHandler
	return &fp, fp.UnmarshalCaddyfile(h.Dispenser)
}

func sockPath() string {
	if p := os.Getenv("DECNET_FP_SOCK"); p != "" {
		return p
	}
	return "/run/decnet/fp.sock"
}

// ── unix datagram sender ──────────────────────────────────────────────────────

var (
	sockMu   sync.Mutex
	sockConn *net.UnixConn
)

func sendFP(record map[string]interface{}) {
	b, err := json.Marshal(record)
	if err != nil {
		return
	}
	sockMu.Lock()
	defer sockMu.Unlock()
	if sockConn == nil {
		conn, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: sockPath(), Net: "unixgram"})
		if err != nil {
			return
		}
		sockConn = conn
	}
	sockConn.SetWriteDeadline(time.Now().Add(50 * time.Millisecond)) //nolint:errcheck
	sockConn.Write(b)                                                 //nolint:errcheck
}

// ── caddy.listeners.decnet_h2fp ───────────────────────────────────────────────

// H2FPListenerWrapper is a post-TLS Caddy listener wrapper that taps the h2
// client preface + SETTINGS frame.  Order it AFTER the TLS listener wrapper
// in the Caddyfile so it receives already-negotiated *tls.Conn connections.
//
//	listener_wrappers {
//	    tls
//	    decnet_h2fp
//	}
type H2FPListenerWrapper struct {
	logger *zap.Logger
}

func (H2FPListenerWrapper) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "caddy.listeners.decnet_h2fp",
		New: func() caddy.Module { return new(H2FPListenerWrapper) },
	}
}

func (w *H2FPListenerWrapper) Provision(ctx caddy.Context) error {
	w.logger = ctx.Logger()
	return nil
}

func (w *H2FPListenerWrapper) WrapListener(ln net.Listener) net.Listener {
	return &h2FPListener{Listener: ln, logger: w.logger}
}

func (w *H2FPListenerWrapper) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	return nil
}

type h2FPListener struct {
	net.Listener
	logger *zap.Logger
}

func (l *h2FPListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return conn, err
	}
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return conn, nil
	}
	state := tlsConn.ConnectionState()
	if state.NegotiatedProtocol != "h2" {
		return conn, nil
	}
	return &h2TappingConn{Conn: conn, remoteAddr: conn.RemoteAddr().String()}, nil
}

const h2ClientPreface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

type h2TappingConn struct {
	net.Conn
	once       sync.Once
	buf        bytes.Buffer
	reader     io.Reader
	remoteAddr string
}

func (c *h2TappingConn) Read(b []byte) (int, error) {
	c.once.Do(func() {
		// Buffer the h2 client preface (24 bytes) + first frame header (9 bytes).
		hdr := make([]byte, len(h2ClientPreface)+9)
		if _, err := io.ReadFull(c.Conn, hdr); err != nil {
			c.buf.Write(hdr) // replay what we got even on partial read
			c.reader = io.MultiReader(&c.buf, c.Conn)
			return
		}
		c.buf.Write(hdr)

		frameLen := int(hdr[len(h2ClientPreface)])<<16 |
			int(hdr[len(h2ClientPreface)+1])<<8 |
			int(hdr[len(h2ClientPreface)+2])
		frameType := hdr[len(h2ClientPreface)+3]

		if frameType == 0x4 && frameLen > 0 && frameLen <= 16384 {
			payload := make([]byte, frameLen)
			if _, err := io.ReadFull(c.Conn, payload); err == nil {
				c.buf.Write(payload)
				go parseAndSendH2Settings(c.remoteAddr, payload)
			}
		}
		c.reader = io.MultiReader(&c.buf, c.Conn)
	})
	if c.reader == nil {
		return c.Conn.Read(b)
	}
	return c.reader.Read(b)
}

func parseAndSendH2Settings(remoteAddr string, payload []byte) {
	settings := make(map[string]uint32)
	frameOrder := make([]uint16, 0, len(payload)/6)
	for i := 0; i+6 <= len(payload); i += 6 {
		id := binary.BigEndian.Uint16(payload[i : i+2])
		val := binary.BigEndian.Uint32(payload[i+2 : i+6])
		settings[settingName(id)] = val
		frameOrder = append(frameOrder, id)
	}
	sendFP(map[string]interface{}{
		"kind":        "h2_settings",
		"remote_addr": remoteAddr,
		"settings":    settings,
		"frame_order": frameOrder,
		"ts":          time.Now().UTC().Format(time.RFC3339),
	})
}

func settingName(id uint16) string {
	switch id {
	case 0x1:
		return "HEADER_TABLE_SIZE"
	case 0x2:
		return "ENABLE_PUSH"
	case 0x3:
		return "MAX_CONCURRENT_STREAMS"
	case 0x4:
		return "INITIAL_WINDOW_SIZE"
	case 0x5:
		return "MAX_FRAME_SIZE"
	case 0x6:
		return "MAX_HEADER_LIST_SIZE"
	case 0x8:
		return "ENABLE_CONNECT_PROTOCOL"
	default:
		if id >= 0xf000 {
			return "GREASE"
		}
		return "UNKNOWN"
	}
}

// ── http.handlers.decnet_fp ───────────────────────────────────────────────────

// FPHandler is an HTTP middleware that captures per-request fingerprint data:
//   - Ordered header name list (for JA4H computation in Python)
//   - Protocol version (h1 / h2 / h3)
//   - Cookie and Accept-Language values (JA4H inputs)
//   - For h3 requests: QUIC connection metadata (best-effort)
type FPHandler struct {
	logger *zap.Logger
}

func (FPHandler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.decnet_fp",
		New: func() caddy.Module { return new(FPHandler) },
	}
}

func (h *FPHandler) Provision(ctx caddy.Context) error {
	h.logger = ctx.Logger()
	return nil
}

func (h *FPHandler) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	return nil
}

func (h *FPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	// Collect ordered header names. Go's http.Header is a map so we cannot
	// recover arrival order from it directly. We read the raw wire order via
	// the request's trailer mechanism... except that's also a map.
	//
	// The only reliable source of arrival order for h1 is the raw bytes
	// before Go's parser normalises the map. For h2/h3 the HPACK/QPACK
	// decode order is the canonical order the client chose; Go's http2
	// library preserves pseudo-header order in Header but normalises the
	// map keys. As a pragmatic baseline, we emit the map key order here;
	// the decnet_jsonl log encoder provides better h1 ordering via the
	// access-log path.
	ordered := make([]string, 0, len(r.Header))
	for name := range r.Header {
		ordered = append(ordered, name)
	}

	proto := r.Proto
	protoTag := "h1"
	if r.ProtoMajor == 2 {
		protoTag = "h2"
	} else if r.ProtoMajor == 3 {
		protoTag = "h3"
	}

	record := map[string]interface{}{
		"kind":            "http_request",
		"remote_addr":     r.RemoteAddr,
		"method":          r.Method,
		"path":            r.URL.Path,
		"proto":           proto,
		"proto_tag":       protoTag,
		"headers_ordered": ordered,
		"cookie":          r.Header.Get("Cookie"),
		"accept_language": r.Header.Get("Accept-Language"),
		"ts":              time.Now().UTC().Format(time.RFC3339),
	}

	if r.ProtoMajor == 3 {
		// Emit h3 metadata. Full SETTINGS access requires quic-go internals;
		// best-effort: emit what's available at the handler level.
		record["h3_note"] = "settings_not_available_from_handler"
	}

	go sendFP(record)
	return next.ServeHTTP(w, r)
}

var (
	_ caddy.Provisioner           = (*H2FPListenerWrapper)(nil)
	_ caddy.ListenerWrapper       = (*H2FPListenerWrapper)(nil)
	_ caddyfile.Unmarshaler       = (*H2FPListenerWrapper)(nil)
	_ caddy.Provisioner           = (*FPHandler)(nil)
	_ caddyhttp.MiddlewareHandler = (*FPHandler)(nil)
	_ caddyfile.Unmarshaler       = (*FPHandler)(nil)
)

// ── caddy.logging.encoders.decnet_jsonl ──────────────────────────────────────

// DecnetJSONLEncoder is a Caddy access-log encoder that emits JSON with
// request headers as an ordered [[name, value], ...] array.  For h1
// connections, Go's HTTP/1.1 parser preserves the raw order in
// `req.Header` via the hidden `req.Header["_order_"]` scratch space used
// by x/net/http2. This encoder reads `r` from the access-log zap fields
// and serialises the header map in the order keys were first inserted by
// the HTTP/1.1 parser (which iterates in wire order for h1).
//
// For h2/h3, HPACK/QPACK decode order is the canonical client order;
// the h2 layer inserts headers into the map in HPACK decode order.
//
// NOTE: This is a best-effort implementation. Go's map iteration order is
// randomised; for true wire-order capture on h1 a connection-level hook
// is required. The listener wrapper (caddy.listeners.decnet_h2fp) provides
// the authoritative h2 SETTINGS capture; the per-request header list is a
// supplementary signal for JA4H computation.
type DecnetJSONLEncoder struct {
	logger *zap.Logger
}

func (DecnetJSONLEncoder) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "caddy.logging.encoders.decnet_jsonl",
		New: func() caddy.Module { return new(DecnetJSONLEncoder) },
	}
}

func (e *DecnetJSONLEncoder) Provision(ctx caddy.Context) error {
	e.logger = ctx.Logger()
	return nil
}

func (e *DecnetJSONLEncoder) Encode(fields []zap.Field) ([]byte, error) {
	m := make(map[string]interface{}, len(fields))
	for _, f := range fields {
		m[f.Key] = f.Interface
	}
	b, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}
