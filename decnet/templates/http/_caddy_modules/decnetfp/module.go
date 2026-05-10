// Package decnetfp provides Caddy modules for HTTP fingerprint capture.
//
// Registered modules:
//   - caddy.listeners.decnet_fp      — post-TLS listener wrapper that taps
//     the h2 client preface (SETTINGS + HEADERS frames via persistent HPACK
//     decoder) and h1 request-line / header bytes, emitting ordered header
//     name lists to /run/decnet/fp.sock (unix datagram).
//   - http.handlers.decnet_fp        — HTTP middleware that emits an
//     access_log record (status code, bytes, protocol) after each response.
//   - caddy.logging.encoders.decnet_jsonl — log encoder stub (registered
//     but not wired into Caddyfile; access_log comes from the handler above).
//
// All modules write JSON lines to a unix datagram socket whose path is
// controlled by DECNET_FP_SOCK (default: /run/decnet/fp.sock).
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
	"golang.org/x/net/http2/hpack"
)

func init() {
	caddy.RegisterModule(FPListenerWrapper{})
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

// ── caddy.listeners.decnet_fp ─────────────────────────────────────────────────

// FPListenerWrapper is a post-TLS Caddy listener wrapper that:
//   - For h2 ALPN connections: taps the h2 client preface (SETTINGS frame)
//     and then continuously parses HEADERS/CONTINUATION frames via a
//     persistent HPACK decoder, emitting ordered header name lists.
//   - For h1 ALPN connections (or plain connections): taps the first request's
//     header bytes, emitting ordered header names from the wire.
//
// Place it AFTER the TLS listener wrapper so it sees post-TLS data:
//
//	listener_wrappers {
//	    tls
//	    decnet_fp
//	}
type FPListenerWrapper struct {
	logger *zap.Logger
}

func (FPListenerWrapper) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "caddy.listeners.decnet_fp",
		New: func() caddy.Module { return new(FPListenerWrapper) },
	}
}

func (w *FPListenerWrapper) Provision(ctx caddy.Context) error {
	w.logger = ctx.Logger()
	return nil
}

func (w *FPListenerWrapper) WrapListener(ln net.Listener) net.Listener {
	return &fpListener{Listener: ln, logger: w.logger}
}

func (w *FPListenerWrapper) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	return nil
}

type fpListener struct {
	net.Listener
	logger *zap.Logger
}

func (l *fpListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return conn, err
	}
	remote := conn.RemoteAddr().String()

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		// Plain (cleartext) connection — peek to distinguish h2c from h1.
		return &plainTappingConn{Conn: conn, remoteAddr: remote}, nil
	}
	state := tlsConn.ConnectionState()
	switch state.NegotiatedProtocol {
	case "h2":
		return &h2TappingConn{Conn: conn, remoteAddr: remote}, nil
	default:
		// http/1.1 ALPN or no ALPN — post-TLS plaintext is h1; safe to
		// use plainTappingConn (h2c preface won't appear after TLS).
		return &plainTappingConn{Conn: conn, remoteAddr: remote}, nil
	}
}

// ── Plain connection tap (h1 and h2c) ────────────────────────────────────────

const h1MaxHeaderBuf = 8192

// plainTappingConn handles post-accept connections that are not TLS h2.
// It peeks the first bytes to distinguish h2c prior-knowledge from h1,
// then routes to the appropriate parser.  Used for both cleartext (port 80)
// and TLS-h1 (ALPN "" or "http/1.1") connections.
type plainTappingConn struct {
	net.Conn
	once       sync.Once
	buf        bytes.Buffer
	reader     io.Reader
	remoteAddr string
}

// tapWriter is a non-blocking io.Writer that drops if the channel is full.
type tapWriter struct {
	ch chan<- []byte
}

func (t tapWriter) Write(p []byte) (int, error) {
	cp := make([]byte, len(p))
	copy(cp, p)
	select {
	case t.ch <- cp:
	default:
	}
	return len(p), nil
}

func (c *plainTappingConn) Read(b []byte) (int, error) {
	c.once.Do(func() {
		// Peek exactly len(h2ClientPreface) bytes to detect h2c prior knowledge.
		preface := make([]byte, len(h2ClientPreface))
		n, _ := io.ReadFull(c.Conn, preface)
		c.buf.Write(preface[:n])

		if n == len(h2ClientPreface) && string(preface) == h2ClientPreface {
			// h2c prior-knowledge connection — run the same SETTINGS+HPACK tap.
			hdr9 := make([]byte, 9)
			if m, err := io.ReadFull(c.Conn, hdr9); m == 9 && err == nil {
				c.buf.Write(hdr9)
				frameLen := int(hdr9[0])<<16 | int(hdr9[1])<<8 | int(hdr9[2])
				frameType := hdr9[3]
				if frameType == 0x4 && frameLen > 0 && frameLen <= 16384 {
					payload := make([]byte, frameLen)
					if _, err := io.ReadFull(c.Conn, payload); err == nil {
						c.buf.Write(payload)
						go parseAndSendH2Settings(c.remoteAddr, payload)
					}
				}
			}
			tap := make(chan []byte, 256)
			c.reader = io.TeeReader(io.MultiReader(&c.buf, c.Conn), tapWriter{ch: tap})
			go parseH2HeadersLoop(c.remoteAddr, tap)
			return
		}

		// h1 — buffer up to h1MaxHeaderBuf or until \r\n\r\n.
		scratch := make([]byte, h1MaxHeaderBuf)
		for c.buf.Len() < h1MaxHeaderBuf {
			nn, err := c.Conn.Read(scratch[:h1MaxHeaderBuf-c.buf.Len()])
			c.buf.Write(scratch[:nn])
			if bytes.Contains(c.buf.Bytes(), []byte("\r\n\r\n")) {
				break
			}
			if err != nil {
				break
			}
		}
		go parseAndSendH1Headers(c.remoteAddr, c.buf.Bytes())
		c.reader = io.MultiReader(&c.buf, c.Conn)
	})
	if c.reader == nil {
		return c.Conn.Read(b)
	}
	return c.reader.Read(b)
}

func parseAndSendH1Headers(remoteAddr string, raw []byte) {
	idx := bytes.Index(raw, []byte("\r\n\r\n"))
	if idx < 0 {
		idx = len(raw)
	}
	lines := bytes.Split(raw[:idx], []byte("\r\n"))
	if len(lines) == 0 {
		return
	}
	// First line: "GET /path HTTP/1.1"
	requestLine := string(lines[0])
	var method, path, proto string
	parts := bytes.Fields(lines[0])
	if len(parts) >= 3 {
		method = string(parts[0])
		path = string(parts[1])
		proto = string(parts[2])
	}

	var ordered [][]string // [[name, value], ...]
	var cookie, acceptLang string
	for _, line := range lines[1:] {
		sep := bytes.IndexByte(line, ':')
		if sep < 0 {
			continue
		}
		name := string(bytes.ToLower(bytes.TrimSpace(line[:sep])))
		value := string(bytes.TrimSpace(line[sep+1:]))
		ordered = append(ordered, []string{name, value})
		switch name {
		case "cookie":
			cookie = value
		case "accept-language":
			acceptLang = value
		}
	}

	sendFP(map[string]interface{}{
		"kind":            "http_request_headers",
		"remote_addr":     remoteAddr,
		"proto_tag":       "h1",
		"request_line":    requestLine,
		"method":          method,
		"path":            path,
		"proto":           proto,
		"headers_ordered": ordered,
		"cookie":          cookie,
		"accept_language": acceptLang,
		"ts":              time.Now().UTC().Format(time.RFC3339),
	})
}

// ── H2 client preface + HPACK continuous tap ──────────────────────────────────

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
		// Buffer client preface (24 B) + first frame header (9 B).
		hdr := make([]byte, len(h2ClientPreface)+9)
		if _, err := io.ReadFull(c.Conn, hdr); err != nil {
			c.buf.Write(hdr)
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

		// Start HPACK continuous parse on a non-blocking channel tap.
		tap := make(chan []byte, 256)
		c.reader = io.TeeReader(io.MultiReader(&c.buf, c.Conn), tapWriter{ch: tap})
		go parseH2HeadersLoop(c.remoteAddr, tap)
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

// hpackConn holds per-connection HPACK decoder state.
type hpackConn struct {
	decoder      *hpack.Decoder
	currentFields []hpack.HeaderField
}

func newHpackConn(maxTableSize uint32) *hpackConn {
	hc := &hpackConn{}
	hc.decoder = hpack.NewDecoder(maxTableSize, func(f hpack.HeaderField) {
		hc.currentFields = append(hc.currentFields, f)
	})
	return hc
}

// decode decodes a header block fragment, appending to existing and returning combined.
func (hc *hpackConn) decode(fragment []byte, existing []hpack.HeaderField) []hpack.HeaderField {
	hc.currentFields = existing
	hc.decoder.Write(fragment) //nolint:errcheck
	return hc.currentFields
}

func parseH2HeadersLoop(remoteAddr string, tap <-chan []byte) {
	var buf []byte
	prefaceLen := len(h2ClientPreface)
	prefaceSkipped := false
	hc := newHpackConn(4096)

	type streamState struct {
		fields []hpack.HeaderField
	}
	streams := make(map[uint32]*streamState)

	for chunk := range tap {
		buf = append(buf, chunk...)

		if !prefaceSkipped {
			if len(buf) < prefaceLen {
				continue
			}
			buf = buf[prefaceLen:]
			prefaceSkipped = true
		}

		for len(buf) >= 9 {
			frameLen := int(buf[0])<<16 | int(buf[1])<<8 | int(buf[2])
			frameType := buf[3]
			flags := buf[4]
			streamID := binary.BigEndian.Uint32(buf[5:9]) & 0x7fffffff

			total := 9 + frameLen
			if len(buf) < total {
				break
			}
			payload := buf[9:total]
			buf = buf[total:]

			switch frameType {
			case 0x4: // SETTINGS from client
				if flags&0x1 != 0 { // ACK
					break
				}
				for i := 0; i+6 <= len(payload); i += 6 {
					id := binary.BigEndian.Uint16(payload[i : i+2])
					val := binary.BigEndian.Uint32(payload[i+2 : i+6])
					if id == 0x1 { // SETTINGS_HEADER_TABLE_SIZE
						hc.decoder.SetMaxDynamicTableSize(val)
					}
				}

			case 0x1, 0x9: // HEADERS, CONTINUATION
				fragment := payload
				if frameType == 0x1 {
					off := 0
					var padLen byte
					if flags&0x08 != 0 { // PADDED
						if len(fragment) < 1 {
							continue
						}
						padLen = fragment[0]
						off = 1
					}
					if flags&0x20 != 0 { // PRIORITY
						off += 5
					}
					end := len(fragment) - int(padLen)
					if off > end || end < 0 {
						continue
					}
					fragment = fragment[off:end]
				}

				ss, ok := streams[streamID]
				if !ok {
					ss = &streamState{}
					streams[streamID] = ss
				}
				ss.fields = hc.decode(fragment, ss.fields)

				if flags&0x04 != 0 { // END_HEADERS
					emitH2RequestHeaders(remoteAddr, streamID, ss.fields)
					delete(streams, streamID)
				}
			}
		}
	}
}

func emitH2RequestHeaders(remoteAddr string, streamID uint32, fields []hpack.HeaderField) {
	ordered := make([][]string, 0, len(fields))
	var cookie, acceptLang, method, path string
	for _, f := range fields {
		ordered = append(ordered, []string{f.Name, f.Value})
		switch f.Name {
		case "cookie":
			cookie = f.Value
		case "accept-language":
			acceptLang = f.Value
		case ":method":
			method = f.Value
		case ":path":
			path = f.Value
		}
	}
	sendFP(map[string]interface{}{
		"kind":            "http_request_headers",
		"remote_addr":     remoteAddr,
		"stream_id":       streamID,
		"proto_tag":       "h2",
		"method":          method,
		"path":            path,
		"headers_ordered": ordered,
		"cookie":          cookie,
		"accept_language": acceptLang,
		"ts":              time.Now().UTC().Format(time.RFC3339),
	})
}

// ── http.handlers.decnet_fp ───────────────────────────────────────────────────

// FPHandler is HTTP middleware that emits an access_log record (status code,
// bytes, proto) after each response via the fp socket.  For h3 requests it
// also emits a best-effort http_request_headers record (header order degraded
// — QPACK decode order is preserved by quic-go but the Go map randomises it
// further; canonical h3 header order requires request-stream QPACK tapping
// which is a follow-up task).
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

// responseCapture captures the status code and bytes written.
type responseCapture struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (rc *responseCapture) WriteHeader(status int) {
	rc.status = status
	rc.ResponseWriter.WriteHeader(status)
}

func (rc *responseCapture) Write(b []byte) (int, error) {
	n, err := rc.ResponseWriter.Write(b)
	rc.bytes += n
	if rc.status == 0 {
		rc.status = 200
	}
	return n, err
}

func (h *FPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	rc := &responseCapture{ResponseWriter: w}
	err := next.ServeHTTP(rc, r)

	protoTag := "h1"
	if r.ProtoMajor == 2 {
		protoTag = "h2"
	} else if r.ProtoMajor == 3 {
		protoTag = "h3"
	}

	status := rc.status
	if status == 0 {
		status = 200
	}

	go sendFP(map[string]interface{}{
		"kind":        "access_log",
		"remote_addr": r.RemoteAddr,
		"method":      r.Method,
		"path":        r.URL.Path,
		"proto":       r.Proto,
		"proto_tag":   protoTag,
		"status":      status,
		"bytes":       rc.bytes,
		"ts":          time.Now().UTC().Format(time.RFC3339),
	})

	// For h3, emit best-effort http_request_headers (map order, degraded).
	if r.ProtoMajor == 3 {
		ordered := make([][]string, 0, len(r.Header))
		var cookie, acceptLang string
		for name, vals := range r.Header {
			v := ""
			if len(vals) > 0 {
				v = vals[0]
			}
			ordered = append(ordered, []string{name, v})
			switch http.CanonicalHeaderKey(name) {
			case "Cookie":
				cookie = v
			case "Accept-Language":
				acceptLang = v
			}
		}
		go sendFP(map[string]interface{}{
			"kind":            "http_request_headers",
			"remote_addr":     r.RemoteAddr,
			"proto_tag":       "h3",
			"method":          r.Method,
			"path":            r.URL.Path,
			"headers_ordered": ordered,
			"cookie":          cookie,
			"accept_language": acceptLang,
			"h3_order_note":   "degraded_map_iteration",
			"ts":              time.Now().UTC().Format(time.RFC3339),
		})
	}

	return err
}

var (
	_ caddy.Provisioner           = (*FPListenerWrapper)(nil)
	_ caddy.ListenerWrapper       = (*FPListenerWrapper)(nil)
	_ caddyfile.Unmarshaler       = (*FPListenerWrapper)(nil)
	_ caddy.Provisioner           = (*FPHandler)(nil)
	_ caddyhttp.MiddlewareHandler = (*FPHandler)(nil)
	_ caddyfile.Unmarshaler       = (*FPHandler)(nil)
)

// ── caddy.logging.encoders.decnet_jsonl ──────────────────────────────────────

// DecnetJSONLEncoder is a registered Caddy module stub.  A full zapcore.Encoder
// implementation (required for `log { format decnet_jsonl }`) is deferred;
// access_log records are emitted by FPHandler.ServeHTTP instead.
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
