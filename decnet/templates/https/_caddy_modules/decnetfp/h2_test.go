package decnetfp

import (
	"encoding/binary"
	"encoding/json"
	"net"
	"testing"
	"time"

	"golang.org/x/net/http2/hpack"
)

// buildH2Preface returns the 24-byte h2 client preface.
func buildH2Preface() []byte {
	return []byte(h2ClientPreface)
}

// buildH2Settings builds a SETTINGS frame payload from id/val pairs.
func buildH2Settings(pairs [][2]uint32) []byte {
	payload := make([]byte, len(pairs)*6)
	for i, p := range pairs {
		binary.BigEndian.PutUint16(payload[i*6:], uint16(p[0]))
		binary.BigEndian.PutUint32(payload[i*6+2:], p[1])
	}
	return buildH2Frame(0x4, 0, 0, payload)
}

// buildH2Frame builds a raw h2 frame (9-byte header + payload).
func buildH2Frame(typ, flags byte, streamID uint32, payload []byte) []byte {
	frame := make([]byte, 9+len(payload))
	frame[0] = byte(len(payload) >> 16)
	frame[1] = byte(len(payload) >> 8)
	frame[2] = byte(len(payload))
	frame[3] = typ
	frame[4] = flags
	binary.BigEndian.PutUint32(frame[5:], streamID)
	copy(frame[9:], payload)
	return frame
}

// buildH2HeadersFrame encodes headers with HPACK and wraps in a HEADERS frame.
func buildH2HeadersFrame(streamID uint32, headers [][2]string, endHeaders bool) []byte {
	var hbuf []byte
	enc := hpack.NewEncoder(writeCloser{&hbuf})
	for _, h := range headers {
		enc.WriteField(hpack.HeaderField{Name: h[0], Value: h[1]}) //nolint:errcheck
	}
	flags := byte(0)
	if endHeaders {
		flags |= 0x04
	}
	return buildH2Frame(0x1, flags, streamID, hbuf)
}

type writeCloser struct{ b *[]byte }

func (w writeCloser) Write(p []byte) (int, error) {
	*w.b = append(*w.b, p...)
	return len(p), nil
}

func TestParseH2HeadersLoop_DecodesHPACKOrder(t *testing.T) {
	sockPath := t.TempDir() + "/fp_h2.sock"
	t.Setenv("DECNET_FP_SOCK", sockPath)
	sockMu.Lock()
	sockConn = nil
	sockMu.Unlock()
	t.Cleanup(func() {
		sockMu.Lock()
		if sockConn != nil {
			sockConn.Close()
			sockConn = nil
		}
		sockMu.Unlock()
	})

	srv := bindSock(t, sockPath)
	t.Cleanup(func() { srv.Close() })

	done := make(chan []map[string]interface{}, 1)
	go func() { done <- drainSock(t, srv, 1, 3*time.Second) }()

	// Build: preface + SETTINGS + HEADERS (stream 1, END_HEADERS).
	// Headers in a specific order to verify HPACK decode order is preserved.
	wantHeaders := [][2]string{
		{":method", "GET"},
		{":path", "/index.html"},
		{":scheme", "https"},
		{":authority", "example.com"},
		{"accept", "text/html"},
		{"user-agent", "Go-http-client/2.0"},
		{"accept-language", "en-US"},
	}

	preface := buildH2Preface()
	settings := buildH2Settings([][2]uint32{{0x3, 100}}) // MAX_CONCURRENT_STREAMS=100
	headers := buildH2HeadersFrame(1, wantHeaders, true)

	tap := make(chan []byte, 256)

	// Feed the preface through the tap.
	chunks := [][]byte{preface, settings, headers}
	for _, c := range chunks {
		cp := make([]byte, len(c))
		copy(cp, c)
		tap <- cp
	}
	close(tap)

	go parseH2HeadersLoop("5.6.7.8:443", tap)

	records := <-done
	if len(records) == 0 {
		t.Fatal("no records received")
	}
	rec := records[0]
	if rec["kind"] != "http_request_headers" {
		t.Errorf("kind: got %v", rec["kind"])
	}
	if rec["proto_tag"] != "h2" {
		t.Errorf("proto_tag: got %v", rec["proto_tag"])
	}
	if rec["method"] != "GET" {
		t.Errorf("method: got %v", rec["method"])
	}
	if rec["path"] != "/index.html" {
		t.Errorf("path: got %v", rec["path"])
	}
	if rec["accept_language"] != "en-US" {
		t.Errorf("accept_language: got %v", rec["accept_language"])
	}

	rawOrdered, _ := json.Marshal(rec["headers_ordered"])
	var ordered [][]string
	if err := json.Unmarshal(rawOrdered, &ordered); err != nil {
		t.Fatalf("unmarshal headers_ordered: %v", err)
	}
	if len(ordered) != len(wantHeaders) {
		t.Fatalf("want %d headers, got %d: %v", len(wantHeaders), len(ordered), ordered)
	}
	for i, pair := range ordered {
		if pair[0] != wantHeaders[i][0] {
			t.Errorf("header[%d]: got %q, want %q", i, pair[0], wantHeaders[i][0])
		}
	}
}

func TestParseH2Settings_FrameOrder(t *testing.T) {
	sockPath := t.TempDir() + "/fp_h2s.sock"
	t.Setenv("DECNET_FP_SOCK", sockPath)
	sockMu.Lock()
	sockConn = nil
	sockMu.Unlock()
	t.Cleanup(func() {
		sockMu.Lock()
		if sockConn != nil {
			sockConn.Close()
			sockConn = nil
		}
		sockMu.Unlock()
	})

	srv, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: sockPath, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	// SETTINGS frame with 3 params in a specific order.
	settings := [][2]uint32{
		{0x4, 65535},  // INITIAL_WINDOW_SIZE
		{0x3, 1000},   // MAX_CONCURRENT_STREAMS
		{0x1, 65536},  // HEADER_TABLE_SIZE
	}
	payload := make([]byte, len(settings)*6)
	for i, s := range settings {
		binary.BigEndian.PutUint16(payload[i*6:], uint16(s[0]))
		binary.BigEndian.PutUint32(payload[i*6+2:], s[1])
	}

	done := make(chan map[string]interface{}, 1)
	go func() {
		buf := make([]byte, 65536)
		srv.SetDeadline(time.Now().Add(2 * time.Second))
		n, _ := srv.Read(buf)
		var m map[string]interface{}
		json.Unmarshal(buf[:n], &m) //nolint:errcheck
		done <- m
	}()

	parseAndSendH2Settings("1.2.3.4:1234", payload)

	rec := <-done
	if rec["kind"] != "h2_settings" {
		t.Errorf("kind: got %v", rec["kind"])
	}
	rawOrder, _ := json.Marshal(rec["frame_order"])
	var order []float64 // JSON numbers decode as float64
	json.Unmarshal(rawOrder, &order) //nolint:errcheck
	if len(order) != 3 {
		t.Fatalf("want 3 frame_order entries, got %d", len(order))
	}
	if order[0] != 4 || order[1] != 3 || order[2] != 1 {
		t.Errorf("frame_order: got %v, want [4 3 1]", order)
	}
}
