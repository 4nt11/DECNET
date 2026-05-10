package decnetfp

import (
	"encoding/binary"
	"encoding/json"
	"net"
	"testing"
	"time"
)

// encodeVarint encodes a uint64 as an RFC 9000 variable-length integer.
func encodeVarint(v uint64) []byte {
	switch {
	case v <= 0x3f:
		return []byte{byte(v)}
	case v <= 0x3fff:
		return []byte{0x40 | byte(v>>8), byte(v)}
	case v <= 0x3fffffff:
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, uint32(v)|0x80000000)
		return b
	default:
		b := make([]byte, 8)
		binary.BigEndian.PutUint64(b, v|0xc000000000000000)
		return b
	}
}

// buildH3ControlStream builds the opening bytes of an h3 control stream
// with a SETTINGS frame containing the given id/val pairs.
func buildH3ControlStream(settings [][2]uint64) []byte {
	// Stream type = 0x00 (control stream)
	var body []byte
	for _, s := range settings {
		body = append(body, encodeVarint(s[0])...)
		body = append(body, encodeVarint(s[1])...)
	}
	// h3 frame: type=0x04 (SETTINGS), length=len(body), body
	frame := append(encodeVarint(0x04), encodeVarint(uint64(len(body)))...)
	frame = append(frame, body...)

	return append(encodeVarint(0x00), frame...)
}

func TestTryParseH3ControlStream_ParsesSettings(t *testing.T) {
	sockPath := t.TempDir() + "/fp_h3.sock"
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

	settings := [][2]uint64{
		{0x01, 0},    // QPACK_MAX_TABLE_CAPACITY
		{0x06, 0},    // MAX_FIELD_SECTION_SIZE (0 = unlimited)
		{0x07, 0},    // QPACK_BLOCKED_STREAMS
		{0x4242, 1},  // GREASE-like unknown value
	}
	data := buildH3ControlStream(settings)

	done := make(chan map[string]interface{}, 1)
	go func() {
		buf := make([]byte, 65536)
		srv.SetDeadline(time.Now().Add(2 * time.Second))
		n, _ := srv.Read(buf)
		var m map[string]interface{}
		json.Unmarshal(buf[:n], &m) //nolint:errcheck
		done <- m
	}()

	tryParseH3ControlStream("9.8.7.6:443", data)

	rec := <-done
	if rec == nil {
		t.Fatal("no record received")
	}
	if rec["kind"] != "h3_settings" {
		t.Errorf("kind: got %v, want h3_settings", rec["kind"])
	}
	if rec["remote_addr"] != "9.8.7.6:443" {
		t.Errorf("remote_addr: got %v", rec["remote_addr"])
	}

	rawSettings, _ := json.Marshal(rec["settings"])
	var gotSettings map[string]interface{}
	json.Unmarshal(rawSettings, &gotSettings) //nolint:errcheck
	if _, ok := gotSettings["QPACK_MAX_TABLE_CAPACITY"]; !ok {
		t.Errorf("missing QPACK_MAX_TABLE_CAPACITY in settings: %v", gotSettings)
	}
	if _, ok := gotSettings["MAX_FIELD_SECTION_SIZE"]; !ok {
		t.Errorf("missing MAX_FIELD_SECTION_SIZE in settings: %v", gotSettings)
	}

	rawOrder, _ := json.Marshal(rec["frame_order"])
	var order []interface{}
	json.Unmarshal(rawOrder, &order) //nolint:errcheck
	if len(order) != 4 {
		t.Errorf("want 4 frame_order entries, got %d: %v", len(order), order)
	}
}

func TestTryParseH3ControlStream_WrongStreamType(t *testing.T) {
	// Stream type 0x02 = QPACK encoder stream — should be ignored.
	data := append(encodeVarint(0x02), []byte{0x00}...)
	// Should not panic or emit any record.
	tryParseH3ControlStream("1.2.3.4:443", data) // no socket — will silently drop
}

func TestTryParseH3ControlStream_TruncatedData(t *testing.T) {
	// Only stream-type prefix, no SETTINGS frame yet.
	data := encodeVarint(0x00)
	tryParseH3ControlStream("1.2.3.4:443", data) // must not panic
}

func TestQuicVarint(t *testing.T) {
	cases := []struct {
		input []byte
		want  uint64
		wantN int
	}{
		{[]byte{0x00}, 0, 1},
		{[]byte{0x3f}, 63, 1},
		{[]byte{0x40, 0x00}, 0, 2},
		{[]byte{0x7f, 0xff}, 16383, 2},
		{[]byte{0x80, 0x00, 0x00, 0x00}, 0, 4},
		{[]byte{0xbf, 0xff, 0xff, 0xff}, 1073741823, 4},
		// Empty input
		{[]byte{}, 0, 0},
		// Truncated 2-byte
		{[]byte{0x40}, 0, 0},
	}
	for _, c := range cases {
		v, n := quicVarint(c.input)
		if v != c.want || n != c.wantN {
			t.Errorf("quicVarint(%x) = (%d, %d), want (%d, %d)", c.input, v, n, c.want, c.wantN)
		}
	}
}

func TestH3SettingName(t *testing.T) {
	cases := []struct {
		id   uint64
		want string
	}{
		{0x01, "QPACK_MAX_TABLE_CAPACITY"},
		{0x06, "MAX_FIELD_SECTION_SIZE"},
		{0x07, "QPACK_BLOCKED_STREAMS"},
		{0x08, "ENABLE_CONNECT_PROTOCOL"},
		{0x33, "H3_DATAGRAM"},
		{0x41, "UNKNOWN"}, // not a GREASE pattern (GREASE = 0x1f*N+0x21; 0x41-0x21=0x20, not div by 0x1f)
	}
	for _, c := range cases {
		if got := h3SettingName(c.id); got != c.want {
			t.Errorf("h3SettingName(0x%x) = %q, want %q", c.id, got, c.want)
		}
	}
}
