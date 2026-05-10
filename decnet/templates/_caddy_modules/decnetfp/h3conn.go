package decnetfp

import (
	"bytes"
	"context"
	"io"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/logging"
)

// newH3SettingsTracer is the quic.Config.Tracer factory.  We don't use
// quic-go's logging.ConnectionTracer for SETTINGS (its ReceivedStreamFrame
// hook gives only metadata, not payload bytes).  The actual h3 SETTINGS
// capture happens in h3TappingUniStream by wrapping AcceptUniStream.
// This function returns nil (no-op tracer) so quic-go uses its default path.
func newH3SettingsTracer(_ context.Context, _ logging.Perspective, _ quic.ConnectionID) *logging.ConnectionTracer {
	return nil
}

// ── QUIC connection wrapper ───────────────────────────────────────────────────

// h3SettingsTappingConn wraps quic.Connection and intercepts AcceptUniStream
// so the first bytes of each client-initiated unidirectional stream can be
// inspected for h3 control stream SETTINGS before being replayed to the
// http3.Server.
type h3SettingsTappingConn struct {
	quic.Connection
	remoteAddr string
}

func (c *h3SettingsTappingConn) AcceptUniStream(ctx context.Context) (quic.ReceiveStream, error) {
	stream, err := c.Connection.AcceptUniStream(ctx)
	if err != nil {
		return stream, err
	}
	return &h3TappingUniStream{ReceiveStream: stream, remoteAddr: c.remoteAddr}, nil
}

// ── QUIC receive-stream wrapper ───────────────────────────────────────────────

// h3TappingUniStream peeks at the first bytes of a unidirectional stream to
// identify the h3 control stream (stream type 0x00, RFC 9114 §6.2.1) and
// extract its first SETTINGS frame, then replays all bytes to the caller.
type h3TappingUniStream struct {
	quic.ReceiveStream
	once       sync.Once
	buf        bytes.Buffer
	reader     io.Reader
	remoteAddr string
}

// maxH3ControlPeek is enough to cover the stream-type varint + SETTINGS
// frame type varint + frame-length varint + a typical SETTINGS frame body
// (6 settings × 8 bytes each = 48 bytes, plus 3 varint headers ≈ 64 bytes).
const maxH3ControlPeek = 256

func (s *h3TappingUniStream) Read(p []byte) (int, error) {
	s.once.Do(func() {
		scratch := make([]byte, maxH3ControlPeek)
		n, _ := s.ReceiveStream.Read(scratch)
		s.buf.Write(scratch[:n])
		go tryParseH3ControlStream(s.remoteAddr, s.buf.Bytes())
		s.reader = io.MultiReader(&s.buf, s.ReceiveStream)
	})
	if s.reader != nil {
		return s.reader.Read(p)
	}
	return s.ReceiveStream.Read(p)
}

// tryParseH3ControlStream examines the peeked bytes.  If the stream opens
// with stream-type 0x00 (h3 control stream) and the first frame is SETTINGS
// (type 0x04), it emits an h3_settings fp record.  All errors are silent —
// this is a best-effort tap.
func tryParseH3ControlStream(remoteAddr string, data []byte) {
	streamType, c0 := quicVarint(data)
	if c0 == 0 || streamType != 0x00 {
		return // not the h3 control stream
	}
	data = data[c0:]

	frameType, c1 := quicVarint(data)
	if c1 == 0 {
		return
	}
	data = data[c1:]

	frameLen, c2 := quicVarint(data)
	if c2 == 0 {
		return
	}
	data = data[c2:]

	// Per RFC 9114 §7.2.4: the first frame on the control stream MUST be SETTINGS.
	if frameType != 0x04 {
		return
	}
	if uint64(len(data)) < frameLen {
		return // need more bytes — we only peeked 256
	}
	body := data[:frameLen]

	settings := make(map[string]uint64)
	frameOrder := make([]uint64, 0, 8)
	for len(body) > 0 {
		id, ci := quicVarint(body)
		if ci == 0 {
			break
		}
		body = body[ci:]
		val, cv := quicVarint(body)
		if cv == 0 {
			break
		}
		body = body[cv:]
		settings[h3SettingName(id)] = val
		frameOrder = append(frameOrder, id)
	}

	sendFP(map[string]interface{}{
		"kind":        "h3_settings",
		"remote_addr": remoteAddr,
		"settings":    settings,
		"frame_order": frameOrder,
		"ts":          time.Now().UTC().Format(time.RFC3339),
	})
}

// quicVarint decodes an RFC 9000 §16 variable-length integer.
// Returns (value, bytes_consumed); bytes_consumed == 0 on failure.
func quicVarint(b []byte) (uint64, int) {
	if len(b) == 0 {
		return 0, 0
	}
	prefix := b[0] >> 6
	switch prefix {
	case 0:
		return uint64(b[0] & 0x3f), 1
	case 1:
		if len(b) < 2 {
			return 0, 0
		}
		return uint64(b[0]&0x3f)<<8 | uint64(b[1]), 2
	case 2:
		if len(b) < 4 {
			return 0, 0
		}
		return uint64(b[0]&0x3f)<<24 | uint64(b[1])<<16 | uint64(b[2])<<8 | uint64(b[3]), 4
	case 3:
		if len(b) < 8 {
			return 0, 0
		}
		return uint64(b[0]&0x3f)<<56 | uint64(b[1])<<48 | uint64(b[2])<<40 | uint64(b[3])<<32 |
			uint64(b[4])<<24 | uint64(b[5])<<16 | uint64(b[6])<<8 | uint64(b[7]), 8
	}
	return 0, 0
}

// h3SettingName maps RFC 9114 and extension SETTINGS IDs to human-readable names.
func h3SettingName(id uint64) string {
	switch id {
	case 0x01:
		return "QPACK_MAX_TABLE_CAPACITY"
	case 0x06:
		return "MAX_FIELD_SECTION_SIZE"
	case 0x07:
		return "QPACK_BLOCKED_STREAMS"
	case 0x08:
		return "ENABLE_CONNECT_PROTOCOL"
	case 0x33:
		return "H3_DATAGRAM"
	case 0xc671706a:
		return "ENABLE_WEBTRANSPORT"
	default:
		// GREASE values per RFC 9114 §7.2.8 pattern (0x1f * N + 0x21)
		if id > 0x20 && (id-0x21)%0x1f == 0 {
			return "GREASE"
		}
		return "UNKNOWN"
	}
}
