package decnetfp

import (
	"encoding/json"
	"net"
	"testing"
	"time"
)

// bindSock creates a unix datagram socket at path and returns it.
// The caller must close it (or register a t.Cleanup).
func bindSock(t *testing.T, path string) *net.UnixConn {
	t.Helper()
	sock, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		t.Fatalf("listen %s: %v", path, err)
	}
	return sock
}

// drainSock reads up to n records from an already-bound unix datagram socket.
func drainSock(t *testing.T, sock *net.UnixConn, count int, timeout time.Duration) []map[string]interface{} {
	t.Helper()
	sock.SetDeadline(time.Now().Add(timeout)) //nolint:errcheck
	var records []map[string]interface{}
	buf := make([]byte, 65536)
	for len(records) < count {
		n, err := sock.Read(buf)
		if err != nil {
			break
		}
		var m map[string]interface{}
		if err := json.Unmarshal(buf[:n], &m); err != nil {
			t.Logf("unmarshal: %v", err)
			continue
		}
		records = append(records, m)
	}
	return records
}

func TestParseAndSendH1Headers(t *testing.T) {
	path := t.TempDir() + "/fp_h1.sock"
	t.Setenv("DECNET_FP_SOCK", path)
	// Reset the global socket so it reconnects to the test socket.
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

	srv := bindSock(t, path)
	t.Cleanup(func() { srv.Close() })

	done := make(chan []map[string]interface{}, 1)
	go func() {
		done <- drainSock(t, srv, 1, 2*time.Second)
	}()

	// Typical curl HTTP/1.1 request bytes.
	raw := "GET /robots.txt HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"User-Agent: curl/8.0.1\r\n" +
		"Accept: */*\r\n" +
		"X-Custom-A: alpha\r\n" +
		"X-Custom-B: beta\r\n" +
		"\r\n"

	parseAndSendH1Headers("1.2.3.4:9999", []byte(raw))

	records := <-done
	if len(records) != 1 {
		t.Fatalf("want 1 record, got %d", len(records))
	}
	rec := records[0]

	if rec["kind"] != "http_request_headers" {
		t.Errorf("kind: got %v, want http_request_headers", rec["kind"])
	}
	if rec["proto_tag"] != "h1" {
		t.Errorf("proto_tag: got %v, want h1", rec["proto_tag"])
	}
	if rec["method"] != "GET" {
		t.Errorf("method: got %v, want GET", rec["method"])
	}
	if rec["path"] != "/robots.txt" {
		t.Errorf("path: got %v, want /robots.txt", rec["path"])
	}

	rawOrdered, _ := json.Marshal(rec["headers_ordered"])
	var ordered [][]string
	if err := json.Unmarshal(rawOrdered, &ordered); err != nil {
		t.Fatalf("unmarshal headers_ordered: %v", err)
	}
	if len(ordered) != 5 {
		t.Fatalf("want 5 headers, got %d: %v", len(ordered), ordered)
	}
	// Wire order must be preserved exactly.
	want := []string{"host", "user-agent", "accept", "x-custom-a", "x-custom-b"}
	for i, pair := range ordered {
		if pair[0] != want[i] {
			t.Errorf("header[%d]: got %q, want %q", i, pair[0], want[i])
		}
	}
}

func TestParseAndSendH1Headers_StopsAtEmptyLine(t *testing.T) {
	// Headers should not include body bytes after \r\n\r\n.
	raw := "POST /login HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nuser=bob&pass=secret"
	path := t.TempDir() + "/fp_h1b.sock"
	t.Setenv("DECNET_FP_SOCK", path)
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

	srv := bindSock(t, path)
	t.Cleanup(func() { srv.Close() })

	done := make(chan []map[string]interface{}, 1)
	go func() { done <- drainSock(t, srv, 1, 2*time.Second) }()
	parseAndSendH1Headers("10.0.0.1:1234", []byte(raw))

	records := <-done
	if len(records) != 1 {
		t.Fatalf("want 1 record, got %d", len(records))
	}
	rawOrdered, _ := json.Marshal(records[0]["headers_ordered"])
	var ordered [][]string
	json.Unmarshal(rawOrdered, &ordered) //nolint:errcheck
	if len(ordered) != 1 {
		t.Fatalf("want 1 header (Content-Type), got %d: %v", len(ordered), ordered)
	}
	if ordered[0][0] != "content-type" {
		t.Errorf("header[0]: got %q, want content-type", ordered[0][0])
	}
}
