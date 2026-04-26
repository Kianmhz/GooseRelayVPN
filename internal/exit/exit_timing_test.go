package exit

import (
	"bytes"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kianmhz/relay-tunnel/internal/frame"
)

const exitTimingTestKeyHex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func mustExitTimingServer(tb testing.TB) *Server {
	tb.Helper()
	s, err := New(Config{ListenAddr: "127.0.0.1:0", AESKeyHex: exitTimingTestKeyHex})
	if err != nil {
		tb.Fatalf("new server: %v", err)
	}
	return s
}

func mustExitTimingCrypto(tb testing.TB) *frame.Crypto {
	tb.Helper()
	c, err := frame.NewCryptoFromHexKey(exitTimingTestKeyHex)
	if err != nil {
		tb.Fatalf("new crypto: %v", err)
	}
	return c
}

func invokeExitTunnel(tb testing.TB, s *Server, c *frame.Crypto, frames []*frame.Frame) time.Duration {
	tb.Helper()
	body, err := frame.EncodeBatch(c, frames)
	if err != nil {
		tb.Fatalf("encode request: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/tunnel", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	t0 := time.Now()
	s.handleTunnel(rec, req)
	resp := rec.Result()
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return time.Since(t0)
}

func startSilentServer(tb testing.TB) (string, func()) {
	tb.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		tb.Fatalf("listen: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(io.Discard, c)
			}(conn)
		}
	}()
	return ln.Addr().String(), func() {
		_ = ln.Close()
		<-done
	}
}

func TestExitDrainWindow_EmptyPollUsesLongWindow(t *testing.T) {
	s := mustExitTimingServer(t)
	c := mustExitTimingCrypto(t)
	elapsed := invokeExitTunnel(t, s, c, nil)
	if elapsed < LongPollWindow-500*time.Millisecond {
		t.Fatalf("empty poll returned too quickly: %v", elapsed)
	}
}

func TestExitDrainWindow_ActiveBatchUsesShortWindow(t *testing.T) {
	s := mustExitTimingServer(t)
	c := mustExitTimingCrypto(t)
	target, closeFn := startSilentServer(t)
	defer closeFn()
	elapsed := invokeExitTunnel(t, s, c, []*frame.Frame{{
		SessionID: [frame.SessionIDLen]byte{1},
		Seq:       0,
		Flags:     frame.FlagSYN,
		Target:    target,
		Payload:   []byte("PING"),
	}})
	if elapsed > ActiveDrainWindow+350*time.Millisecond {
		t.Fatalf("active batch waited too long: %v", elapsed)
	}
}

func BenchmarkExitActiveSilent(b *testing.B) {
	s := mustExitTimingServer(b)
	c := mustExitTimingCrypto(b)
	target, closeFn := startSilentServer(b)
	defer closeFn()
	frames := []*frame.Frame{{
		SessionID: [frame.SessionIDLen]byte{2},
		Seq:       0,
		Flags:     frame.FlagSYN,
		Target:    target,
		Payload:   []byte("GET / HTTP/1.0\r\n\r\n"),
	}}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = invokeExitTunnel(b, s, c, frames)
	}
}
