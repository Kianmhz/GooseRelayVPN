package socks

import (
	"errors"
	"io"
	"testing"

	"github.com/kianmhz/GooseRelayVPN/internal/frame"
	"github.com/kianmhz/GooseRelayVPN/internal/session"
)

func TestVirtualConnWriteReportsClosedSession(t *testing.T) {
	var id [frame.SessionIDLen]byte
	id[0] = 0x7c
	s := session.New(id, "example.com:443", true)
	conn := NewVirtualConn(s)

	s.Abort()

	n, err := conn.Write([]byte("hello"))
	if !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("Write err = %v, want io.ErrClosedPipe", err)
	}
	if n != 0 {
		t.Fatalf("Write n = %d, want 0 on closed session", n)
	}
	if frames := s.DrainTx(64 * 1024); len(frames) != 0 {
		t.Fatalf("closed write queued %d frame(s)", len(frames))
	}
}
