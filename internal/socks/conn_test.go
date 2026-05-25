package socks

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

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

func TestVirtualConnCloseUnblocksRead(t *testing.T) {
	var id [frame.SessionIDLen]byte
	id[0] = 0x7d
	s := session.New(id, "example.com:443", true)
	conn := NewVirtualConn(s)

	done := make(chan error, 1)
	go func() {
		_, err := conn.Read(make([]byte, 1))
		done <- err
	}()

	time.Sleep(10 * time.Millisecond)
	if err := conn.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	select {
	case err := <-done:
		if !errors.Is(err, io.EOF) {
			t.Fatalf("Read err = %v, want io.EOF after Close", err)
		}
	case <-time.After(250 * time.Millisecond):
		t.Fatal("Read stayed blocked after Close")
	}
}

func TestVirtualConnReadZeroLengthReturnsImmediately(t *testing.T) {
	var id [frame.SessionIDLen]byte
	id[0] = 0x81
	s := session.New(id, "example.com:443", true)
	conn := NewVirtualConn(s)
	defer conn.Close()

	done := make(chan struct {
		n   int
		err error
	}, 1)
	go func() {
		n, err := conn.Read(nil)
		done <- struct {
			n   int
			err error
		}{n: n, err: err}
	}()

	select {
	case got := <-done:
		if got.n != 0 || got.err != nil {
			t.Fatalf("Read(nil) = (%d, %v), want (0, nil)", got.n, got.err)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("Read(nil) blocked; net.Conn requires zero-length reads to return immediately")
	}
}

func TestVirtualConnSetReadDeadlineWakesBlockedRead(t *testing.T) {
	var id [frame.SessionIDLen]byte
	id[0] = 0x7e
	s := session.New(id, "example.com:443", true)
	conn := NewVirtualConn(s)
	defer conn.Close()

	done := make(chan error, 1)
	go func() {
		_, err := conn.Read(make([]byte, 1))
		done <- err
	}()

	time.Sleep(10 * time.Millisecond)
	if err := conn.SetReadDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}

	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("Read err = %v, want deadline exceeded", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Read did not observe updated deadline")
	}
}

func TestVirtualConnWriteDeadlineBoundsBlockedWrite(t *testing.T) {
	var id [frame.SessionIDLen]byte
	id[0] = 0x7f
	s := session.New(id, "example.com:443", true)
	s.SetTxBudget(session.NewTxBudget(1))
	conn := NewVirtualConn(s)
	defer conn.Close()

	if n, err := conn.Write([]byte("x")); err != nil || n != 1 {
		t.Fatalf("initial Write n=%d err=%v, want 1 nil", n, err)
	}
	if err := conn.SetWriteDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}

	start := time.Now()
	n, err := conn.Write([]byte("y"))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("blocked Write err = %v, want deadline exceeded", err)
	}
	if n != 0 {
		t.Fatalf("blocked Write n = %d, want 0", n)
	}
	if elapsed := time.Since(start); elapsed > 300*time.Millisecond {
		t.Fatalf("blocked Write ignored deadline; elapsed=%v", elapsed)
	}
}

func TestVirtualConnSetWriteDeadlineWakesBlockedWrite(t *testing.T) {
	var id [frame.SessionIDLen]byte
	id[0] = 0x80
	s := session.New(id, "example.com:443", true)
	s.SetTxBudget(session.NewTxBudget(1))
	conn := NewVirtualConn(s)
	defer conn.Close()

	if n, err := conn.Write([]byte("x")); err != nil || n != 1 {
		t.Fatalf("initial Write n=%d err=%v, want 1 nil", n, err)
	}

	done := make(chan error, 1)
	go func() {
		_, err := conn.Write([]byte("y"))
		done <- err
	}()

	select {
	case err := <-done:
		t.Fatalf("blocked Write returned before deadline update: %v", err)
	case <-time.After(20 * time.Millisecond):
	}

	if err := conn.SetWriteDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}

	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("blocked Write err = %v, want deadline exceeded", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("blocked Write did not observe updated write deadline")
	}
}

func TestVirtualConnSetDeadlineWakesBlockedWrite(t *testing.T) {
	var id [frame.SessionIDLen]byte
	id[0] = 0x82
	s := session.New(id, "example.com:443", true)
	s.SetTxBudget(session.NewTxBudget(1))
	conn := NewVirtualConn(s)
	defer conn.Close()

	if n, err := conn.Write([]byte("x")); err != nil || n != 1 {
		t.Fatalf("initial Write n=%d err=%v, want 1 nil", n, err)
	}

	done := make(chan error, 1)
	go func() {
		_, err := conn.Write([]byte("y"))
		done <- err
	}()

	select {
	case err := <-done:
		t.Fatalf("blocked Write returned before deadline update: %v", err)
	case <-time.After(20 * time.Millisecond):
	}

	if err := conn.SetDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}

	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("blocked Write err = %v, want deadline exceeded", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("blocked Write did not observe updated full deadline")
	}
}
