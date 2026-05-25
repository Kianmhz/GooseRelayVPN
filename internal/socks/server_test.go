package socks

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/kianmhz/GooseRelayVPN/internal/frame"
	"github.com/kianmhz/GooseRelayVPN/internal/session"
)

func TestListenNetworkChoosesIPv4ForIPv4BindAddresses(t *testing.T) {
	for _, addr := range []string{"127.0.0.1:1080", "0.0.0.0:1080"} {
		if got := listenNetwork(addr); got != "tcp4" {
			t.Fatalf("listenNetwork(%q) = %q, want tcp4", addr, got)
		}
	}
}

func TestListenNetworkChoosesIPv6ForIPv6BindAddresses(t *testing.T) {
	for _, addr := range []string{"[::1]:1080", "[::]:1080"} {
		if got := listenNetwork(addr); got != "tcp6" {
			t.Fatalf("listenNetwork(%q) = %q, want tcp6", addr, got)
		}
	}
}

func TestListenNetworkKeepsHostnamesDualStack(t *testing.T) {
	if got := listenNetwork("localhost:1080"); got != "tcp" {
		t.Fatalf("listenNetwork(localhost) = %q, want tcp", got)
	}
}

func TestListenNetworkIPv4ListenerAcceptsIPv4Dial(t *testing.T) {
	addr := "127.0.0.1:0"
	ln, err := net.Listen(listenNetwork(addr), addr)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	tcp, ok := ln.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("listener addr type = %T, want *net.TCPAddr", ln.Addr())
	}
	if got := tcp.IP.To4(); got == nil {
		t.Fatalf("listener IP = %v, want IPv4", tcp.IP)
	}

	accepted := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			accepted <- err
			return
		}
		_ = conn.Close()
		accepted <- nil
	}()

	conn, err := net.DialTimeout("tcp4", tcp.String(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial tcp4: %v", err)
	}
	_ = conn.Close()

	select {
	case err := <-accepted:
		if err != nil {
			t.Fatalf("accept: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("listener did not accept IPv4 connection")
	}
}

func TestSessionLimiterRejectsAboveCapAndReleases(t *testing.T) {
	limiter := newSessionLimiter(1)
	release, ok := limiter.acquire()
	if !ok {
		t.Fatal("first acquire rejected")
	}
	if _, ok := limiter.acquire(); ok {
		t.Fatal("second acquire succeeded above cap")
	}
	release()
	if _, ok := limiter.acquire(); !ok {
		t.Fatal("acquire after release rejected")
	}
}

func TestSessionLimiterZeroMeansUnlimited(t *testing.T) {
	limiter := newSessionLimiter(0)
	for i := 0; i < 100; i++ {
		if _, ok := limiter.acquire(); !ok {
			t.Fatalf("acquire %d rejected with unlimited cap", i)
		}
	}
}

func TestLimitedConnReleasesOnlyOnce(t *testing.T) {
	var releases int
	conn := &limitedConn{
		Conn: noopConn{},
		release: func() {
			releases++
		},
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("first close: %v", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("second close: %v", err)
	}
	if releases != 1 {
		t.Fatalf("releases = %d, want 1", releases)
	}
}

func TestServeReturnsWhenContextCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)

	go func() {
		errCh <- Serve(ctx, "127.0.0.1:0", "", "", false, 0, func(target string) *session.Session {
			var id [frame.SessionIDLen]byte
			id[0] = 0x81
			return session.New(id, target, true)
		})
	}()

	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case err := <-errCh:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Serve err = %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not return after context cancellation")
	}
}

type noopConn struct{}

func (noopConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (noopConn) Write([]byte) (int, error)        { return 0, io.ErrClosedPipe }
func (noopConn) Close() error                     { return nil }
func (noopConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (noopConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (noopConn) SetDeadline(time.Time) error      { return nil }
func (noopConn) SetReadDeadline(time.Time) error  { return nil }
func (noopConn) SetWriteDeadline(time.Time) error { return nil }
