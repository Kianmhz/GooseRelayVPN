// Package socks adapts the SOCKS5 server to relay-tunnel sessions.
package socks

import (
	"context"
	"io"
	"net"
	"sync"
	"time"

	"github.com/kianmhz/GooseRelayVPN/internal/session"
)

// VirtualConn fulfills net.Conn by reading from session.RxChan and writing to
// session.EnqueueTx. The SOCKS5 library hands this back to the local SOCKS
// client and treats it as a regular TCP connection.
//
// Ported from FlowDriver/internal/transport/conn.go.
type VirtualConn struct {
	s            *session.Session
	mu           sync.Mutex
	readBuf      []byte
	readDeadline time.Time
}

func NewVirtualConn(s *session.Session) *VirtualConn { return &VirtualConn{s: s} }

func (v *VirtualConn) Read(b []byte) (int, error) {
	for {
		v.mu.Lock()
		if len(v.readBuf) > 0 {
			n := copy(b, v.readBuf)
			v.readBuf = v.readBuf[n:]
			v.mu.Unlock()
			return n, nil
		}
		deadline := v.readDeadline
		v.mu.Unlock()

		var timerCh <-chan time.Time
		if !deadline.IsZero() {
			dur := time.Until(deadline)
			if dur <= 0 {
				return 0, context.DeadlineExceeded
			}
			timerCh = time.After(dur)
		}

		select {
		case data, ok := <-v.s.RxChan:
			if !ok {
				return 0, io.EOF
			}
			if len(data) == 0 {
				continue
			}
			v.mu.Lock()
			n := copy(b, data)
			if n < len(data) {
				v.readBuf = data[n:]
			}
			v.mu.Unlock()
			return n, nil
		case <-timerCh:
			return 0, context.DeadlineExceeded
		}
	}
}

func (v *VirtualConn) Write(b []byte) (int, error) {
	if len(b) > 0 {
		// connect_data optimization: if this is the first write for a new
		// session and the SYN hasn't been sent yet, bundle it.
		if err := v.s.EnqueueInitialData(b); err != nil {
			return 0, io.ErrClosedPipe
		}
	}
	return len(b), nil
}

func (v *VirtualConn) Close() error {
	v.s.RequestClose()
	return nil
}

func (v *VirtualConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
}
func (v *VirtualConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
}
func (v *VirtualConn) SetDeadline(t time.Time) error {
	v.mu.Lock()
	v.readDeadline = t
	v.mu.Unlock()
	return nil
}
func (v *VirtualConn) SetReadDeadline(t time.Time) error {
	v.mu.Lock()
	v.readDeadline = t
	v.mu.Unlock()
	return nil
}
func (v *VirtualConn) SetWriteDeadline(t time.Time) error { return nil }
