// Package socks adapts the SOCKS5 server to relay-tunnel sessions.
package socks

import (
	"context"
	"errors"
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
	s             *session.Session
	mu            sync.Mutex
	readBuf       []byte
	readDeadline  time.Time
	writeDeadline time.Time
	deadlineCh    chan struct{}
}

func NewVirtualConn(s *session.Session) *VirtualConn {
	return &VirtualConn{s: s, deadlineCh: make(chan struct{})}
}

func (v *VirtualConn) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	for {
		v.mu.Lock()
		if len(v.readBuf) > 0 {
			n := copy(b, v.readBuf)
			v.readBuf = v.readBuf[n:]
			v.mu.Unlock()
			return n, nil
		}
		deadline := v.readDeadline
		deadlineCh := v.deadlineCh
		v.mu.Unlock()

		var timerCh <-chan time.Time
		var timer *time.Timer
		if !deadline.IsZero() {
			dur := time.Until(deadline)
			if dur <= 0 {
				return 0, context.DeadlineExceeded
			}
			timer = time.NewTimer(dur)
			timerCh = timer.C
		}

		select {
		case data, ok := <-v.s.RxChan:
			stopReadTimer(timer)
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
		case <-deadlineCh:
			stopReadTimer(timer)
			continue
		}
	}
}

func stopReadTimer(timer *time.Timer) {
	if timer == nil {
		return
	}
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
}

func (v *VirtualConn) Write(b []byte) (int, error) {
	if len(b) > 0 {
		deadline := func() time.Time {
			v.mu.Lock()
			defer v.mu.Unlock()
			return v.writeDeadline
		}
		// connect_data optimization: if this is the first write for a new
		// session and the SYN hasn't been sent yet, bundle it.
		if err := v.s.EnqueueInitialDataDeadlineFunc(b, deadline); err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				return 0, context.DeadlineExceeded
			}
			return 0, io.ErrClosedPipe
		}
	}
	return len(b), nil
}

func (v *VirtualConn) Close() error {
	v.s.RequestClose()
	v.s.Stop()
	v.signalDeadlineWaiters()
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
	v.writeDeadline = t
	v.signalDeadlineLocked()
	v.mu.Unlock()
	v.s.WakeTxWaiters()
	return nil
}
func (v *VirtualConn) SetReadDeadline(t time.Time) error {
	v.mu.Lock()
	v.readDeadline = t
	v.signalDeadlineLocked()
	v.mu.Unlock()
	return nil
}
func (v *VirtualConn) SetWriteDeadline(t time.Time) error {
	v.mu.Lock()
	v.writeDeadline = t
	v.mu.Unlock()
	v.s.WakeTxWaiters()
	return nil
}

func (v *VirtualConn) signalDeadlineWaiters() {
	v.mu.Lock()
	v.signalDeadlineLocked()
	v.mu.Unlock()
}

func (v *VirtualConn) signalDeadlineLocked() {
	close(v.deadlineCh)
	v.deadlineCh = make(chan struct{})
}
