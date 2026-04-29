package socks

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"

	"github.com/kianmhz/GooseRelayVPN/internal/session"
	"github.com/things-go/go-socks5"
	"github.com/things-go/go-socks5/statute"
)

// SessionFactory creates a new tunneled session for the given "host:port"
// target. The returned session is owned by the carrier (which polls it for
// outgoing frames and routes incoming ones). Returns nil if the carrier
// cannot create a session right now (e.g. crypto/rand failure) — callers
// must surface a connection refusal cleanly instead of dereferencing nil.
type SessionFactory func(target string) *session.Session

// Serve starts a SOCKS5 listener on listenAddr that wraps every connection in
// a VirtualConn over a fresh tunneled session. The DNS resolver is overridden
// with a no-op to prevent local DNS leaks (clients must use socks5h://).
//
// Wraps the listener with a TCP_NODELAY-applying acceptor so the kernel
// doesn't introduce 40 ms Nagle delays on small SOCKS payloads (HTTP request
// lines, TLS handshake records). The exit side already does this for upstream
// connections; mirroring on the local side closes the loop.
//
// Blocks until ListenAndServe returns. Caller passes ctx for shutdown
// signaling (the underlying go-socks5 library doesn't take a ctx, so this
// just wires it through for parity with the rest of the codebase).
func Serve(ctx context.Context, listenAddr string, factory SessionFactory) error {
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return err
	}
	return ServeListener(ctx, ln, factory)
}

// ServeListener serves SOCKS5 on a caller-provided listener. The caller
// retains ownership of the listener (Close is its responsibility); this
// function returns when ln.Accept returns an error.
func ServeListener(_ context.Context, ln net.Listener, factory SessionFactory) error {
	server := socks5.NewServer(
		socks5.WithDial(func(_ context.Context, _, addr string) (net.Conn, error) {
			s := factory(addr)
			if s == nil {
				return nil, fmt.Errorf("session creation refused")
			}
			log.Printf("[socks] new session %x for %s", s.ID[:4], addr)
			return NewVirtualConn(s), nil
		}),
		socks5.WithAssociateHandle(func(_ context.Context, w io.Writer, _ *socks5.Request) error {
			_ = socks5.SendReply(w, statute.RepCommandNotSupported, nil)
			return fmt.Errorf("UDP associate not supported")
		}),
		socks5.WithResolver(noopResolver{}),
	)
	return server.Serve(&noDelayListener{Listener: ln})
}

// noDelayListener wraps net.Listener so each accepted *net.TCPConn has
// SetNoDelay(true) applied. This eliminates kernel Nagle 40ms delays on small
// SOCKS payloads (HTTP request line, TLS handshake records).
type noDelayListener struct {
	net.Listener
}

func (l *noDelayListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	if tcp, ok := c.(*net.TCPConn); ok {
		_ = tcp.SetNoDelay(true)
	}
	return c, nil
}

// noopResolver is a SOCKS5 name resolver that returns the host string verbatim
// (no DNS lookup). Combined with socks5h:// clients, this keeps DNS off the
// local machine entirely — it's resolved on the VPS exit instead.
type noopResolver struct{}

func (noopResolver) Resolve(ctx context.Context, _ string) (context.Context, net.IP, error) {
	return ctx, nil, nil
}
