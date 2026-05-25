package socks

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"

	"github.com/kianmhz/GooseRelayVPN/internal/session"
	"github.com/things-go/go-socks5"
	"github.com/things-go/go-socks5/statute"
)

// SessionFactory creates a new tunneled session for the given "host:port"
// target. The returned session is owned by the carrier (which polls it for
// outgoing frames and routes incoming ones).
type SessionFactory func(target string) *session.Session

// Serve starts a SOCKS5 listener on listenAddr that wraps every connection in
// a VirtualConn over a fresh tunneled session. The DNS resolver is overridden
// with a no-op to prevent local DNS leaks (clients must use socks5h://).
//
// Wraps the listener with a TCP_NODELAY + TCP_QUICKACK applying acceptor so
// the kernel doesn't introduce 40 ms Nagle delays on small SOCKS payloads
// (HTTP request lines, TLS handshake records) and doesn't hold back ACKs for
// up to 40 ms on small request/reply pairs. The exit side already disables
// Nagle for upstream connections; mirroring on the local side closes the loop.
//
// When user and pass are both non-empty, RFC 1929 username/password
// authentication is required; unauthenticated clients are rejected.
//
// Blocks until the SOCKS server returns or ctx is canceled. The underlying
// go-socks5 server does not accept a context, so cancellation closes the
// listener to unblock Serve.
func Serve(ctx context.Context, listenAddr, user, pass string, debugTiming bool, maxSessions int, factory SessionFactory) error {
	if ctx == nil {
		ctx = context.Background()
	}
	limiter := newSessionLimiter(maxSessions)
	opts := []socks5.Option{
		socks5.WithDial(func(_ context.Context, _, addr string) (net.Conn, error) {
			release, ok := limiter.acquire()
			if !ok {
				return nil, fmt.Errorf("max local SOCKS sessions reached (%d)", maxSessions)
			}
			s := factory(addr)
			if debugTiming {
				log.Printf("[socks] new session %x for %s", s.ID[:4], addr)
			}
			return &limitedConn{Conn: NewVirtualConn(s), release: release}, nil
		}),
		socks5.WithAssociateHandle(func(_ context.Context, w io.Writer, _ *socks5.Request) error {
			_ = socks5.SendReply(w, statute.RepCommandNotSupported, nil)
			return fmt.Errorf("UDP associate not supported")
		}),
		socks5.WithResolver(noopResolver{}),
	}
	if user != "" {
		opts = append(opts, socks5.WithAuthMethods([]socks5.Authenticator{
			socks5.UserPassAuthenticator{
				Credentials: socks5.StaticCredentials{user: pass},
			},
		}))
	}

	ln, err := net.Listen(listenNetwork(listenAddr), listenAddr)
	if err != nil {
		return err
	}
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = ln.Close()
		case <-done:
		}
	}()
	server := socks5.NewServer(opts...)
	err = server.Serve(&noDelayListener{Listener: ln})
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}

type sessionLimiter struct {
	max    int
	active atomic.Int32
}

func newSessionLimiter(max int) *sessionLimiter {
	return &sessionLimiter{max: max}
}

func (l *sessionLimiter) acquire() (func(), bool) {
	if l == nil || l.max <= 0 {
		return func() {}, true
	}
	current := l.active.Add(1)
	if current > int32(l.max) {
		l.active.Add(-1)
		return nil, false
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			l.active.Add(-1)
		})
	}, true
}

type limitedConn struct {
	net.Conn
	release func()
	once    sync.Once
}

func (c *limitedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() {
		if c.release != nil {
			c.release()
		}
	})
	return err
}

func listenNetwork(listenAddr string) string {
	host, _, err := net.SplitHostPort(listenAddr)
	if err != nil {
		return "tcp"
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return "tcp"
	}
	if ip.To4() != nil {
		return "tcp4"
	}
	return "tcp6"
}

// noDelayListener wraps net.Listener so each accepted *net.TCPConn has both
// SetNoDelay(true) and (on Linux) TCP_QUICKACK applied. This eliminates the
// kernel's 40 ms Nagle delay on small SOCKS write payloads and the 40 ms
// delayed-ACK on small read replies — together they cover both directions
// of every interactive request/reply pair (DNS-over-HTTPS, REST GETs, TLS
// handshake records).
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
	setQuickAck(c)
	return c, nil
}

// noopResolver is a SOCKS5 name resolver that returns the host string verbatim
// (no DNS lookup). Combined with socks5h:// clients, this keeps DNS off the
// local machine entirely — it's resolved on the VPS exit instead.
type noopResolver struct{}

func (noopResolver) Resolve(ctx context.Context, _ string) (context.Context, net.IP, error) {
	return ctx, nil, nil
}
