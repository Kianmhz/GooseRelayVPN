// Package carrier implements the client side of the Apps Script transport:
// a long-poll loop that batches outgoing frames, POSTs them through a
// domain-fronted HTTPS connection, and routes the response frames back to
// their sessions.
package carrier

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"time"
)

// FrontingConfig describes how to reach script.google.com without revealing
// the real Host to a passive on-path observer: dial GoogleIP, do a TLS
// handshake with one of the SNIHosts. Go's default behavior of Host = URL.Host
// then routes the request to the right Google backend (and follows the Apps
// Script 302 redirect to script.googleusercontent.com correctly).
//
// Multiple SNIHosts are supported: each creates an independent HTTP client
// with its own connection pool, which maps to a separate TLS SNI value and
// therefore a separate per-domain throttle bucket on the Google CDN. Requests
// are distributed across clients in round-robin order.
type FrontingConfig struct {
	GoogleIP string   // "ip:443"
	SNIHosts []string // e.g. ["www.google.com", "mail.google.com", "accounts.google.com"]
}

// NewFrontedClients returns one *http.Client per SNI host in cfg.SNIHosts.
// Each client has an independent transport/connection-pool so requests to
// different SNI names are genuinely separate TLS sessions, each consuming
// its own throttle bucket.
//
// pollTimeout is the per-request ceiling; it should comfortably exceed the
// server's long-poll window (we use ~25 s).
//
// Each SNI gets its own tls.ClientSessionCache. A ticket from one Google
// edge backend (e.g. www.google.com) is not valid for another (e.g.
// mail.google.com) because they terminate at different fronts, so a
// shared cache produces no resumes — only same-SNI reuse helps.
func NewFrontedClients(cfg FrontingConfig, pollTimeout time.Duration) []*http.Client {
	hosts := cfg.SNIHosts
	if len(hosts) == 0 {
		hosts = []string{"www.google.com"}
	}
	caches := make(map[string]tls.ClientSessionCache, len(hosts))
	for _, sni := range hosts {
		if _, ok := caches[sni]; !ok {
			caches[sni] = tls.NewLRUClientSessionCache(8)
		}
	}
	clients := make([]*http.Client, len(hosts))
	for i, sni := range hosts {
		clients[i] = newFrontedClient(cfg.GoogleIP, sni, pollTimeout, caches[sni])
	}
	// Best-effort: warm each SNI's TLS session in the background so the
	// first real poll resumes (saves ~140 ms TLS handshake per cold conn).
	// Zero Apps Script executions consumed; failures are silently ignored.
	prewarmFrontedClients(cfg.GoogleIP, hosts, caches)
	return clients
}

// prewarmFrontedClients fires one TLS dial per SNI host in the background
// to populate each SNI's session ticket cache. Critical detail: in TLS 1.3
// the server sends NewSessionTicket *after* the handshake completes, on
// the data channel. Closing immediately after HandshakeContext drops the
// ticket on the floor (this is exactly why our first probe showed
// resumed=false everywhere). To capture the ticket we issue a tiny read
// with a short deadline; the read errors out on deadline but by then the
// crypto/tls layer has consumed the post-handshake message and stored the
// ticket in the cache.
func prewarmFrontedClients(googleIP string, sniHosts []string, caches map[string]tls.ClientSessionCache) {
	const (
		dialTimeout   = 3 * time.Second
		ticketWindow  = 500 * time.Millisecond
		overallBudget = 5 * time.Second
	)
	dialer := &net.Dialer{Timeout: dialTimeout}
	for _, sni := range sniHosts {
		go func(sniHost string, cache tls.ClientSessionCache) {
			ctx, cancel := context.WithTimeout(context.Background(), overallBudget)
			defer cancel()
			addr := googleIP
			if addr == "" {
				addr = net.JoinHostPort(sniHost, "443")
			}
			rawConn, err := dialer.DialContext(ctx, "tcp", addr)
			if err != nil {
				return
			}
			defer rawConn.Close()
			tlsConn := tls.Client(rawConn, &tls.Config{
				ServerName:         sniHost,
				ClientSessionCache: cache,
				// Match the real http.Transport ALPN so the resumed
				// session is usable by HTTP/2 in the actual poll.
				NextProtos: []string{"h2", "http/1.1"},
			})
			if err := tlsConn.HandshakeContext(ctx); err != nil {
				return
			}
			// Wait briefly so the post-handshake NewSessionTicket frame
			// arrives and crypto/tls stores it in cache. We expect the
			// read to time out (no real server-initiated data), which is
			// fine — the side-effect of receiving and parsing the ticket
			// is what we actually want.
			_ = tlsConn.SetReadDeadline(time.Now().Add(ticketWindow))
			var buf [1]byte
			_, _ = tlsConn.Read(buf[:])
		}(sni, caches[sni])
	}
}

// newFrontedClient builds a single *http.Client that dials googleIP and
// presents sniHost in the TLS handshake.
func newFrontedClient(googleIP, sniHost string, pollTimeout time.Duration, sessionCache tls.ClientSessionCache) *http.Client {
	dialer := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}

	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if googleIP != "" {
				return dialer.DialContext(ctx, "tcp", googleIP)
			}
			return dialer.DialContext(ctx, network, addr)
		},
		TLSClientConfig: &tls.Config{
			ServerName: sniHost,
			// Enable TLS session resumption tickets so reconnects after
			// idle timeout (and the prewarm dial in NewFrontedClients) can
			// skip a full handshake round-trip.
			ClientSessionCache: sessionCache,
			// Pin ALPN so the resumed session matches the prewarm dial.
			// (The TLS 1.3 resumption ticket is bound to ALPN; mismatched
			// NextProtos causes the server to fall back to a full handshake.)
			NextProtos: []string{"h2", "http/1.1"},
		},
		ForceAttemptHTTP2: true,
		MaxIdleConns:      16,
		// Default MaxIdleConnsPerHost is 2, which forces idle h1 conns to be
		// recycled between poll workers when ALPN downgrades or the server
		// closes h2 streams. Pin it to roughly the worker count per endpoint
		// so each worker can keep its own warm conn.
		MaxIdleConnsPerHost: workersPerEndpoint * 2,
		// Larger HTTP read/write buffers cut syscall count on bulk batch
		// bodies (server can return up to ~12 MB per poll under busy
		// fan-out: 144 frames × 256 KB max payload, base64-expanded).
		WriteBufferSize:       64 * 1024,
		ReadBufferSize:        64 * 1024,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   15 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	return &http.Client{Transport: transport, Timeout: pollTimeout}
}
