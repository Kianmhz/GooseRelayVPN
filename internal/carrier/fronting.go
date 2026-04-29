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
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/net/http2"
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
//
// GoogleIP may be a single "ip:port" or a comma-separated list of "ip:port"
// values. With multiple IPs each dial round-robins across them so a single
// brittle Google PoP can't bring the tunnel down.
type FrontingConfig struct {
	GoogleIP string   // "ip:443" or "ip1:443,ip2:443,ip3:443"
	SNIHosts []string // e.g. ["www.google.com", "mail.google.com", "accounts.google.com"]
}

// NewFrontedClients returns one *http.Client per SNI host in cfg.SNIHosts.
// Each client has an independent transport/connection-pool so requests to
// different SNI names are genuinely separate TLS sessions, each consuming
// its own throttle bucket.
//
// pollTimeout is the per-request ceiling; it should comfortably exceed the
// server's long-poll window (we use ~25 s).
func NewFrontedClients(cfg FrontingConfig, pollTimeout time.Duration) []*http.Client {
	hosts := cfg.SNIHosts
	if len(hosts) == 0 {
		hosts = []string{"www.google.com"}
	}
	googleIPs := splitGoogleIPs(cfg.GoogleIP)
	clients := make([]*http.Client, len(hosts))
	for i, sni := range hosts {
		clients[i] = newFrontedClient(googleIPs, sni, pollTimeout)
	}
	return clients
}

// splitGoogleIPs accepts either a single "ip:port" or a comma-separated list,
// trims whitespace, and returns the parsed slice. An empty/whitespace input
// returns nil so dialContext falls back to default DNS resolution.
func splitGoogleIPs(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// tlsSessionCache is a process-global LRU cache of TLS 1.3 session tickets.
// Without an explicit ClientSessionCache, Go's tls package re-handshakes from
// scratch on every cold connection — which is every time MaxIdleConnsPerHost
// rotates a stale conn or the GFE rotates us to a new edge IP that still
// happens to issue a resumable ticket. With this cache, resumed handshakes
// are 1-RTT (vs 2-RTT for full TLS 1.3), saving ~1 RTT to Google on every
// cold reconnect. Sized at 64 entries so we cache tickets across all
// configured google_host IPs and SNI variations comfortably.
var tlsSessionCache = tls.NewLRUClientSessionCache(64)

// newFrontedClient builds a single *http.Client that dials one of googleIPs
// (round-robin) and presents sniHost in the TLS handshake.
func newFrontedClient(googleIPs []string, sniHost string, pollTimeout time.Duration) *http.Client {
	dialer := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}

	var rrCounter atomic.Uint64
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if len(googleIPs) == 0 {
				return dialer.DialContext(ctx, network, addr)
			}
			// Round-robin across configured Google IPs so a single brittle
			// edge node can't take the tunnel down. For one configured IP this
			// reduces to the previous behavior.
			idx := rrCounter.Add(1) - 1
			ip := googleIPs[idx%uint64(len(googleIPs))]
			conn, err := dialer.DialContext(ctx, "tcp", ip)
			if err != nil && len(googleIPs) > 1 {
				// Try the next IP exactly once; if the first attempt failed
				// (TCP RST, host unreachable, slow handshake) we don't want
				// to fail the whole poll while another known-good IP is
				// available in the same client.
				next := googleIPs[(idx+1)%uint64(len(googleIPs))]
				if conn2, err2 := dialer.DialContext(ctx, "tcp", next); err2 == nil {
					return conn2, nil
				}
			}
			return conn, err
		},
		TLSClientConfig: &tls.Config{
			ServerName: sniHost,
			// Require TLS 1.3 to (a) eliminate TLS 1.2's 2-RTT handshake on
			// cold pools and (b) get ChaCha20-Poly1305 negotiation when the
			// CPU lacks AES-NI. All Google front-ends advertise 1.3.
			MinVersion: tls.VersionTLS13,
			// Reuse session tickets across cold reconnects so resumed
			// handshakes are 1-RTT instead of 2-RTT. Cache is process-global
			// and shared across all per-SNI clients.
			ClientSessionCache: tlsSessionCache,
		},
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          16,
		MaxIdleConnsPerHost:   workersPerEndpoint + 1, // ≥ workers/endpoint so cold-pool handshakes are rare
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   15 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		WriteBufferSize:       64 * 1024,
		ReadBufferSize:        64 * 1024,
	}
	// Configure HTTP/2 so the long-lived h2 connection sends pings and detects
	// black-holed peers quickly. Without ReadIdleTimeout, a dead h2 conn can
	// linger until the kernel's TCP keepalive fires (~2 hours by default),
	// leaking poll worker time as in-flight requests stall.
	if h2t, err := http2.ConfigureTransports(transport); err == nil && h2t != nil {
		h2t.ReadIdleTimeout = 30 * time.Second
		h2t.PingTimeout = 15 * time.Second
		// Raise the max DATA frame size we are willing to receive from 16 KiB
		// (spec default) to 1 MiB. Each DATA frame carries a 9-byte header,
		// so on a long bulk download (Apps Script gateway streaming a video
		// chunk back) the framing overhead drops by ~64× and the receiver
		// makes ~64× fewer Read syscalls per MiB. Stream/conn flow control
		// windows in golang.org/x/net/http2 already default to 4 MiB / 1 GiB,
		// so the actual throughput cap is RTT-bound, not window-bound.
		h2t.MaxReadFrameSize = 1 << 20
	}
	return &http.Client{Transport: transport, Timeout: pollTimeout}
}
