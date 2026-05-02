// Package carrier implements the client side of the Apps Script transport:
// a long-poll loop that batches outgoing frames, POSTs them through a
// domain-fronted HTTPS connection, and routes the response frames back to
// their sessions.
package carrier

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync/atomic"
	"time"
)

const frontedProbeOKBody = "GooseRelay forwarder OK"

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
	GoogleIP string   // "ip:443" or "ip1:443,ip2:443"
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
func NewFrontedClients(cfg FrontingConfig, pollTimeout time.Duration, probeURL string) []*http.Client {
	hosts := cfg.SNIHosts
	if len(hosts) == 0 {
		hosts = []string{"www.google.com"}
	}
	googleIPs := splitGoogleIPs(cfg.GoogleIP)
	caches := make(map[string]tls.ClientSessionCache, len(hosts))
	for _, sni := range hosts {
		if _, ok := caches[sni]; !ok {
			caches[sni] = tls.NewLRUClientSessionCache(8)
		}
	}
	clients := make([]*http.Client, len(hosts))
	for i, sni := range hosts {
		clients[i] = newFrontedClient(googleIPs, sni, pollTimeout, caches[sni])
	}
	hosts, clients = filterFrontedClientsByProbe(hosts, clients, probeURL)
	// Best-effort: warm each SNI's TLS session in the background so the
	// first real poll resumes (saves ~140 ms TLS handshake per cold conn).
	// Zero Apps Script executions consumed; failures are silently ignored.
	prewarmFrontedClients(googleIPs, hosts, caches)
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

type frontedProbeResult struct {
	index   int
	host    string
	client  *http.Client
	samples []time.Duration
	err     error
}

func (r frontedProbeResult) ok() bool {
	return len(r.samples) > 0
}

func (r frontedProbeResult) latency() time.Duration {
	if len(r.samples) == 0 {
		return 0
	}
	sorted := append([]time.Duration(nil), r.samples...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	return sorted[len(sorted)/2]
}

// filterFrontedClientsByProbe probes each configured SNI once at startup and
// removes only clearly bad candidates: hosts that never complete a response,
// or successful hosts that are dramatic outliers while at least two faster
// survivors remain. Round-robin still happens across the retained set.
func filterFrontedClientsByProbe(hosts []string, clients []*http.Client, probeURL string) ([]string, []*http.Client) {
	if len(hosts) <= 1 || probeURL == "" {
		return hosts, clients
	}

	results := probeFrontedClients(hosts, clients, probeURL)
	keep := selectFrontedClientIndexes(results)
	if len(keep) == 0 {
		return hosts, clients
	}

	keptHosts := make([]string, 0, len(keep))
	keptClients := make([]*http.Client, 0, len(keep))
	kept := make(map[int]struct{}, len(keep))
	for _, idx := range keep {
		kept[idx] = struct{}{}
		keptHosts = append(keptHosts, hosts[idx])
		keptClients = append(keptClients, clients[idx])
	}

	logFrontedProbeDecision(results, keep)
	return keptHosts, keptClients
}

func probeFrontedClients(hosts []string, clients []*http.Client, probeURL string) []frontedProbeResult {
	const (
		probeSamples = 2
		probeTimeout = 8 * time.Second
	)
	results := make([]frontedProbeResult, len(hosts))
	resultCh := make(chan frontedProbeResult, len(hosts))
	for i, host := range hosts {
		client := clients[i]
		go func(index int, sniHost string, httpClient *http.Client) {
			res := frontedProbeResult{index: index, host: sniHost, client: httpClient}
			for sample := 0; sample < probeSamples; sample++ {
				ctx, cancel := context.WithTimeout(context.Background(), probeTimeout)
				req, err := http.NewRequestWithContext(ctx, http.MethodGet, probeURL, nil)
				if err != nil {
					cancel()
					res.err = err
					break
				}
				start := time.Now()
				resp, err := httpClient.Do(req)
				if err != nil {
					cancel()
					res.err = err
					continue
				}
				body, readErr := io.ReadAll(resp.Body)
				_ = resp.Body.Close()
				if readErr != nil {
					cancel()
					res.err = readErr
					continue
				}
				if err := validateFrontedProbeResponse(resp.StatusCode, body); err != nil {
					cancel()
					res.err = err
					continue
				}
				res.samples = append(res.samples, time.Since(start))
				cancel()
			}
			resultCh <- res
		}(i, host, client)
	}

	for range hosts {
		res := <-resultCh
		results[res.index] = res
	}
	return results
}

func validateFrontedProbeResponse(statusCode int, body []byte) error {
	if statusCode != http.StatusOK {
		return fmt.Errorf("unexpected probe status %d", statusCode)
	}
	if strings.TrimSpace(string(body)) != frontedProbeOKBody {
		return fmt.Errorf("unexpected probe body %q", strings.TrimSpace(string(body)))
	}
	return nil
}

func selectFrontedClientIndexes(results []frontedProbeResult) []int {
	if len(results) <= 1 {
		return allFrontedClientIndexes(len(results))
	}

	successes := make([]frontedProbeResult, 0, len(results))
	for _, res := range results {
		if res.ok() {
			successes = append(successes, res)
		}
	}
	if len(successes) == 0 {
		return allFrontedClientIndexes(len(results))
	}
	if len(successes) == 1 {
		return []int{successes[0].index}
	}

	latencies := make([]time.Duration, 0, len(successes))
	for _, res := range successes {
		latencies = append(latencies, res.latency())
	}
	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
	median := latencies[len(latencies)/2]
	if len(successes) <= 2 || median <= 0 {
		return indexesForFrontedResults(successes)
	}

	threshold := 3 * median
	kept := make([]int, 0, len(successes))
	for _, res := range successes {
		if res.latency() <= threshold {
			kept = append(kept, res.index)
		}
	}
	if len(kept) < 2 {
		return indexesForFrontedResults(successes)
	}
	return kept
}

func indexesForFrontedResults(results []frontedProbeResult) []int {
	indexes := make([]int, 0, len(results))
	for _, res := range results {
		indexes = append(indexes, res.index)
	}
	return indexes
}

func allFrontedClientIndexes(n int) []int {
	indexes := make([]int, n)
	for i := range indexes {
		indexes[i] = i
	}
	return indexes
}

func logFrontedProbeDecision(results []frontedProbeResult, keep []int) {
	kept := make(map[int]struct{}, len(keep))
	for _, idx := range keep {
		kept[idx] = struct{}{}
	}
	latencies := make([]time.Duration, 0, len(results))
	for _, res := range results {
		if res.ok() {
			latencies = append(latencies, res.latency())
		}
	}
	if len(latencies) > 0 {
		sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
	}
	median := time.Duration(0)
	if len(latencies) > 0 {
		median = latencies[len(latencies)/2]
	}
	for _, res := range results {
		action := "drop"
		if _, ok := kept[res.index]; ok {
			action = "keep"
		}
		if res.ok() {
			log.Printf("[fronting] startup probe %s sni=%s ttfb=%s samples=%d", action, res.host, res.latency().Round(time.Millisecond), len(res.samples))
			continue
		}
		if res.err != nil {
			log.Printf("[fronting] startup probe %s sni=%s err=%v", action, res.host, res.err)
			continue
		}
		log.Printf("[fronting] startup probe %s sni=%s no-successful-samples", action, res.host)
	}
	log.Printf("[fronting] startup probe kept %d/%d sni hosts median_ttfb=%s", len(keep), len(results), median.Round(time.Millisecond))
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
func prewarmFrontedClients(googleIPs []string, sniHosts []string, caches map[string]tls.ClientSessionCache) {
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
			addr := ""
			if len(googleIPs) > 0 {
				addr = googleIPs[0]
			}
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

// newFrontedClient builds a single *http.Client that dials one of googleIPs
// (round-robin) and presents sniHost in the TLS handshake.
func newFrontedClient(googleIPs []string, sniHost string, pollTimeout time.Duration, sessionCache tls.ClientSessionCache) *http.Client {
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
