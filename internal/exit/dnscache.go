package exit

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"
)

// dnsCacheTTL is how long a successful resolution is reused before re-querying.
// Five minutes balances staleness against resolver round-trips on repeated
// connections to popular targets (CDNs, video hosts) where the same hostname
// is dialed dozens of times in quick succession.
const dnsCacheTTL = 5 * time.Minute

// dnsNegativeCacheTTL is how long an NXDOMAIN/timeout result is cached.
// Short enough that transient resolver issues recover quickly, long enough
// that repeated dials to a typo'd target don't hammer the upstream resolver.
const dnsNegativeCacheTTL = 30 * time.Second

// dnsCache holds recent hostname → IP resolutions to skip the resolver on
// repeated dials to the same target. Goroutine-safe.
//
// Per entry we store all addresses returned by LookupIPAddr (rather than just
// the first), and rotate through them on dial failure so a single broken IP
// doesn't blackhole all dials to a multi-A-record host.
type dnsCache struct {
	mu      sync.Mutex
	entries map[string]*dnsEntry
}

type dnsEntry struct {
	ips      []string
	rrCursor int
	expires  time.Time
	negative bool // true → resolution failed (NXDOMAIN/timeout); ips empty
}

func newDNSCache() *dnsCache {
	return &dnsCache{entries: make(map[string]*dnsEntry)}
}

// pick returns the next cached IP for host, advancing the round-robin cursor.
// Returns "" + false on miss/expired/negative-still-valid; in the negative-
// cached case the second return value is true with neg=true so the caller can
// short-circuit the resolver.
func (c *dnsCache) pick(host string) (ip string, hit bool, neg bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[host]
	if !ok {
		return "", false, false
	}
	if time.Now().After(e.expires) {
		delete(c.entries, host)
		return "", false, false
	}
	if e.negative {
		return "", true, true
	}
	if len(e.ips) == 0 {
		return "", false, false
	}
	ip = e.ips[e.rrCursor%len(e.ips)]
	e.rrCursor++
	return ip, true, false
}

// markFailure rotates past the IP that just failed to dial. The next pick
// returns a different IP. If all IPs in the entry are exhausted within one
// round-trip we fall back to re-resolving on the next call.
func (c *dnsCache) markFailure(host, ip string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[host]
	if !ok {
		return
	}
	// Drop the failing IP from the list so it isn't re-tried within this
	// cache window; if all IPs end up dropped, evict the entry entirely so
	// the next lookup forces a fresh resolution.
	out := make([]string, 0, len(e.ips))
	for _, x := range e.ips {
		if x != ip {
			out = append(out, x)
		}
	}
	if len(out) == 0 {
		delete(c.entries, host)
		return
	}
	e.ips = out
	e.rrCursor = 0
}

func (c *dnsCache) setOK(host string, ips []string) {
	c.mu.Lock()
	c.entries[host] = &dnsEntry{
		ips:     ips,
		expires: time.Now().Add(dnsCacheTTL),
	}
	c.mu.Unlock()
}

func (c *dnsCache) setNegative(host string) {
	c.mu.Lock()
	c.entries[host] = &dnsEntry{
		expires:  time.Now().Add(dnsNegativeCacheTTL),
		negative: true,
	}
	c.mu.Unlock()
}

// dialResult is the outcome of dialWithDNSCache. The timing fields are always
// populated (the cost is two time.Now calls) so callers can log them on demand.
type dialResult struct {
	Conn      net.Conn
	DNSCached bool          // true if the cache served the host without a fresh lookup
	DNS       time.Duration // time spent in DNS resolution (zero on literal IP or cache hit)
	TCP       time.Duration // time spent in the underlying baseDial call
}

// errCachedNXDOMAIN is the sentinel returned from dialWithDNSCache when
// negative caching short-circuits the resolver.
var errCachedNXDOMAIN = errors.New("dns: cached negative result")

// dialWithDNSCache resolves host:port through the cache, then dials the
// underlying TCP connection via baseDial. Falls through to baseDial directly
// when the address is already a literal IP or unparseable.
func dialWithDNSCache(
	cache *dnsCache,
	baseDial func(network, address string, timeout time.Duration) (net.Conn, error),
	network, address string,
	timeout time.Duration,
) (*dialResult, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil || net.ParseIP(host) != nil {
		// Literal IP or malformed — let baseDial handle it.
		tcpStart := time.Now()
		conn, derr := baseDial(network, address, timeout)
		if derr != nil {
			return nil, derr
		}
		return &dialResult{Conn: conn, TCP: time.Since(tcpStart)}, nil
	}

	// Negative cache short-circuit.
	if ip, hit, neg := cache.pick(host); hit {
		if neg {
			return nil, errCachedNXDOMAIN
		}
		tcpStart := time.Now()
		conn, derr := baseDial(network, net.JoinHostPort(ip, port), timeout)
		tcpElapsed := time.Since(tcpStart)
		if derr != nil {
			cache.markFailure(host, ip)
			return nil, derr
		}
		return &dialResult{Conn: conn, DNSCached: true, TCP: tcpElapsed}, nil
	}

	// Cache miss: resolve, then dial. Use a context bounded by `timeout`
	// so a slow resolver cannot eat the entire dial budget.
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	dnsStart := time.Now()
	addrs, lerr := net.DefaultResolver.LookupIPAddr(ctx, host)
	dnsElapsed := time.Since(dnsStart)
	if lerr != nil || len(addrs) == 0 {
		cache.setNegative(host)
		// Fall through to baseDial which will surface the same/similar error.
		tcpStart := time.Now()
		conn, derr := baseDial(network, address, timeout)
		if derr != nil {
			return nil, derr
		}
		return &dialResult{Conn: conn, DNS: dnsElapsed, TCP: time.Since(tcpStart)}, nil
	}
	ips := make([]string, 0, len(addrs))
	for _, a := range addrs {
		ips = append(ips, a.IP.String())
	}
	cache.setOK(host, ips)
	tcpStart := time.Now()
	conn, derr := baseDial(network, net.JoinHostPort(ips[0], port), timeout)
	tcpElapsed := time.Since(tcpStart)
	if derr != nil {
		cache.markFailure(host, ips[0])
		return nil, derr
	}
	return &dialResult{Conn: conn, DNS: dnsElapsed, TCP: tcpElapsed}, nil
}
