package exit

import (
	"context"
	"net"
	"sync"
	"time"
)

// dnsCacheTTL is how long a successful resolution is reused before re-querying.
// Five minutes balances staleness against resolver round-trips on repeated
// connections to popular targets (CDNs, video hosts) where the same hostname
// is dialed dozens of times in quick succession.
const dnsCacheTTL = 5 * time.Minute

// dnsCache holds recent hostname → IP resolutions to skip the resolver on
// repeated dials to the same target. Goroutine-safe.
type dnsCache struct {
	mu      sync.Mutex
	entries map[string]dnsEntry
}

type dnsEntry struct {
	ip      string
	expires time.Time
}

func newDNSCache() *dnsCache {
	return &dnsCache{entries: make(map[string]dnsEntry)}
}

// get returns a cached IP for host, or "" if missing/expired. Expired entries
// are evicted on access to keep the map small.
func (c *dnsCache) get(host string) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[host]
	if !ok {
		return ""
	}
	if time.Now().After(e.expires) {
		delete(c.entries, host)
		return ""
	}
	return e.ip
}

func (c *dnsCache) set(host, ip string) {
	c.mu.Lock()
	c.entries[host] = dnsEntry{ip: ip, expires: time.Now().Add(dnsCacheTTL)}
	c.mu.Unlock()
}

func (c *dnsCache) forget(host string) {
	c.mu.Lock()
	delete(c.entries, host)
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
	if ip := cache.get(host); ip != "" {
		tcpStart := time.Now()
		conn, derr := baseDial(network, net.JoinHostPort(ip, port), timeout)
		tcpElapsed := time.Since(tcpStart)
		if derr != nil {
			// Cached IP failed; evict so the next call re-resolves.
			cache.forget(host)
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
		// Fall through to baseDial which will surface the same/similar error.
		tcpStart := time.Now()
		conn, derr := baseDial(network, address, timeout)
		if derr != nil {
			return nil, derr
		}
		return &dialResult{Conn: conn, DNS: dnsElapsed, TCP: time.Since(tcpStart)}, nil
	}
	ip := addrs[0].IP.String()
	cache.set(host, ip)
	tcpStart := time.Now()
	conn, derr := baseDial(network, net.JoinHostPort(ip, port), timeout)
	tcpElapsed := time.Since(tcpStart)
	if derr != nil {
		return nil, derr
	}
	return &dialResult{Conn: conn, DNS: dnsElapsed, TCP: tcpElapsed}, nil
}
