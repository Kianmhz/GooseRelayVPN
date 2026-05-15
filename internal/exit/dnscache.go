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
	ips     []string
	expires time.Time
}

func newDNSCache() *dnsCache {
	return &dnsCache{entries: make(map[string]dnsEntry)}
}

// get returns cached IPs for host, or nil if missing/expired. Expired entries
// are evicted on access to keep the map small.
func (c *dnsCache) get(host string) []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[host]
	if !ok {
		return nil
	}
	if time.Now().After(e.expires) {
		delete(c.entries, host)
		return nil
	}
	return append([]string(nil), e.ips...)
}

func (c *dnsCache) set(host string, ips []string) {
	if len(ips) == 0 {
		return
	}
	c.mu.Lock()
	c.entries[host] = dnsEntry{ips: append([]string(nil), ips...), expires: time.Now().Add(dnsCacheTTL)}
	c.mu.Unlock()
}

func (c *dnsCache) rememberSuccess(host, ip string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[host]
	if !ok || time.Now().After(e.expires) || len(e.ips) <= 1 || e.ips[0] == ip {
		return
	}
	next := make([]string, 0, len(e.ips))
	next = append(next, ip)
	for _, cached := range e.ips {
		if cached != ip {
			next = append(next, cached)
		}
	}
	e.ips = next
	c.entries[host] = e
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
	return dialWithDNSCacheContext(context.Background(), cache, baseDial, network, address, timeout)
}

func dialWithDNSCacheContext(
	ctx context.Context,
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
	if ips := cache.get(host); len(ips) > 0 {
		res, derr := dialResolvedIPs(cache, baseDial, network, host, port, timeout, ips, true, 0)
		if derr != nil {
			// Cached IPs failed; evict so the next call re-resolves.
			cache.forget(host)
			return nil, derr
		}
		return res, nil
	}
	// Cache miss: resolve, then dial. Use a context bounded by `timeout`
	// so a slow resolver cannot eat the entire dial budget.
	ctx, cancel := context.WithTimeout(ctx, timeout)
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
	ips := make([]string, 0, len(addrs))
	seen := make(map[string]struct{}, len(addrs))
	for _, addr := range addrs {
		ip := addr.IP.String()
		if ip == "" {
			continue
		}
		if _, ok := seen[ip]; ok {
			continue
		}
		seen[ip] = struct{}{}
		ips = append(ips, ip)
	}
	cache.set(host, ips)
	return dialResolvedIPs(cache, baseDial, network, host, port, timeout, ips, false, dnsElapsed)
}

func dialResolvedIPs(
	cache *dnsCache,
	baseDial func(network, address string, timeout time.Duration) (net.Conn, error),
	network, host, port string,
	timeout time.Duration,
	ips []string,
	cached bool,
	dnsElapsed time.Duration,
) (*dialResult, error) {
	deadline := time.Now().Add(timeout)
	var (
		lastErr error
		tcpSum  time.Duration
	)
	for _, ip := range ips {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			break
		}
		tcpStart := time.Now()
		conn, err := baseDial(network, net.JoinHostPort(ip, port), remaining)
		tcpElapsed := time.Since(tcpStart)
		tcpSum += tcpElapsed
		if err == nil {
			cache.rememberSuccess(host, ip)
			return &dialResult{Conn: conn, DNSCached: cached, DNS: dnsElapsed, TCP: tcpSum}, nil
		}
		lastErr = err
	}
	if lastErr != nil {
		return nil, lastErr
	}
	tcpStart := time.Now()
	conn, err := baseDial(network, net.JoinHostPort(host, port), timeout)
	if err != nil {
		return nil, err
	}
	return &dialResult{Conn: conn, DNSCached: cached, DNS: dnsElapsed, TCP: time.Since(tcpStart)}, nil
}
