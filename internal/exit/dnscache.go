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
const (
	dnsCacheTTL        = 5 * time.Minute
	dnsCacheMaxEntries = 4096
)

// happyEyeballsDelay is the stagger before trying the next resolved upstream
// address while a previous candidate is still connecting. It is short enough
// to avoid multi-second stalls on broken IPv6/CDN edges, but long enough that
// a healthy first address usually wins without extra socket churn.
const happyEyeballsDelay = 75 * time.Millisecond

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
	now := time.Now()
	c.pruneExpiredLocked(now)
	c.entries[host] = dnsEntry{ips: append([]string(nil), ips...), expires: now.Add(dnsCacheTTL)}
	c.trimLocked()
	c.mu.Unlock()
}

func (c *dnsCache) pruneExpired(now time.Time) {
	c.mu.Lock()
	c.pruneExpiredLocked(now)
	c.mu.Unlock()
}

func (c *dnsCache) pruneExpiredLocked(now time.Time) {
	for host, entry := range c.entries {
		if now.After(entry.expires) {
			delete(c.entries, host)
		}
	}
}

func (c *dnsCache) trimLocked() {
	for len(c.entries) > dnsCacheMaxEntries {
		var oldestHost string
		var oldestExpiry time.Time
		first := true
		for host, entry := range c.entries {
			if first || entry.expires.Before(oldestExpiry) {
				oldestHost = host
				oldestExpiry = entry.expires
				first = false
			}
		}
		if oldestHost == "" {
			return
		}
		delete(c.entries, oldestHost)
	}
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
	IP        string        // resolved IP that won the dial, empty for literal/proxy fallbacks
	Attempts  int           // number of candidate addresses attempted
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
		timeout, err := remainingDialTimeout(ctx, timeout)
		if err != nil {
			return nil, err
		}
		tcpStart := time.Now()
		conn, derr := baseDial(network, address, timeout)
		if derr != nil {
			return nil, derr
		}
		return &dialResult{Conn: conn, TCP: time.Since(tcpStart), IP: host, Attempts: 1}, nil
	}
	if ips := cache.get(host); len(ips) > 0 {
		res, derr := dialResolvedIPs(ctx, cache, baseDial, network, host, port, timeout, ips, true, 0)
		if derr != nil {
			// Cached IPs failed; evict so the next call re-resolves.
			cache.forget(host)
			return nil, derr
		}
		return res, nil
	}
	// Cache miss: resolve, then dial. Use one context bounded by `timeout`
	// so DNS and TCP share the same absolute budget.
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	dnsStart := time.Now()
	addrs, lerr := net.DefaultResolver.LookupIPAddr(ctx, host)
	dnsElapsed := time.Since(dnsStart)
	if lerr != nil || len(addrs) == 0 {
		// Fall through to baseDial which will surface the same/similar error.
		timeout, err := remainingDialTimeout(ctx, timeout)
		if err != nil {
			return nil, err
		}
		tcpStart := time.Now()
		conn, derr := baseDial(network, address, timeout)
		if derr != nil {
			return nil, derr
		}
		return &dialResult{Conn: conn, DNS: dnsElapsed, TCP: time.Since(tcpStart), Attempts: 1}, nil
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
	return dialResolvedIPs(ctx, cache, baseDial, network, host, port, timeout, ips, false, dnsElapsed)
}

func remainingDialTimeout(ctx context.Context, fallback time.Duration) (time.Duration, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			if err := ctx.Err(); err != nil {
				return 0, err
			}
			return 0, context.DeadlineExceeded
		}
		if remaining < fallback {
			return remaining, nil
		}
	}
	return fallback, nil
}

func dialResolvedIPs(
	ctx context.Context,
	cache *dnsCache,
	baseDial func(network, address string, timeout time.Duration) (net.Conn, error),
	network, host, port string,
	timeout time.Duration,
	ips []string,
	cached bool,
	dnsElapsed time.Duration,
) (*dialResult, error) {
	dialStart := time.Now()
	deadline := time.Now().Add(timeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	type attemptResult struct {
		conn net.Conn
		ip   string
		err  error
	}
	resultCh := make(chan attemptResult, len(ips))
	launch := func(ip string) bool {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return false
		}
		go func() {
			conn, err := baseDial(network, net.JoinHostPort(ip, port), remaining)
			res := attemptResult{conn: conn, ip: ip, err: err}
			if ctx.Err() != nil {
				if conn != nil {
					_ = conn.Close()
				}
				return
			}
			select {
			case resultCh <- res:
			case <-ctx.Done():
				if conn != nil {
					_ = conn.Close()
				}
			}
		}()
		return true
	}

	var (
		lastErr  error
		attempts int
		active   int
		next     int
	)
	if len(ips) > 0 && launch(ips[0]) {
		attempts++
		active++
		next = 1
	}
	stagger := time.NewTimer(happyEyeballsDelay)
	defer stagger.Stop()
	deadlineTimer := time.NewTimer(time.Until(deadline))
	defer deadlineTimer.Stop()

	resetStagger := func() {
		if !stagger.Stop() {
			select {
			case <-stagger.C:
			default:
			}
		}
		stagger.Reset(happyEyeballsDelay)
	}

	for active > 0 || next < len(ips) {
		select {
		case <-ctx.Done():
			if lastErr != nil {
				return nil, lastErr
			}
			return nil, ctx.Err()
		case <-deadlineTimer.C:
			if lastErr != nil {
				return nil, lastErr
			}
			return nil, &net.OpError{Op: "dial", Net: network, Source: nil, Addr: nil, Err: context.DeadlineExceeded}
		case res := <-resultCh:
			active--
			if res.err == nil {
				cancel()
				cache.rememberSuccess(host, res.ip)
				return &dialResult{
					Conn:      res.conn,
					DNSCached: cached,
					DNS:       dnsElapsed,
					TCP:       time.Since(dialStart),
					IP:        res.ip,
					Attempts:  attempts,
				}, nil
			}
			lastErr = res.err
			if active == 0 && next < len(ips) && launch(ips[next]) {
				attempts++
				active++
				next++
				resetStagger()
			}
		case <-stagger.C:
			if next < len(ips) && launch(ips[next]) {
				attempts++
				active++
				next++
				if next < len(ips) {
					resetStagger()
				}
			}
		}
	}
	if lastErr != nil {
		return nil, lastErr
	}
	tcpStart := time.Now()
	conn, err := baseDial(network, net.JoinHostPort(host, port), timeout)
	if err != nil {
		return nil, err
	}
	return &dialResult{Conn: conn, DNSCached: cached, DNS: dnsElapsed, TCP: time.Since(tcpStart), Attempts: attempts + 1}, nil
}
