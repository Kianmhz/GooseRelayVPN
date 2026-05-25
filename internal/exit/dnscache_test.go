package exit

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

func TestDialWithDNSCacheTriesCachedAddressesUntilOneWorks(t *testing.T) {
	cache := newDNSCache()
	cache.set("example.test", []string{"192.0.2.10", "192.0.2.20"})

	var dialed []string
	baseDial := func(network, address string, timeout time.Duration) (net.Conn, error) {
		dialed = append(dialed, address)
		if address == "192.0.2.10:443" {
			return nil, errors.New("first address down")
		}
		a, b := net.Pipe()
		t.Cleanup(func() {
			_ = a.Close()
			_ = b.Close()
		})
		return a, nil
	}

	res, err := dialWithDNSCache(cache, baseDial, "tcp", "example.test:443", time.Second)
	if err != nil {
		t.Fatalf("dialWithDNSCache: %v", err)
	}
	if !res.DNSCached {
		t.Fatal("expected cached DNS result")
	}
	if got, want := len(dialed), 2; got != want {
		t.Fatalf("dial attempts = %d, want %d (%v)", got, want, dialed)
	}
	if dialed[0] != "192.0.2.10:443" || dialed[1] != "192.0.2.20:443" {
		t.Fatalf("dial order = %v", dialed)
	}

	ips := cache.get("example.test")
	if len(ips) == 0 || ips[0] != "192.0.2.20" {
		t.Fatalf("successful IP was not promoted in cache: %v", ips)
	}
}

func TestDialWithDNSCacheContextUsesAbsoluteDeadlineForCachedDial(t *testing.T) {
	cache := newDNSCache()
	cache.set("example.test", []string{"192.0.2.10"})

	var gotTimeout time.Duration
	baseDial := func(network, address string, timeout time.Duration) (net.Conn, error) {
		gotTimeout = timeout
		return nil, context.DeadlineExceeded
	}

	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	_, err := dialWithDNSCacheContext(ctx, cache, baseDial, "tcp", "example.test:443", time.Second)
	if err == nil {
		t.Fatal("dialWithDNSCacheContext succeeded, want timeout")
	}
	if gotTimeout <= 0 || gotTimeout > 100*time.Millisecond {
		t.Fatalf("baseDial timeout = %v, want bounded by caller context instead of full 1s fallback", gotTimeout)
	}
}

func TestDialWithDNSCacheRacesSlowFirstAddress(t *testing.T) {
	cache := newDNSCache()
	cache.set("example.test", []string{"192.0.2.10", "192.0.2.20"})

	var dialed []string
	var mu sync.Mutex
	baseDial := func(network, address string, timeout time.Duration) (net.Conn, error) {
		mu.Lock()
		dialed = append(dialed, address)
		mu.Unlock()
		if address == "192.0.2.10:443" {
			time.Sleep(500 * time.Millisecond)
			return nil, errors.New("first address slow and down")
		}
		a, b := net.Pipe()
		t.Cleanup(func() {
			_ = a.Close()
			_ = b.Close()
		})
		return a, nil
	}

	start := time.Now()
	res, err := dialWithDNSCache(cache, baseDial, "tcp", "example.test:443", time.Second)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("dialWithDNSCache: %v", err)
	}
	if !res.DNSCached {
		t.Fatal("expected cached DNS result")
	}
	if elapsed > 300*time.Millisecond {
		t.Fatalf("dial took %v; want slow first address raced by faster alternate", elapsed)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(dialed) < 2 {
		t.Fatalf("dial attempts = %d, want both candidates attempted (%v)", len(dialed), dialed)
	}
}

func TestDNSCachePrunesExpiredEntriesOnSet(t *testing.T) {
	cache := newDNSCache()
	cache.entries["expired.test"] = dnsEntry{
		ips:     []string{"192.0.2.1"},
		expires: time.Now().Add(-time.Second),
	}

	cache.set("fresh.test", []string{"192.0.2.2"})

	cache.mu.Lock()
	_, expiredPresent := cache.entries["expired.test"]
	_, freshPresent := cache.entries["fresh.test"]
	cache.mu.Unlock()
	if expiredPresent {
		t.Fatal("expired DNS cache entry survived set-time prune")
	}
	if !freshPresent {
		t.Fatal("fresh DNS cache entry missing")
	}
}

func TestDNSCacheTrimsToMaxEntries(t *testing.T) {
	cache := newDNSCache()
	for i := 0; i < dnsCacheMaxEntries+8; i++ {
		cache.set(string(rune('a'+(i%26)))+time.Duration(i).String()+".test", []string{"192.0.2.1"})
	}

	cache.mu.Lock()
	got := len(cache.entries)
	cache.mu.Unlock()
	if got > dnsCacheMaxEntries {
		t.Fatalf("dns cache entries = %d, want <= %d", got, dnsCacheMaxEntries)
	}
}
