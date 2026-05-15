package exit

import (
	"errors"
	"net"
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
