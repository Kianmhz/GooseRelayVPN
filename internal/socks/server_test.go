package socks

import "testing"

func TestListenNetworkChoosesIPv4ForIPv4BindAddresses(t *testing.T) {
	for _, addr := range []string{"127.0.0.1:1080", "0.0.0.0:1080"} {
		if got := listenNetwork(addr); got != "tcp4" {
			t.Fatalf("listenNetwork(%q) = %q, want tcp4", addr, got)
		}
	}
}

func TestListenNetworkChoosesIPv6ForIPv6BindAddresses(t *testing.T) {
	for _, addr := range []string{"[::1]:1080", "[::]:1080"} {
		if got := listenNetwork(addr); got != "tcp6" {
			t.Fatalf("listenNetwork(%q) = %q, want tcp6", addr, got)
		}
	}
}

func TestListenNetworkKeepsHostnamesDualStack(t *testing.T) {
	if got := listenNetwork("localhost:1080"); got != "tcp" {
		t.Fatalf("listenNetwork(localhost) = %q, want tcp", got)
	}
}
