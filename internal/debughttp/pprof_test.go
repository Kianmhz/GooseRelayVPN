package debughttp

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewPprofMuxServesIndex(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/debug/pprof/", nil)
	rec := httptest.NewRecorder()
	NewPprofMux().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("pprof index status = %d, want 200", rec.Code)
	}
}

func TestIsLoopbackAddr(t *testing.T) {
	for _, addr := range []string{"127.0.0.1:6060", "localhost:6060", "[::1]:6060"} {
		if !isLoopbackAddr(addr) {
			t.Fatalf("isLoopbackAddr(%q) = false, want true", addr)
		}
	}
}

func TestIsLoopbackAddrRejectsPublicBinds(t *testing.T) {
	for _, addr := range []string{":6060", "0.0.0.0:6060", "[::]:6060", "192.0.2.10:6060", "example.com:6060"} {
		if isLoopbackAddr(addr) {
			t.Fatalf("isLoopbackAddr(%q) = true, want false", addr)
		}
	}
}
