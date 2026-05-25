package debughttp

import (
	"log"
	"net"
	"net/http"
	"net/http/pprof"
	"strings"
)

// NewPprofMux returns a private pprof mux. We avoid importing net/http/pprof
// for its default-mux side effects so enabling diagnostics never changes the
// application's public handlers.
func NewPprofMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	return mux
}

// StartPprof starts a best-effort pprof HTTP listener when addr is non-empty.
// The listener is intentionally opt-in; callers should prefer localhost
// addresses such as 127.0.0.1:6060 on shared machines.
func StartPprof(addr, component string) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return
	}
	if !isLoopbackAddr(addr) {
		log.Printf("[%s] refusing to expose unauthenticated debug pprof on non-loopback address %q", component, addr)
		return
	}
	go func() {
		log.Printf("[%s] debug pprof listening on http://%s/debug/pprof/", component, addr)
		if err := http.ListenAndServe(addr, NewPprofMux()); err != nil {
			log.Printf("[%s] debug pprof stopped: %v", component, err)
		}
	}()
}

func isLoopbackAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	host = strings.TrimSpace(host)
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
