// Package bench provides an integration benchmark harness that measures
// end-to-end latency and throughput of the GooseRelayVPN tunnel without
// involving Apps Script. It stands up the exit Server in an httptest.Server,
// configures the carrier with that server's URL via direct relay_urls mode,
// drives traffic through the carrier's SOCKS5 entry point, and measures
// connection setup, time-to-first-byte, and bulk throughput.
//
// Use:
//
//	rig := bench.NewRig(t)
//	defer rig.Close()
//	conn, err := rig.Dial("loopback-target")
//
// The harness is intentionally NOT a *_test.go file so it can be linked into
// both the integration test suite and the benchmark CLI.
package bench

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"time"

	"github.com/kianmhz/GooseRelayVPN/internal/carrier"
	"github.com/kianmhz/GooseRelayVPN/internal/exit"
	"github.com/kianmhz/GooseRelayVPN/internal/session"
	"github.com/kianmhz/GooseRelayVPN/internal/socks"
)

// Rig owns the loopback exit server, in-process carrier client, and SOCKS5
// listener for a single benchmark run.
type Rig struct {
	exitSrv     *httptest.Server
	upstreamLn  net.Listener
	carr        *carrier.Client
	socksLn     net.Listener
	socksAddr   string
	cancelFn    context.CancelFunc
	closed      bool
	mu          sync.Mutex
	upstreamSrv struct {
		ln   net.Listener
		stop chan struct{}
	}
}

// Result records the end-to-end timings for one Run.
type Result struct {
	SetupTime time.Duration // socks5 connect + tunnel SYN round-trip
	TTFB      time.Duration // first byte of upstream response received
	Total     time.Duration // entire transfer
	Bytes     int64
}

// NewRig spins up the harness. Caller must call rig.Close().
func NewRig() (*Rig, error) {
	keyBytes := make([]byte, 32)
	if _, err := rand.Read(keyBytes); err != nil {
		return nil, fmt.Errorf("rng: %w", err)
	}
	keyHex := hex.EncodeToString(keyBytes)

	rig := &Rig{}
	if err := rig.startUpstream(); err != nil {
		return nil, err
	}

	// Build the exit server with no upstream proxy (direct dial). The exit
	// server's HTTP /tunnel handler is bound to an httptest.Server that
	// listens on a random port and returns its URL via Server.URL.
	exitCfg := exit.Config{
		ListenAddr: "127.0.0.1:0",
		AESKeyHex:  keyHex,
	}
	srv, err := exit.New(exitCfg)
	if err != nil {
		rig.Close()
		return nil, fmt.Errorf("exit.New: %w", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/tunnel", srv.ServeTunnel)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	rig.exitSrv = httptest.NewServer(mux)
	srv.StartBackground()

	// Carrier in direct relay_urls mode talking to the loopback exit server.
	carrCfg := carrier.Config{
		ScriptURLs: []string{rig.exitSrv.URL + "/tunnel"},
		AESKeyHex:  keyHex,
		Fronting:   carrier.FrontingConfig{},
	}
	carr, err := carrier.New(carrCfg)
	if err != nil {
		rig.Close()
		return nil, fmt.Errorf("carrier.New: %w", err)
	}
	rig.carr = carr

	ctx, cancel := context.WithCancel(context.Background())
	rig.cancelFn = cancel
	go func() { _ = carr.Run(ctx) }()

	// SOCKS5 entry point on a random localhost port.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		rig.Close()
		return nil, fmt.Errorf("socks listen: %w", err)
	}
	rig.socksLn = ln
	rig.socksAddr = ln.Addr().String()
	go func() {
		_ = socks.ServeListener(ctx, ln, func(target string) *session.Session {
			return carr.NewSession(target)
		})
	}()
	// Allow the carrier loops to settle.
	time.Sleep(50 * time.Millisecond)
	return rig, nil
}

// startUpstream stands up a tiny TCP echo-with-payload server that the
// benchmark client dials through the tunnel. It serves a single response
// of the requested size after reading a 4-byte length-prefix request.
func (r *Rig) startUpstream() error {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("upstream listen: %w", err)
	}
	r.upstreamSrv.ln = ln
	r.upstreamSrv.stop = make(chan struct{})
	r.upstreamLn = ln
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				var hdr [4]byte
				if _, err := io.ReadFull(c, hdr[:]); err != nil {
					return
				}
				size := int(hdr[0])<<24 | int(hdr[1])<<16 | int(hdr[2])<<8 | int(hdr[3])
				if size <= 0 || size > 64*1024*1024 {
					return
				}
				// Send `size` bytes of fixed pattern. Using a single 64KiB
				// chunk reused from the stack keeps allocations negligible.
				chunk := make([]byte, 64*1024)
				for i := range chunk {
					chunk[i] = byte(i)
				}
				remaining := size
				for remaining > 0 {
					n := len(chunk)
					if n > remaining {
						n = remaining
					}
					if _, err := c.Write(chunk[:n]); err != nil {
						return
					}
					remaining -= n
				}
			}(conn)
		}
	}()
	return nil
}

// SOCKSAddr returns the loopback SOCKS5 listener for the rig.
func (r *Rig) SOCKSAddr() string { return r.socksAddr }

// UpstreamAddr returns the loopback upstream server address that the harness
// dials through the tunnel.
func (r *Rig) UpstreamAddr() string { return r.upstreamLn.Addr().String() }

// Run performs one transfer of `size` bytes through the tunnel and records
// SetupTime / TTFB / Total. Reuses the global SOCKS listener for parallelism.
func (r *Rig) Run(size int) (Result, error) {
	startConnect := time.Now()
	conn, err := dialSOCKS(r.socksAddr, r.UpstreamAddr())
	if err != nil {
		return Result{}, err
	}
	defer conn.Close()
	setup := time.Since(startConnect)

	// Send 4-byte size header to upstream echo server.
	hdr := []byte{byte(size >> 24), byte(size >> 16), byte(size >> 8), byte(size)}
	if _, err := conn.Write(hdr); err != nil {
		return Result{}, err
	}
	startRead := time.Now()
	first := make([]byte, 1)
	if _, err := io.ReadFull(conn, first); err != nil {
		return Result{}, err
	}
	ttfb := time.Since(startRead)
	// Read remainder.
	remaining := size - 1
	if remaining > 0 {
		_, err := io.CopyN(io.Discard, conn, int64(remaining))
		if err != nil {
			return Result{}, err
		}
	}
	total := time.Since(startConnect)
	return Result{
		SetupTime: setup,
		TTFB:      ttfb,
		Total:     total,
		Bytes:     int64(size),
	}, nil
}

// dialSOCKS performs a SOCKS5 CONNECT to addr through the proxy at proxyAddr.
// No auth, no DNS-via-proxy (we only support hostname for parity with our
// production dial).
func dialSOCKS(proxyAddr, addr string) (net.Conn, error) {
	c, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		return nil, err
	}
	// Greeting: ver=5, nmethods=1, methods=[0=no-auth]
	if _, err := c.Write([]byte{5, 1, 0}); err != nil {
		c.Close()
		return nil, err
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(c, resp); err != nil {
		c.Close()
		return nil, err
	}
	if resp[0] != 5 || resp[1] != 0 {
		c.Close()
		return nil, fmt.Errorf("socks: greeting refused: %v", resp)
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		c.Close()
		return nil, err
	}
	pInt := 0
	for _, ch := range port {
		pInt = pInt*10 + int(ch-'0')
	}
	// CONNECT (cmd=1) by domain (atyp=3)
	hostBytes := []byte(host)
	req := []byte{5, 1, 0, 3, byte(len(hostBytes))}
	req = append(req, hostBytes...)
	req = append(req, byte(pInt>>8), byte(pInt))
	if _, err := c.Write(req); err != nil {
		c.Close()
		return nil, err
	}
	respHdr := make([]byte, 4)
	if _, err := io.ReadFull(c, respHdr); err != nil {
		c.Close()
		return nil, err
	}
	if respHdr[1] != 0 {
		c.Close()
		return nil, fmt.Errorf("socks: connect failed: %d", respHdr[1])
	}
	// Skip BND.ADDR + BND.PORT
	switch respHdr[3] {
	case 1:
		_, _ = io.CopyN(io.Discard, c, 4+2)
	case 3:
		l := make([]byte, 1)
		_, _ = io.ReadFull(c, l)
		_, _ = io.CopyN(io.Discard, c, int64(l[0])+2)
	case 4:
		_, _ = io.CopyN(io.Discard, c, 16+2)
	}
	return c, nil
}

// Close releases all the harness resources. Idempotent.
func (r *Rig) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return
	}
	r.closed = true
	if r.cancelFn != nil {
		r.cancelFn()
	}
	if r.exitSrv != nil {
		r.exitSrv.Close()
	}
	if r.upstreamLn != nil {
		_ = r.upstreamLn.Close()
	}
	if r.socksLn != nil {
		_ = r.socksLn.Close()
	}
	// Give goroutines a brief grace period to exit cleanly.
	time.Sleep(20 * time.Millisecond)
}

// init configures harness logging so benchmark output is timestamped at
// microsecond resolution — the nanosecond noise of the underlying components
// (carrier poll cycles, SOCKS handshakes) needs sub-millisecond timestamps
// to be readable.
func init() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
}
