// Package exit implements the VPS-side HTTP handler. Apps Script POSTs
// AES-encrypted frame batches here; we decrypt, demux by session_id, dial real
// upstream targets on SYN, pump bytes between net.Conn and session, and
// long-poll the response so downstream bytes get delivered with low latency.
package exit

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/kianmhz/GooseRelayVPN/internal/frame"
	"github.com/kianmhz/GooseRelayVPN/internal/session"
	"golang.org/x/net/proxy"
)

const (
	// maxRequestBodyBytes is the hard cap on /tunnel POST body size. Apps Script
	// itself caps at ~50MB; this matches that with margin so a malicious or
	// buggy client cannot OOM the server with a single request.
	maxRequestBodyBytes = 50 * 1024 * 1024

	// dialFailureGCInterval is how often the recordDialFailure GC sweeps
	// expired entries so a long-running server with many distinct failed
	// hostnames does not slowly leak memory.
	dialFailureGCInterval = 60 * time.Second

	// httpReadHeaderTimeout caps HTTP request *header* read time. Without
	// this a slowloris attacker can hold connections open writing one byte
	// every minute forever.
	httpReadHeaderTimeout = 15 * time.Second

	// httpIdleTimeout closes idle keepalive HTTP/1.1 connections. The
	// long-poll relay only needs one in-flight request at a time per client;
	// 90s is generous and matches Go's transport default.
	httpIdleTimeout = 90 * time.Second

	// gracefulShutdownTimeout bounds how long we wait for in-flight long-poll
	// requests to drain on SIGTERM before forcing connection close.
	gracefulShutdownTimeout = LongPollWindow + 5*time.Second

	// ActiveDrainWindow caps how long a batch that just performed real work
	// (SYN/connect or non-empty uplink data) waits for downstream bytes.
	// Kept short so the client's single poll loop can quickly cycle back
	// and send SYN frames for other sessions that queued up while this poll
	// was in-flight. A long value here (e.g. 2s) causes head-of-line
	// blocking: when YouTube opens 4-6 parallel connections, later SYNs
	// are delayed by ActiveDrainWindow × (position in queue), easily
	// pushing total setup time past the player's ~7s abort threshold.
	ActiveDrainWindow = 350 * time.Millisecond

	// LongPollWindow is how long the handler holds open a request waiting for
	// downstream bytes. UrlFetchApp has a practical read timeout of ~10s, so
	// keep this comfortably below that.
	LongPollWindow = 8 * time.Second

	// MaxFramePayload caps the bytes per downstream frame (matches carrier).
	// Raised from 128KB: single-seal means no per-frame crypto cost, so fewer
	// larger frames are strictly better (less length-prefix overhead, fewer
	// Unmarshal calls). Must match the value in internal/carrier/client.go.
	MaxFramePayload = 256 * 1024

	// upstreamReadBuf is the chunk size for reading from real net.Conn before
	// pushing to session.EnqueueTx (which then chunks into frames).
	upstreamReadBuf = 128 * 1024

	// coalesceWindow lets us gather a few more frames before responding, which
	// improves throughput for video streams under higher RTT links.
	coalesceWindow = 25 * time.Millisecond

	// coalesceMinFrames is the minimum number of frames in a drain before we
	// bother waiting coalesceWindow. Batches at or below this threshold are
	// almost certainly interactive (TLS handshake, HTTP control frames) and
	// adding 25ms per hop compounds visibly across round-trips.
	coalesceMinFrames = 4

	// maxDrainFramesPerSession keeps one hot session from dominating an entire
	// response batch when many interactive sessions are active concurrently.
	maxDrainFramesPerSession = 8

	// maxDrainFramesPerBatch bounds total frames emitted in one HTTP response so
	// one poll does not become a very large base64 body under high concurrency.
	maxDrainFramesPerBatch = 48

	// Under high fan-out (mobile apps opening many parallel connections), allow
	// a larger but still bounded batch to reduce queueing delay.
	busySessionThreshold       = 24
	maxDrainFramesPerBatchBusy = 144

	// dialFailureBackoff is how long we suppress repeated SYN dial attempts to a
	// target after a structural network/DNS failure.
	dialFailureBackoff = 2 * time.Second

	// idleSessionTimeout caps how long a session can go without any client-side
	// frame before we declare it orphaned and force-close the upstream.
	// Triggered by ungraceful client disconnects (Ctrl+C, OOM kill, sleep/wake,
	// network drop): without this the upstream goroutines and TCP connections
	// stay alive indefinitely for any persistent target (Telegram, websockets,
	// etc.), and the server slowly grinds to a halt over multiple disconnect
	// cycles. 10 minutes is long enough to tolerate quiet streaming sessions
	// (large download with no client→server traffic) without false-positives.
	idleSessionTimeout = 10 * time.Minute

	// idleGCInterval is how often the cleanup loop scans for orphaned sessions.
	idleGCInterval = 60 * time.Second
)

// Config is the VPS server's configuration.
type Config struct {
	ListenAddr    string // "0.0.0.0:8443"
	AESKeyHex     string // 64-char hex
	DebugTiming   bool   // when true, log per-session dial breakdown and first-read latency
	UpstreamProxy string // optional "host:port" of a local SOCKS5 proxy (e.g. WARP on 127.0.0.1:40000)
}

// Server holds the per-process session state.
type Server struct {
	cfg          Config
	aead         *frame.Crypto
	dial         func(network, address string, timeout time.Duration) (net.Conn, error)
	dns          *dnsCache
	debugTiming  bool

	mu           sync.Mutex
	sessions     map[[frame.SessionIDLen]byte]*session.Session
	txReady      map[[frame.SessionIDLen]byte]struct{} // sessions with pending TX frames
	firstReply   map[[frame.SessionIDLen]byte]struct{} // sessions whose first downstream batch hasn't been sent yet
	upstreams    map[[frame.SessionIDLen]byte]net.Conn // upstream conn per session, kept so GC can force-close
	lastActivity map[[frame.SessionIDLen]byte]time.Time // last time the client sent a frame for this session
	dialFail     map[string]time.Time
	pendingRSTs  []*frame.Frame // RST frames to send back on the next response

	activity chan struct{} // buffered len 1; coalesces "session has new tx" signals
	stats    serverStats

	// httpSrv is captured so a SIGTERM/SIGINT handler can call Shutdown(ctx)
	// for graceful drain instead of dropping all in-flight long-polls.
	httpSrv *http.Server

	// cancelBg cancels the StartBackground-launched maintenance goroutines.
	cancelBg context.CancelFunc

	// upstreamReadPool is a sync.Pool of 128KiB read buffers reused across
	// upstream pump goroutines. Per-session goroutines previously allocated
	// a fresh 128KiB buffer on every openSession; the pool eliminates that.
	upstreamReadPool sync.Pool
}

// serverStats holds atomic counters surfaced periodically by runStatsLoop.
type serverStats struct {
	requests       atomic.Uint64
	framesIn       atomic.Uint64
	framesOut      atomic.Uint64
	bytesIn        atomic.Uint64
	bytesOut       atomic.Uint64
	sessionsOpen   atomic.Uint64
	sessionsClose  atomic.Uint64
	dialsOK        atomic.Uint64
	dialsFail      atomic.Uint64
	rstSent        atomic.Uint64
	decodeFailures atomic.Uint64
}

// New constructs an exit Server.
func New(cfg Config) (*Server, error) {
	aead, err := frame.NewCryptoFromHexKey(cfg.AESKeyHex)
	if err != nil {
		return nil, err
	}
	dialFn := dialFunc(cfg.UpstreamProxy)
	s := &Server{
		cfg:          cfg,
		aead:         aead,
		dial:         dialFn,
		dns:          newDNSCache(),
		debugTiming:  cfg.DebugTiming,
		sessions:     make(map[[frame.SessionIDLen]byte]*session.Session),
		txReady:      make(map[[frame.SessionIDLen]byte]struct{}),
		firstReply:   make(map[[frame.SessionIDLen]byte]struct{}),
		upstreams:    make(map[[frame.SessionIDLen]byte]net.Conn),
		lastActivity: make(map[[frame.SessionIDLen]byte]time.Time),
		dialFail:     make(map[string]time.Time),
		activity:     make(chan struct{}, 1),
	}
	s.upstreamReadPool.New = func() interface{} {
		buf := make([]byte, upstreamReadBuf)
		return &buf
	}
	return s, nil
}

// dialFunc returns a dial function. When proxyAddr is non-empty it routes all
// outbound connections through the SOCKS5 proxy at that address; otherwise it
// falls back to net.DialTimeout.
func dialFunc(proxyAddr string) func(network, address string, timeout time.Duration) (net.Conn, error) {
	if proxyAddr == "" {
		return net.DialTimeout
	}
	forward := &net.Dialer{Timeout: 15 * time.Second}
	d, err := proxy.SOCKS5("tcp", proxyAddr, nil, forward)
	if err != nil {
		// proxy.SOCKS5 only errors on bad auth config; with nil auth this never fires.
		log.Printf("[exit] upstream_proxy: failed to build SOCKS5 dialer: %v — falling back to direct", err)
		return net.DialTimeout
	}
	cd, ok := d.(proxy.ContextDialer)
	if !ok {
		return func(_, address string, _ time.Duration) (net.Conn, error) {
			return d.Dial("tcp", address)
		}
	}
	return func(_, address string, timeout time.Duration) (net.Conn, error) {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		return cd.DialContext(ctx, "tcp", address)
	}
}

// ServeTunnel exposes the /tunnel handler so callers (e.g. integration test
// harnesses or alternative front-ends) can mount it on their own mux.
func (s *Server) ServeTunnel(w http.ResponseWriter, r *http.Request) { s.handleTunnel(w, r) }

// StartBackground starts the long-running maintenance goroutines (idle GC,
// stats loop, dialFail GC). It is intended for embed-style use where the
// caller drives an http.Server itself instead of calling ListenAndServe.
// Safe to call once per Server.
func (s *Server) StartBackground() {
	bgCtx, cancel := context.WithCancel(context.Background())
	s.cancelBg = cancel
	go s.runStatsLoop(bgCtx)
	go s.runIdleGCLoop(bgCtx)
	go s.runDialFailGCLoop(bgCtx)
}

// ListenAndServe blocks. It binds an HTTP listener on cfg.ListenAddr with one
// route, POST /tunnel, that handles batched encrypted frames. Listens for
// SIGINT/SIGTERM and triggers graceful shutdown so in-flight long-polls drain.
func (s *Server) ListenAndServe() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/tunnel", s.handleTunnel)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	metricsHandler := s.metricsHandler()
	if metricsHandler != nil {
		mux.Handle("/metrics", metricsHandler)
	}

	httpSrv := &http.Server{
		Addr:              s.cfg.ListenAddr,
		Handler:           mux,
		ReadHeaderTimeout: httpReadHeaderTimeout,
		ReadTimeout:       30 * time.Second,
		// WriteTimeout intentionally generous — long-poll responses can take
		// up to LongPollWindow to start writing.
		WriteTimeout: LongPollWindow + 10*time.Second,
		IdleTimeout:  httpIdleTimeout,
	}
	s.httpSrv = httpSrv

	// Background loops that share the lifetime of the HTTP server.
	bgCtx, cancelBg := context.WithCancel(context.Background())
	defer cancelBg()
	go s.runStatsLoop(bgCtx)
	go s.runIdleGCLoop(bgCtx)
	go s.runDialFailGCLoop(bgCtx)

	// Graceful shutdown on SIGINT / SIGTERM.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig, ok := <-sigCh
		if !ok {
			return
		}
		log.Printf("[exit] received %s — beginning graceful shutdown (≤%s for in-flight long-polls)", sig, gracefulShutdownTimeout)
		shutdownCtx, cancel := context.WithTimeout(context.Background(), gracefulShutdownTimeout)
		defer cancel()
		if err := httpSrv.Shutdown(shutdownCtx); err != nil {
			log.Printf("[exit] graceful shutdown error: %v", err)
		}
		cancelBg()
	}()

	log.Printf("[exit] listening on %s", s.cfg.ListenAddr)
	err := httpSrv.ListenAndServe()
	signal.Stop(sigCh)
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

// runDialFailGCLoop sweeps expired dialFail entries periodically. Without
// this the map grows indefinitely on long-running servers that see many
// distinct failed hostnames (typo'd targets, blocked-by-region domains, etc).
func (s *Server) runDialFailGCLoop(ctx context.Context) {
	t := time.NewTicker(dialFailureGCInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			now := time.Now()
			s.mu.Lock()
			for target, until := range s.dialFail {
				if now.After(until) {
					delete(s.dialFail, target)
				}
			}
			s.mu.Unlock()
		}
	}
}

func (s *Server) handleTunnel(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	s.stats.requests.Add(1)
	// MaxBytesReader caps body reads — without this a misbehaving (or
	// malicious) client could OOM the process with a 10 GiB POST.
	limited := http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
	defer limited.Close()
	body, err := io.ReadAll(limited)
	if err != nil {
		log.Printf("[exit] read body: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	rxFrames, err := frame.DecodeBatch(s.aead, body)
	if err != nil {
		s.stats.decodeFailures.Add(1)
		// Decode failure on the very first batch from a client almost always
		// means the AES key on the client does not match this server's key.
		log.Printf("[exit] decode batch failed: %v (likely tunnel_key mismatch — confirm client config matches this server's tunnel_key)", err)
		w.WriteHeader(http.StatusNoContent)
		return
	}

	if len(rxFrames) > 0 {
		var bytesIn uint64
		for _, f := range rxFrames {
			bytesIn += uint64(len(f.Payload))
		}
		s.stats.framesIn.Add(uint64(len(rxFrames)))
		s.stats.bytesIn.Add(bytesIn)
	}

	for _, f := range rxFrames {
		s.routeIncoming(f)
	}

	// Active batches use a shorter wait to avoid stalling unrelated sessions,
	// while empty polls keep long-poll behavior for push responsiveness.
	deadline := time.Now().Add(s.drainWindow(rxFrames))
	for {
		txFrames, urgent := s.drainAll()
		if len(txFrames) > 0 {
			// Skip coalesce when the batch is already saturated (frames at the
			// per-batch cap or aggregate payload is large enough that another
			// 25 ms only adds latency without meaningfully more bulk).
			batchCap := maxDrainFramesPerBatch
			s.mu.Lock()
			if len(s.sessions) >= busySessionThreshold {
				batchCap = maxDrainFramesPerBatchBusy
			}
			s.mu.Unlock()
			var totalBytes int
			for _, f := range txFrames {
				totalBytes += len(f.Payload)
			}
			saturated := len(txFrames) >= batchCap || totalBytes >= 1024*1024
			// Coalesce bursts into one response to reduce per-request overhead,
			// but only when the batch is large enough to be bulk/video traffic.
			// Small batches (≤ coalesceMinFrames) are interactive; adding a
			// 25ms wait there compounds latency across every TLS round-trip.
			// Urgent batches (RSTs, first downstream after SYN) skip coalesce
			// unconditionally so connection setup is not delayed.
			if !urgent && !saturated && len(txFrames) > coalesceMinFrames {
				coalesceDeadline := time.Now().Add(coalesceWindow)
			coalesceLoop:
				for {
					if time.Now().After(coalesceDeadline) {
						break coalesceLoop
					}
					remainingCoalesce := time.Until(coalesceDeadline)
					select {
					case <-r.Context().Done():
						return
					case <-s.activity:
						more, _ := s.drainAll()
						txFrames = append(txFrames, more...)
					case <-time.After(remainingCoalesce):
						break coalesceLoop
					}
				}
			}

			respBody, err := frame.EncodeBatch(s.aead, txFrames)
			if err != nil {
				log.Printf("[exit] encode response: %v", err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			var bytesOut uint64
			for _, f := range txFrames {
				bytesOut += uint64(len(f.Payload))
			}
			s.stats.framesOut.Add(uint64(len(txFrames)))
			s.stats.bytesOut.Add(bytesOut)
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write(respBody)
			s.gcDoneSessions()
			return
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			// Empty response (still a valid base64-encoded zero-frame batch).
			respBody, _ := frame.EncodeBatch(s.aead, nil)
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write(respBody)
			return
		}
		select {
		case <-r.Context().Done():
			return
		case <-s.activity:
			// loop and drain
		case <-time.After(remaining):
			// loop one more time, then exit on next iteration
		}
	}
}

func (s *Server) drainWindow(rxFrames []*frame.Frame) time.Duration {
	for _, f := range rxFrames {
		if f.HasFlag(frame.FlagSYN) || len(f.Payload) > 0 {
			return ActiveDrainWindow
		}
	}
	return LongPollWindow
}

// queuePendingRST appends an RST for sid only if one is not already queued.
// Without dedup, a client running with stale session state would generate one
// RST per stray frame, all targeting the same dead session — pure bloat.
func (s *Server) queuePendingRST(sid [frame.SessionIDLen]byte) {
	s.mu.Lock()
	for _, r := range s.pendingRSTs {
		if r.SessionID == sid {
			s.mu.Unlock()
			return
		}
	}
	s.pendingRSTs = append(s.pendingRSTs, &frame.Frame{SessionID: sid, Flags: frame.FlagRST})
	s.mu.Unlock()
	s.stats.rstSent.Add(1)
	s.kick()
}

// routeIncoming routes one incoming frame to its session, creating the session
// (and dialing upstream) if this is a SYN.
func (s *Server) routeIncoming(f *frame.Frame) {
	s.mu.Lock()
	sess, exists := s.sessions[f.SessionID]
	s.mu.Unlock()

	if !exists {
		if !f.HasFlag(frame.FlagSYN) {
			log.Printf("[exit] frame for unknown session (no SYN), sending RST")
			s.queuePendingRST(f.SessionID)
			return
		}
		if s.isDialSuppressed(f.Target) {
			s.queuePendingRST(f.SessionID)
			return
		}
		var err error
		sess, err = s.openSession(f.SessionID, f.Target)
		if err != nil {
			s.recordDialFailure(f.Target, err)
			s.stats.dialsFail.Add(1)
			log.Printf("[exit] dial %s: %v", f.Target, err)
			return
		}
		s.stats.dialsOK.Add(1)
		s.clearDialFailure(f.Target)
	}
	if !sess.ProcessRx(f) {
		// Per-session inbox/queue exceeded its memory cap. Force-close so we
		// don't keep adding frames the slow consumer can't drain.
		log.Printf("[exit] session %x rx-overflow, RST'ing", f.SessionID[:4])
		s.tearDownSession(f.SessionID)
		s.queuePendingRST(f.SessionID)
		return
	}
	// Touch activity AFTER ProcessRx so a successful client→server frame
	// resets the idle timer for this session.
	s.mu.Lock()
	if _, stillExists := s.sessions[f.SessionID]; stillExists {
		s.lastActivity[f.SessionID] = time.Now()
	}
	s.mu.Unlock()
}

// tearDownSession force-closes the session for sid (used on rx-overflow RST).
func (s *Server) tearDownSession(sid [frame.SessionIDLen]byte) {
	s.mu.Lock()
	sess := s.sessions[sid]
	upstream := s.upstreams[sid]
	delete(s.sessions, sid)
	delete(s.txReady, sid)
	delete(s.firstReply, sid)
	delete(s.upstreams, sid)
	delete(s.lastActivity, sid)
	s.mu.Unlock()
	if upstream != nil {
		_ = upstream.Close()
	}
	if sess != nil {
		sess.CloseRx()
		sess.Stop()
	}
	s.stats.sessionsClose.Add(1)
}

// openSession dials the upstream target, creates a Session for the given ID,
// registers it, and spawns the bidirectional pump goroutines.
func (s *Server) openSession(id [frame.SessionIDLen]byte, target string) (*session.Session, error) {
	var upstream net.Conn
	var res *dialResult
	if s.cfg.UpstreamProxy != "" {
		// Let the SOCKS5 proxy handle DNS so the target hostname is resolved
		// on the proxy side (e.g. through WARP), not locally on the VPS.
		conn, err := s.dial("tcp", target, 15*time.Second)
		if err != nil {
			return nil, err
		}
		upstream = conn
	} else {
		var err error
		res, err = dialWithDNSCache(s.dns, s.dial, "tcp", target, 15*time.Second)
		if err != nil {
			return nil, err
		}
		upstream = res.Conn
	}
	// Disable Nagle's algorithm so small writes (TLS handshake records, HTTP
	// request lines) hit the wire immediately instead of waiting up to 40 ms
	// to coalesce. Interactive workloads dominate this tunnel; throughput-bound
	// flows already buffer at the kernel level.
	if tcpConn, ok := upstream.(*net.TCPConn); ok {
		_ = tcpConn.SetNoDelay(true)
	}
	if s.debugTiming {
		if res != nil {
			log.Printf("[timing] %x dial dns=%dms cached=%v tcp=%dms target=%s",
				id[:4], res.DNS.Milliseconds(), res.DNSCached, res.TCP.Milliseconds(), target)
		} else {
			log.Printf("[timing] %x dial via proxy target=%s", id[:4], target)
		}
	}
	dialedAt := time.Now()
	sess := session.New(id, target, false)
	sess.SetOnTx(func() {
		s.mu.Lock()
		s.txReady[id] = struct{}{}
		s.mu.Unlock()
		s.kick()
	})

	s.mu.Lock()
	s.sessions[id] = sess
	s.upstreams[id] = upstream
	s.firstReply[id] = struct{}{}
	s.lastActivity[id] = time.Now()
	s.mu.Unlock()
	s.stats.sessionsOpen.Add(1)

	log.Printf("[exit] new session %x -> %s", id[:4], target)

	// Upstream → session.EnqueueTx (downstream direction).
	go func() {
		defer upstream.Close()
		bufP := s.upstreamReadPool.Get().(*[]byte)
		buf := *bufP
		defer func() {
			// Zero the pointer so we don't accidentally hold a reference;
			// the pool returns the slice header so future Reads get a fresh
			// 128KiB buffer view but back the same allocation.
			s.upstreamReadPool.Put(bufP)
		}()
		firstRead := true
		for {
			n, err := upstream.Read(buf)
			if firstRead && n > 0 {
				if s.debugTiming {
					log.Printf("[timing] %x first_read=%dms after_dial target=%s",
						id[:4], time.Since(dialedAt).Milliseconds(), target)
				}
				firstRead = false
			}
			if n > 0 {
				sess.EnqueueTx(buf[:n])
			}
			if err != nil {
				if err != io.EOF {
					log.Printf("[exit] upstream read %x: %v", id[:4], err)
				}
				sess.RequestClose()
				return
			}
		}
	}()

	// session.RxChan → upstream.Write (upstream direction).
	go func() {
		for data := range sess.RxChan {
			if _, err := upstream.Write(data); err != nil {
				log.Printf("[exit] upstream write %x: %v", id[:4], err)
				_ = upstream.Close()
				return
			}
		}
		_ = upstream.Close()
	}()

	return sess, nil
}

// drainAll returns all currently-buffered TX frames plus an `urgent` flag
// signalling that at least one drained session is delivering its first
// downstream batch (e.g. TLS server hello after SYN). The caller skips the
// normal coalesce wait when urgent is set so connection setup isn't delayed
// by 25 ms on every new TLS handshake.
func (s *Server) drainAll() ([]*frame.Frame, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*frame.Frame
	var urgent bool
	if len(s.pendingRSTs) > 0 {
		out = append(out, s.pendingRSTs...)
		s.pendingRSTs = s.pendingRSTs[:0]
		urgent = true // RSTs are always urgent — client should know immediately
	}
	batchCap := maxDrainFramesPerBatch
	if len(s.sessions) >= busySessionThreshold {
		batchCap = maxDrainFramesPerBatchBusy
	}
	remaining := batchCap
	for id := range s.txReady {
		if remaining <= 0 {
			break
		}
		sess, ok := s.sessions[id]
		if !ok {
			delete(s.txReady, id)
			continue
		}
		perSessionCap := maxDrainFramesPerSession
		if remaining < perSessionCap {
			perSessionCap = remaining
		}
		frames := sess.DrainTxLimited(MaxFramePayload, perSessionCap)
		delete(s.txReady, id) // OnTx re-adds if more data arrives
		if len(frames) > 0 {
			if _, isFirst := s.firstReply[id]; isFirst {
				urgent = true
				delete(s.firstReply, id)
			}
		}
		out = append(out, frames...)
		remaining -= len(frames)
	}
	return out, urgent
}

func (s *Server) gcDoneSessions() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, sess := range s.sessions {
		if sess.IsDone() {
			sess.Stop()
			delete(s.sessions, id)
			delete(s.txReady, id)
			delete(s.firstReply, id)
			delete(s.upstreams, id)
			delete(s.lastActivity, id)
			s.stats.sessionsClose.Add(1)
		}
	}
}

// gcIdleSessions force-closes sessions that haven't seen any client-side
// activity (incoming frame) for longer than idleSessionTimeout. This is the
// safety net for ungraceful client disconnects: when the client is killed
// without sending FIN/RST per session, the upstream goroutines and TCP
// connections to long-lived targets (Telegram, websockets, etc.) would
// otherwise leak forever.
func (s *Server) gcIdleSessions() {
	threshold := time.Now().Add(-idleSessionTimeout)

	type victim struct {
		id       [frame.SessionIDLen]byte
		sess     *session.Session
		upstream net.Conn
		target   string
		idleFor  time.Duration
	}
	var victims []victim

	s.mu.Lock()
	for id, last := range s.lastActivity {
		if last.After(threshold) {
			continue
		}
		sess, ok := s.sessions[id]
		if !ok {
			delete(s.lastActivity, id)
			continue
		}
		victims = append(victims, victim{
			id:       id,
			sess:     sess,
			upstream: s.upstreams[id],
			target:   sess.Target,
			idleFor:  time.Since(last),
		})
		delete(s.sessions, id)
		delete(s.txReady, id)
		delete(s.firstReply, id)
		delete(s.upstreams, id)
		delete(s.lastActivity, id)
	}
	s.mu.Unlock()

	for _, v := range victims {
		log.Printf("[exit] GC orphaned session %x (target=%s, idle for %s)",
			v.id[:4], v.target, v.idleFor.Round(time.Second))
		// Closing upstream causes the read goroutine in openSession to error
		// and exit, which triggers the write goroutine to exit too via the
		// session.RxChan close path. CloseRx + Stop are both idempotent.
		if v.upstream != nil {
			_ = v.upstream.Close()
		}
		if v.sess != nil {
			v.sess.CloseRx()
			v.sess.Stop()
		}
		s.stats.sessionsClose.Add(1)
	}
}

// runIdleGCLoop periodically scans for orphaned sessions and force-closes
// them. Returns when ctx is canceled.
func (s *Server) runIdleGCLoop(ctx context.Context) {
	t := time.NewTicker(idleGCInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.gcIdleSessions()
		}
	}
}

func (s *Server) kick() {
	select {
	case s.activity <- struct{}{}:
	default:
	}
}

func (s *Server) isDialSuppressed(target string) bool {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	until, ok := s.dialFail[target]
	if !ok {
		return false
	}
	if now.After(until) {
		delete(s.dialFail, target)
		return false
	}
	return true
}

func (s *Server) recordDialFailure(target string, err error) {
	if !isBackoffEligibleDialErr(err) {
		return
	}
	s.mu.Lock()
	s.dialFail[target] = time.Now().Add(dialFailureBackoff)
	s.mu.Unlock()
}

func (s *Server) clearDialFailure(target string) {
	s.mu.Lock()
	delete(s.dialFail, target)
	s.mu.Unlock()
}

func isBackoffEligibleDialErr(err error) bool {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
		return true
	}
	var opErr *net.OpError
	if !errors.As(err, &opErr) {
		return false
	}
	if opErr.Timeout() {
		return true
	}
	var errno syscall.Errno
	if !errors.As(opErr, &errno) {
		return false
	}
	switch errno {
	case syscall.ECONNREFUSED,
		syscall.EHOSTUNREACH,
		syscall.ENETUNREACH,
		syscall.ENETDOWN,
		syscall.EADDRNOTAVAIL,
		syscall.ETIMEDOUT:
		return true
	default:
		return false
	}
}
