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
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/kianmhz/GooseRelayVPN/internal/frame"
	"github.com/kianmhz/GooseRelayVPN/internal/session"
)

const (
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
)

// Config is the VPS server's configuration.
type Config struct {
	ListenAddr   string // "0.0.0.0:8443"
	AESKeyHex    string // 64-char hex
	DebugTiming  bool   // when true, log per-session dial breakdown and first-read latency
}

// Server holds the per-process session state.
type Server struct {
	cfg          Config
	aead         *frame.Crypto
	dial         func(network, address string, timeout time.Duration) (net.Conn, error)
	dns          *dnsCache
	debugTiming  bool

	mu          sync.Mutex
	sessions    map[[frame.SessionIDLen]byte]*session.Session
	txReady     map[[frame.SessionIDLen]byte]struct{} // sessions with pending TX frames
	firstReply  map[[frame.SessionIDLen]byte]struct{} // sessions whose first downstream batch hasn't been sent yet
	dialFail    map[string]time.Time
	pendingRSTs []*frame.Frame // RST frames to send back on the next response

	activity chan struct{} // buffered len 1; coalesces "session has new tx" signals
	stats    serverStats
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
	return &Server{
		cfg:         cfg,
		aead:        aead,
		dial:        net.DialTimeout,
		dns:         newDNSCache(),
		debugTiming: cfg.DebugTiming,
		sessions:    make(map[[frame.SessionIDLen]byte]*session.Session),
		txReady:     make(map[[frame.SessionIDLen]byte]struct{}),
		firstReply:  make(map[[frame.SessionIDLen]byte]struct{}),
		dialFail:    make(map[string]time.Time),
		activity:    make(chan struct{}, 1),
	}, nil
}

// ListenAndServe blocks. It binds an HTTP listener on cfg.ListenAddr with one
// route, POST /tunnel, that handles batched encrypted frames.
func (s *Server) ListenAndServe() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/tunnel", s.handleTunnel)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	httpSrv := &http.Server{
		Addr:        s.cfg.ListenAddr,
		Handler:     mux,
		ReadTimeout: 30 * time.Second,
		// WriteTimeout intentionally generous — long-poll responses can take
		// up to LongPollWindow to start writing.
		WriteTimeout: LongPollWindow + 10*time.Second,
	}

	// Periodic stats line so an operator following journalctl/systemd logs can
	// see traffic + session health without grepping. Lives for the lifetime of
	// the HTTP server (cancelled when ListenAndServe returns).
	statsCtx, cancelStats := context.WithCancel(context.Background())
	defer cancelStats()
	go s.runStatsLoop(statsCtx)

	log.Printf("[exit] listening on %s", s.cfg.ListenAddr)
	return httpSrv.ListenAndServe()
}

func (s *Server) handleTunnel(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	s.stats.requests.Add(1)
	body, err := io.ReadAll(r.Body)
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
			// Coalesce bursts into one response to reduce per-request overhead,
			// but only when the batch is large enough to be bulk/video traffic.
			// Small batches (≤ coalesceMinFrames) are interactive; adding a
			// 25ms wait there compounds latency across every TLS round-trip.
			// Urgent batches (RSTs, first downstream after SYN) skip coalesce
			// unconditionally so connection setup is not delayed.
			if !urgent && len(txFrames) > coalesceMinFrames {
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

// routeIncoming routes one incoming frame to its session, creating the session
// (and dialing upstream) if this is a SYN.
func (s *Server) routeIncoming(f *frame.Frame) {
	s.mu.Lock()
	sess, exists := s.sessions[f.SessionID]
	s.mu.Unlock()

	if !exists {
		if !f.HasFlag(frame.FlagSYN) {
			log.Printf("[exit] frame for unknown session (no SYN), sending RST")
			rst := &frame.Frame{SessionID: f.SessionID, Flags: frame.FlagRST}
			s.mu.Lock()
			s.pendingRSTs = append(s.pendingRSTs, rst)
			s.mu.Unlock()
			s.stats.rstSent.Add(1)
			s.kick()
			return
		}
		if s.isDialSuppressed(f.Target) {
			rst := &frame.Frame{SessionID: f.SessionID, Flags: frame.FlagRST}
			s.mu.Lock()
			s.pendingRSTs = append(s.pendingRSTs, rst)
			s.mu.Unlock()
			s.stats.rstSent.Add(1)
			s.kick()
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
	sess.ProcessRx(f)
}

// openSession dials the upstream target, creates a Session for the given ID,
// registers it, and spawns the bidirectional pump goroutines.
func (s *Server) openSession(id [frame.SessionIDLen]byte, target string) (*session.Session, error) {
	res, err := dialWithDNSCache(s.dns, s.dial, "tcp", target, 15*time.Second)
	if err != nil {
		return nil, err
	}
	upstream := res.Conn
	// Disable Nagle's algorithm so small writes (TLS handshake records, HTTP
	// request lines) hit the wire immediately instead of waiting up to 40 ms
	// to coalesce. Interactive workloads dominate this tunnel; throughput-bound
	// flows already buffer at the kernel level.
	if tcpConn, ok := upstream.(*net.TCPConn); ok {
		_ = tcpConn.SetNoDelay(true)
	}
	if s.debugTiming {
		log.Printf("[timing] %x dial dns=%dms cached=%v tcp=%dms target=%s",
			id[:4], res.DNS.Milliseconds(), res.DNSCached, res.TCP.Milliseconds(), target)
	}
	dialedAt := time.Now()
	sess := session.New(id, target, false)
	sess.OnTx = func() {
		s.mu.Lock()
		s.txReady[id] = struct{}{}
		s.mu.Unlock()
		s.kick()
	}

	s.mu.Lock()
	s.sessions[id] = sess
	s.firstReply[id] = struct{}{}
	s.mu.Unlock()
	s.stats.sessionsOpen.Add(1)

	log.Printf("[exit] new session %x -> %s", id[:4], target)

	// Upstream → session.EnqueueTx (downstream direction).
	go func() {
		defer upstream.Close()
		buf := make([]byte, upstreamReadBuf)
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
			s.stats.sessionsClose.Add(1)
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
