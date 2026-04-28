package carrier

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kianmhz/GooseRelayVPN/internal/frame"
	"github.com/kianmhz/GooseRelayVPN/internal/session"
)

const (
	// MaxFramePayload caps the bytes per frame; larger writes are chunked.
	// Raised from 128KB: single-seal means no per-frame crypto cost, so fewer
	// larger frames are strictly better (less length-prefix overhead, fewer
	// Unmarshal calls). Must match the value in internal/exit/exit.go.
	MaxFramePayload = 256 * 1024

	// pollIdleSleep is the breather between polls when nothing is happening,
	// to avoid busy-looping if the server returns instantly with empty bodies.
	pollIdleSleep = 50 * time.Millisecond

	// pollTimeout is the per-request HTTP ceiling; should comfortably exceed
	// the server's long-poll window (~25s).
	pollTimeout = 120 * time.Second

	// maxDrainFramesPerSession keeps one busy session from monopolizing a poll
	// cycle when many short-lived sessions are active (e.g., chat apps).
	maxDrainFramesPerSession = 8

	// maxDrainFramesPerBatch bounds total frames sent in one poll request so
	// very high session fan-out does not create oversized POST bodies.
	maxDrainFramesPerBatch = 48

	// Under high fan-out (mobile apps opening many parallel connections), allow
	// a larger but still bounded batch to reduce queueing delay.
	busySessionThreshold       = 24
	maxDrainFramesPerBatchBusy = 144

	// Hard cap for one relay response body to avoid spending CPU/memory on
	// unexpectedly huge non-frame payloads (HTML error pages, quota pages, etc).
	maxRelayResponseBodyBytes = 32 * 1024 * 1024

	// Endpoint failure backoff to shed unhealthy deployments during quota spikes
	// or tail-latency events without changing protocol behavior.
	endpointBlacklistBaseTTL = 3 * time.Second
	endpointBlacklistMaxTTL  = 48 * time.Second
	endpointBlacklistMaxStep = 4
)

// Config bundles everything the carrier needs to talk to the relay.
type Config struct {
	ScriptURLs  []string // one or more full https://script.google.com/macros/s/.../exec URLs
	Fronting    FrontingConfig
	AESKeyHex   string // 64-char hex, must match server
	DebugTiming bool   // when true, log per-session TTFB and per-poll Apps Script RTT
}

type relayEndpoint struct {
	url             string
	blacklistedTill time.Time
	failCount       int
}

// numPollWorkers is the number of concurrent poll goroutines. Multiple
// goroutines eliminate head-of-line blocking: while one goroutine is blocked
// waiting for the server's long-poll response (e.g. CDN data for session 1),
// the others can immediately send SYNs for sessions 2, 3, 4 that queued up.
const numPollWorkers = 3

// maxConcurrentIdlePolls limits how many workers may issue an empty poll
// simultaneously. Empty polls are long-held by the server (LongPollWindow), so
// if all workers enter them at once, newly queued SYN/data frames must wait
// for a worker to return, causing 8s/16s latency spikes. Keep one long-poll
// for downstream push, and leave the rest of workers available for outbound TX.
// maxConcurrentIdlePollsDownload raises the cap when txReady is empty: in
// pure-download mode (video, large files) there is no outbound TX to reserve
// workers for, so all-but-one workers can long-poll concurrently for better
// downstream throughput.
const (
	maxConcurrentIdlePolls         = 1
	maxConcurrentIdlePollsDownload = numPollWorkers - 1
)

// waker is a broadcast notifier: Broadcast() wakes all goroutines currently
// blocked on C() simultaneously, unlike a buffered chan which only wakes one.
type waker struct {
	mu sync.Mutex
	ch chan struct{}
}

func newWaker() *waker { return &waker{ch: make(chan struct{})} }

// C returns the current channel to select on. Must be captured before
// entering select so a concurrent Broadcast() cannot be missed.
func (w *waker) C() <-chan struct{} {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.ch
}

// Broadcast unblocks all goroutines currently waiting on C().
func (w *waker) Broadcast() {
	w.mu.Lock()
	defer w.mu.Unlock()
	close(w.ch)
	w.ch = make(chan struct{})
}

// Client owns the session map and the long-poll loop.
type Client struct {
	cfg         Config
	aead        *frame.Crypto
	httpClients []*http.Client  // one per SNI host; round-robined per request
	nextHTTP    atomic.Uint64   // round-robin index into httpClients
	debugTiming bool

	// debugStarts tracks session start times when debugTiming is on so we can
	// log time-to-first-byte once each session receives its first downstream
	// frame. Entries are deleted on first rx.
	debugStarts sync.Map

	mu       sync.Mutex
	sessions map[[frame.SessionIDLen]byte]*session.Session
	inFlight map[[frame.SessionIDLen]byte]bool
	txReady  map[[frame.SessionIDLen]byte]struct{} // sessions with pending TX frames

	endpointMu   sync.Mutex
	endpoints    []relayEndpoint
	nextEndpoint int

	idlePollMu       sync.Mutex
	idlePollInFlight int

	wake  *waker // broadcasts to all idle poll goroutines simultaneously
	stats clientStats
}

// clientStats holds atomic counters surfaced periodically by statsLoop.
// All fields are uint64 so they can be Load()ed without locking.
type clientStats struct {
	framesOut     atomic.Uint64
	framesIn      atomic.Uint64
	bytesOut      atomic.Uint64
	bytesIn       atomic.Uint64
	pollsOK       atomic.Uint64
	pollsFail     atomic.Uint64
	rstFromServer atomic.Uint64
	sessionsOpen  atomic.Uint64
	sessionsClose atomic.Uint64
}

// New constructs a Client. The HTTP client is preconfigured for domain
// fronting per cfg.Fronting.
func New(cfg Config) (*Client, error) {
	aead, err := frame.NewCryptoFromHexKey(cfg.AESKeyHex)
	if err != nil {
		return nil, err
	}

	endpoints := make([]relayEndpoint, 0, len(cfg.ScriptURLs))
	seen := make(map[string]struct{}, len(cfg.ScriptURLs))
	for _, raw := range cfg.ScriptURLs {
		url := strings.TrimSpace(raw)
		if url == "" {
			continue
		}
		if _, ok := seen[url]; ok {
			continue
		}
		seen[url] = struct{}{}
		endpoints = append(endpoints, relayEndpoint{url: url})
	}
	if len(endpoints) == 0 {
		return nil, fmt.Errorf("at least one script URL is required")
	}

	return &Client{
		cfg:         cfg,
		aead:        aead,
		httpClients: NewFrontedClients(cfg.Fronting, pollTimeout),
		debugTiming: cfg.DebugTiming,
		sessions:    make(map[[frame.SessionIDLen]byte]*session.Session),
		inFlight:    make(map[[frame.SessionIDLen]byte]bool),
		txReady:     make(map[[frame.SessionIDLen]byte]struct{}),
		endpoints:   endpoints,
		wake:        newWaker(),
	}, nil
}

// NewSession creates a tunneled session for target ("host:port") and registers
// it with the long-poll loop. Returns the session for the caller (typically
// the SOCKS adapter) to wrap in a VirtualConn.
func (c *Client) NewSession(target string) *session.Session {
	var id [frame.SessionIDLen]byte
	if _, err := rand.Read(id[:]); err != nil {
		// crypto/rand failure is unrecoverable; panic so the process exits
		// rather than emitting an all-zero ID.
		panic(fmt.Errorf("crypto/rand: %w", err))
	}
	s := session.New(id, target, true)
	s.OnTx = func() {
		c.mu.Lock()
		c.txReady[id] = struct{}{}
		c.mu.Unlock()
		c.kick()
	}
	c.mu.Lock()
	c.sessions[id] = s
	c.txReady[id] = struct{}{} // SYN is pending immediately on creation
	c.mu.Unlock()
	c.stats.sessionsOpen.Add(1)
	if c.debugTiming {
		c.debugStarts.Store(id, time.Now())
	}
	c.kick()
	return s
}

// Run spawns numPollWorkers concurrent poll goroutines and blocks until ctx
// is canceled. Parallel workers eliminate head-of-line blocking: while one
// worker waits for a server long-poll response, the others immediately dispatch
// queued SYNs for new sessions opened at the same time (e.g. YouTube page load).
func (c *Client) Run(ctx context.Context) error {
	var wg sync.WaitGroup
	for i := 0; i < numPollWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.runWorker(ctx)
		}()
	}
	// Periodic stats line so an operator can spot trends without grepping.
	wg.Add(1)
	go func() {
		defer wg.Done()
		c.runStatsLoop(ctx)
	}()
	wg.Wait()
	return ctx.Err()
}

func (c *Client) runWorker(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		didWork := c.pollOnce(ctx)
		c.gcDoneSessions()
		if !didWork {
			// Capture the wake channel before entering select so we cannot
			// miss a Broadcast() that fires between drainAll() returning
			// empty and us entering the wait.
			wakeCh := c.wake.C()
			select {
			case <-ctx.Done():
				return
			case <-wakeCh:
				// woken by new session data
			case <-time.After(pollIdleSleep):
			}
		}
	}
}

// pollOnce drains pending tx frames, POSTs them as a batch, and routes any
// response frames back to their sessions. Returns true if any work was done
// (frames sent or received) so the Run loop can decide whether to sleep.
func (c *Client) pollOnce(ctx context.Context) bool {
	frames, drainedIDs := c.drainAll()
	if len(drainedIDs) > 0 {
		defer c.releaseInFlight(drainedIDs)
	}
	isIdlePoll := len(frames) == 0
	if isIdlePoll {
		// In pure-download mode (txReady empty) all workers can long-poll
		// concurrently; there is no TX to reserve a free worker for.
		c.mu.Lock()
		idleCap := maxConcurrentIdlePolls
		if len(c.txReady) == 0 {
			idleCap = maxConcurrentIdlePollsDownload
		}
		c.mu.Unlock()
		if !c.acquireIdlePollSlot(idleCap) {
			return false
		}
		defer c.releaseIdlePollSlot()
	}

	// Stats: classify poll outcome on return so callers don't have to remember
	// to bump counters at every terminal point inside the retry loop.
	var (
		attempted bool
		pollOK    bool
	)
	defer func() {
		if !attempted {
			return
		}
		if pollOK {
			c.stats.pollsOK.Add(1)
		} else {
			c.stats.pollsFail.Add(1)
		}
	}()

	body, err := frame.EncodeBatch(c.aead, frames)
	if err != nil {
		log.Printf("[carrier] failed to prepare encrypted request batch: %v", err)
		return false
	}

	maxAttempts := 1
	if len(c.endpoints) > 1 {
		// One same-poll failover attempt keeps drained TX payload from being lost
		// when one deployment intermittently fails under quota pressure.
		maxAttempts = 2
	}

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		endpointIdx, scriptURL := c.pickRelayEndpoint()
		if endpointIdx < 0 || scriptURL == "" {
			log.Printf("[carrier] no relay script URLs are configured")
			return false
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, scriptURL, bytes.NewReader(body))
		if err != nil {
			log.Printf("[carrier] failed to build relay request: %v", err)
			return false
		}
		req.Header.Set("Content-Type", "text/plain")
		attempted = true

		var pollStart time.Time
		if c.debugTiming {
			pollStart = time.Now()
		}
		resp, err := c.pickHTTPClient().Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return false
			}
			c.markEndpointFailure(endpointIdx)
			if attempt < maxAttempts {
				log.Printf("[carrier] relay request failed via %s (attempt %d/%d): %v; retrying alternate script", shortScriptKey(scriptURL), attempt, maxAttempts, err)
				continue
			}
			log.Printf("[carrier] relay request failed via %s: %v (check internet access, script_keys, and google_host)", shortScriptKey(scriptURL), err)
			time.Sleep(time.Second) // back off on transport errors
			return false
		}

		respBody, readErr := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if readErr != nil {
			c.markEndpointFailure(endpointIdx)
			if attempt < maxAttempts {
				log.Printf("[carrier] failed to read relay response via %s (attempt %d/%d): %v; retrying alternate script", shortScriptKey(scriptURL), attempt, maxAttempts, readErr)
				continue
			}
			log.Printf("[carrier] failed to read relay response: %v", readErr)
			return false
		}

		if resp.StatusCode == http.StatusNoContent || len(respBody) == 0 {
			c.markEndpointSuccess(endpointIdx)
			pollOK = true
			countFrameBytes(&c.stats.framesOut, &c.stats.bytesOut, frames)
			return len(frames) > 0
		}
		if resp.StatusCode != http.StatusOK {
			c.markEndpointFailure(endpointIdx)
			if attempt < maxAttempts {
				log.Printf("[carrier] relay returned HTTP %d via %s (attempt %d/%d); retrying alternate script", resp.StatusCode, shortScriptKey(scriptURL), attempt, maxAttempts)
				continue
			}
			log.Printf("[carrier] relay returned HTTP %d via %s (verify Apps Script deployment is live and access is set to Anyone)", resp.StatusCode, shortScriptKey(scriptURL))
			return false
		}
		if len(respBody) > maxRelayResponseBodyBytes {
			c.markEndpointFailure(endpointIdx)
			if attempt < maxAttempts {
				log.Printf("[carrier] relay response too large via %s (attempt %d/%d); retrying alternate script", shortScriptKey(scriptURL), attempt, maxAttempts)
				continue
			}
			log.Printf("[carrier] relay response too large via %s (%d bytes > %d); dropping batch to protect stability", shortScriptKey(scriptURL), len(respBody), maxRelayResponseBodyBytes)
			return len(frames) > 0
		}
		if isLikelyNonBatchRelayPayload(respBody) {
			c.markEndpointFailure(endpointIdx)
			if attempt < maxAttempts {
				log.Printf("[carrier] relay returned non-batch payload via %s (attempt %d/%d); retrying alternate script", shortScriptKey(scriptURL), attempt, maxAttempts)
				continue
			}
			log.Printf("[carrier] relay returned non-batch payload via %s (likely HTML/JSON error page), dropping response", shortScriptKey(scriptURL))
			return len(frames) > 0
		}

		rxFrames, decodeErr := frame.DecodeBatch(c.aead, respBody)
		if decodeErr != nil {
			c.markEndpointFailure(endpointIdx)
			if attempt < maxAttempts {
				log.Printf("[carrier] relay response was invalid via %s (attempt %d/%d): %v; retrying alternate script", shortScriptKey(scriptURL), attempt, maxAttempts, decodeErr)
				continue
			}
			log.Printf("[carrier] relay response was invalid via %s (possibly HTML/error page instead of encrypted data): %v", shortScriptKey(scriptURL), decodeErr)
			return len(frames) > 0
		}

		for _, f := range rxFrames {
			c.routeRx(f)
		}
		c.markEndpointSuccess(endpointIdx)
		pollOK = true
		countFrameBytes(&c.stats.framesOut, &c.stats.bytesOut, frames)
		countFrameBytes(&c.stats.framesIn, &c.stats.bytesIn, rxFrames)
		if c.debugTiming {
			log.Printf("[timing] poll rtt=%dms tx_frames=%d rx_frames=%d resp_bytes=%d via %s",
				time.Since(pollStart).Milliseconds(), len(frames), len(rxFrames), len(respBody), shortScriptKey(scriptURL))
		}
		return len(frames) > 0 || len(rxFrames) > 0
	}

	return false
}

// countFrameBytes adds the count and total payload size of frames to two
// atomic counters. Centralised so the call sites in pollOnce stay terse.
func countFrameBytes(frameCounter, byteCounter *atomic.Uint64, frames []*frame.Frame) {
	if len(frames) == 0 {
		return
	}
	var bytes uint64
	for _, f := range frames {
		bytes += uint64(len(f.Payload))
	}
	frameCounter.Add(uint64(len(frames)))
	byteCounter.Add(bytes)
}

// pickHTTPClient returns the next HTTP client in round-robin order. Each
// client has a distinct SNI host and connection pool, so successive calls
// naturally spread requests across separate throttle buckets.
func (c *Client) pickHTTPClient() *http.Client {
	if len(c.httpClients) == 1 {
		return c.httpClients[0]
	}
	idx := c.nextHTTP.Add(1) - 1
	return c.httpClients[idx%uint64(len(c.httpClients))]
}

func (c *Client) pickRelayEndpoint() (int, string) {
	c.endpointMu.Lock()
	defer c.endpointMu.Unlock()

	n := len(c.endpoints)
	if n == 0 {
		return -1, ""
	}
	now := time.Now()
	start := c.nextEndpoint % n
	for i := 0; i < n; i++ {
		idx := (start + i) % n
		ep := c.endpoints[idx]
		if !ep.blacklistedTill.After(now) {
			c.nextEndpoint = (idx + 1) % n
			return idx, ep.url
		}
	}

	chosen := 0
	soonest := c.endpoints[0].blacklistedTill
	for i := 1; i < n; i++ {
		if c.endpoints[i].blacklistedTill.Before(soonest) {
			chosen = i
			soonest = c.endpoints[i].blacklistedTill
		}
	}
	c.nextEndpoint = (chosen + 1) % n
	return chosen, c.endpoints[chosen].url
}

func (c *Client) markEndpointSuccess(endpointIdx int) {
	c.endpointMu.Lock()
	if endpointIdx < 0 || endpointIdx >= len(c.endpoints) {
		c.endpointMu.Unlock()
		return
	}
	ep := &c.endpoints[endpointIdx]
	wasFailing := ep.failCount > 0
	url := ep.url
	ep.failCount = 0
	ep.blacklistedTill = time.Time{}
	c.endpointMu.Unlock()
	if wasFailing {
		log.Printf("[carrier] endpoint %s recovered (back in rotation)", shortScriptKey(url))
	}
}

func (c *Client) markEndpointFailure(endpointIdx int) {
	c.endpointMu.Lock()
	if endpointIdx < 0 || endpointIdx >= len(c.endpoints) {
		c.endpointMu.Unlock()
		return
	}
	ep := &c.endpoints[endpointIdx]
	wasHealthy := ep.failCount == 0
	ep.failCount++
	step := ep.failCount - 1
	if step > endpointBlacklistMaxStep {
		step = endpointBlacklistMaxStep
	}
	ttl := endpointBlacklistBaseTTL << step
	if ttl > endpointBlacklistMaxTTL {
		ttl = endpointBlacklistMaxTTL
	}
	ep.blacklistedTill = time.Now().Add(ttl)
	url := ep.url
	failCount := ep.failCount
	c.endpointMu.Unlock()
	// Only log on the healthy → blacklisted transition; subsequent failures
	// of an already-blacklisted endpoint would be log noise.
	if wasHealthy {
		log.Printf("[carrier] endpoint %s blacklisted for %s (still rotating across %d others)",
			shortScriptKey(url), ttl.Round(100*time.Millisecond), len(c.endpoints)-1)
	} else if failCount == endpointBlacklistMaxStep+1 {
		// Notify once when an endpoint hits the maximum backoff step so the
		// operator knows this deployment is genuinely degraded, not just flaky.
		log.Printf("[carrier] endpoint %s repeatedly failing (%d consecutive); now at max backoff (%s). Consider re-deploying that script.",
			shortScriptKey(url), failCount, endpointBlacklistMaxTTL)
	}
}

func (c *Client) drainAll() ([]*frame.Frame, [][frame.SessionIDLen]byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []*frame.Frame
	var drainedIDs [][frame.SessionIDLen]byte
	batchCap := maxDrainFramesPerBatch
	if len(c.sessions) >= busySessionThreshold {
		batchCap = maxDrainFramesPerBatchBusy
	}
	remaining := batchCap

	drain := func(id [frame.SessionIDLen]byte, synOnly bool) {
		if remaining <= 0 {
			return
		}
		s, ok := c.sessions[id]
		if !ok {
			delete(c.txReady, id)
			return
		}
		if c.inFlight[id] {
			return // already sending; releaseInFlight will re-add if needed
		}
		if synOnly && !s.HasPendingSYN() {
			return
		}
		perSessionCap := maxDrainFramesPerSession
		if remaining < perSessionCap {
			perSessionCap = remaining
		}
		frames := s.DrainTxLimited(MaxFramePayload, perSessionCap)
		delete(c.txReady, id) // remove now; OnTx re-adds if more data arrives
		if len(frames) == 0 {
			return
		}
		c.inFlight[id] = true
		drainedIDs = append(drainedIDs, id)
		out = append(out, frames...)
		remaining -= len(frames)
	}

	// First pass: SYN sessions only. New connections claim batch slots before
	// ongoing data transfers so a large upload/download cannot push SYN frames
	// out of the batch and delay connection setup by a full poll cycle.
	for id := range c.txReady {
		drain(id, true)
	}
	// Second pass: remaining data sessions.
	for id := range c.txReady {
		drain(id, false)
	}
	return out, drainedIDs
}

func (c *Client) releaseInFlight(ids [][frame.SessionIDLen]byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, id := range ids {
		delete(c.inFlight, id)
		// Re-add to txReady if the batch cap left data behind or new data
		// arrived while this session was in-flight.
		if s, ok := c.sessions[id]; ok && s.HasPendingTx() {
			c.txReady[id] = struct{}{}
		}
	}
}

func (c *Client) routeRx(f *frame.Frame) {
	c.mu.Lock()
	s, ok := c.sessions[f.SessionID]
	c.mu.Unlock()
	if !ok {
		return // unknown session - drop
	}
	if c.debugTiming && len(f.Payload) > 0 {
		// First downstream frame for a session implies time-to-first-byte.
		// LoadAndDelete ensures we log this exactly once per session.
		if start, loaded := c.debugStarts.LoadAndDelete(f.SessionID); loaded {
			ttfb := time.Since(start.(time.Time))
			log.Printf("[timing] %x ttfb=%dms target=%s",
				f.SessionID[:4], ttfb.Milliseconds(), s.Target)
		}
	}
	if f.HasFlag(frame.FlagRST) {
		// Server has no state for this session (e.g. it restarted). Tear it down
		// immediately so the SOCKS client gets an error and reconnects cleanly.
		log.Printf("[carrier] RST from server for session %x; closing", f.SessionID[:4])
		s.CloseRx()
		s.RequestClose()
		c.mu.Lock()
		delete(c.sessions, f.SessionID)
		delete(c.txReady, f.SessionID)
		c.mu.Unlock()
		if c.debugTiming {
			c.debugStarts.Delete(f.SessionID)
		}
		s.Stop()
		c.stats.rstFromServer.Add(1)
		c.stats.sessionsClose.Add(1)
		return
	}
	s.ProcessRx(f)
}

func (c *Client) gcDoneSessions() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for id, s := range c.sessions {
		if s.IsDone() {
			s.Stop()
			delete(c.sessions, id)
			delete(c.txReady, id)
			if c.debugTiming {
				c.debugStarts.Delete(id)
			}
			c.stats.sessionsClose.Add(1)
		}
	}
}

func (c *Client) acquireIdlePollSlot(cap int) bool {
	c.idlePollMu.Lock()
	defer c.idlePollMu.Unlock()
	if c.idlePollInFlight >= cap {
		return false
	}
	c.idlePollInFlight++
	return true
}

func (c *Client) releaseIdlePollSlot() {
	c.idlePollMu.Lock()
	defer c.idlePollMu.Unlock()
	if c.idlePollInFlight > 0 {
		c.idlePollInFlight--
	}
}

// kick broadcasts to all idle poll workers. Safe to call from any goroutine.
func (c *Client) kick() {
	c.wake.Broadcast()
}

func isLikelyNonBatchRelayPayload(body []byte) bool {
	t := bytes.TrimSpace(body)
	if len(t) == 0 {
		return false
	}
	l := bytes.ToLower(t)
	if bytes.HasPrefix(l, []byte("<!doctype")) || bytes.HasPrefix(l, []byte("<html")) {
		return true
	}
	// Base64 batches never begin with JSON object/array delimiters or raw HTTP.
	if t[0] == '{' || t[0] == '[' || bytes.HasPrefix(t, []byte("HTTP/")) {
		return true
	}
	return false
}

func shortScriptKey(scriptURL string) string {
	parts := strings.Split(strings.Trim(scriptURL, "/"), "/")
	for i := 0; i < len(parts)-1; i++ {
		if parts[i] == "s" {
			id := parts[i+1]
			if len(id) > 14 {
				return id[:6] + "..." + id[len(id)-6:]
			}
			return id
		}
	}
	return "(unknown)"
}
