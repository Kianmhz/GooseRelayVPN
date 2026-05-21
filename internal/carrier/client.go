package carrier

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
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

	// pollIdleSleep is the breather between polls when nothing is happening.
	// 10ms instead of 50ms: keeps workers responsive to kick() misses and
	// idle-slot retry at negligible CPU cost at true idle. Adaptive backoff
	// (see idleBackoff) extends this when consecutive polls return no work.
	pollIdleSleep = 10 * time.Millisecond

	// pureDownloadIdleCap is the minimum number of concurrent idle long-polls
	// allowed in pure-download mode (no pending TX). The actual cap is
	// max(pureDownloadIdleCap, len(endpoints)) so multi-endpoint configs get
	// one idle poll per deployment. This floor ensures single-endpoint configs
	// keep two slots for redundancy during the pollIdleSleep re-entry window.
	// Previously this was numWorkers-1 (issue #41: excessive empty POSTs);
	// a hard cap of 2 overcorrected for multi-endpoint configs (issue #73).
	pureDownloadIdleCap = 2

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
	endpointBlacklistMaxTTL  = 1 * time.Hour

	// Local offline failures should not ramp a mobile client into the 30m/1h
	// endpoint penalty box. Keep the pause long enough to avoid a tight retry
	// loop while airplane mode is on, but short enough that new sessions recover
	// quickly when the network returns.
	localNetworkOfflineBlacklistTTL = 15 * time.Second
	localNetworkRecoveryProbeEvery  = 5 * time.Second
	localNetworkRecoveryProbeTO     = 2 * time.Second
)

func isLocalNetworkOffline(err error) bool {
	if err == nil {
		return false
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		if dnsErr.IsTimeout || dnsErr.IsTemporary || dnsErr.IsNotFound {
			return true
		}
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) && strings.EqualFold(opErr.Op, "dial") {
		if opErr.Timeout() || errors.Is(opErr.Err, context.DeadlineExceeded) {
			return true
		}
	}
	var syscallErr *os.SyscallError
	if errors.As(err, &syscallErr) && isLocalOfflineSyscall(syscallErr.Err) {
		return true
	}
	if isLocalOfflineSyscall(err) {
		return true
	}

	// Last-resort fallback for platform-specific wrapped messages, especially
	// Windows WSA errors whose Errno values do not always compare cleanly after
	// net/http wraps them in url.Error/net.OpError.
	msg := strings.ToLower(err.Error())
	for _, needle := range []string{
		"network is unreachable",
		"unreachable network",
		"no route to host",
		"network is down",
		"host is down",
		"host is unreachable",
		"temporary failure in name resolution",
		"no such host",
	} {
		if strings.Contains(msg, needle) {
			return true
		}
	}
	return false
}

// isLocalOfflineSyscall checks errno values that indicate the local network
// stack is offline. The set is intentionally restricted to errnos defined on
// every supported platform (Linux/macOS/Windows). Linux-only ENONET ("machine
// is not on the network") is covered by the message-substring fallback in
// isLocalNetworkOffline.
func isLocalOfflineSyscall(err error) bool {
	for _, target := range []error{
		syscall.ENETUNREACH,
		syscall.EHOSTUNREACH,
		syscall.ENETDOWN,
		syscall.EHOSTDOWN,
	} {
		if errors.Is(err, target) {
			return true
		}
	}
	return false
}

func recoveryProbeAddress(cfg Config) string {
	addr := strings.TrimSpace(cfg.Fronting.GoogleIP)
	if addr == "" {
		return ""
	}
	if _, _, err := net.SplitHostPort(addr); err == nil {
		return addr
	}
	return net.JoinHostPort(addr, "443")
}

func readRelayResponseBody(r io.Reader, contentLength int64, limit int) ([]byte, error) {
	if contentLength > int64(limit) {
		return nil, fmt.Errorf("relay response too large (%d bytes > %d)", contentLength, limit)
	}
	if contentLength >= 0 {
		body := make([]byte, int(contentLength))
		if _, err := io.ReadFull(r, body); err != nil {
			return nil, err
		}
		return body, nil
	}
	lr := &io.LimitedReader{R: r, N: int64(limit) + 1}
	body, err := io.ReadAll(lr)
	if err != nil {
		return nil, err
	}
	if len(body) > limit {
		return nil, fmt.Errorf("relay response too large (%d bytes > %d)", len(body), limit)
	}
	return body, nil
}

// Config bundles everything the carrier needs to talk to the relay.
type Config struct {
	ScriptURLs    []string // one or more full https://script.google.com/macros/s/.../exec URLs
	ClientVersion string   // build version string for diagnostics

	// ScriptAccounts is an optional parallel slice to ScriptURLs labeling each
	// deployment with the Google account it lives under. When set, the periodic
	// stats line aggregates today/script counts by account so the operator can
	// see how much of each account's ~20k/day quota has been spent. nil or
	// shorter slices are tolerated; missing entries are treated as unlabeled.
	ScriptAccounts []string

	Fronting    FrontingConfig
	AESKeyHex   string // 64-char hex, must match server
	DebugTiming bool   // when true, log per-session TTFB and per-poll Apps Script RTT

	// CoalesceStep / CoalesceMax enable adaptive uplink coalescing on kick().
	// When CoalesceStep > 0 the first kick of a burst arms a step timer; each
	// subsequent kick within the window resets it, bounded by CoalesceMax from
	// the first kick. Bursts collapse into a single wake. Both 0 = disabled.
	CoalesceStep time.Duration
	CoalesceMax  time.Duration

	// IdleSlotsPerBucket is the number of concurrent idle long-polls allowed
	// per account bucket. <= 0 means default (1). Validated and capped at 3
	// by the config layer; the carrier accepts any positive value here but
	// users should configure through the config layer to get the cap and the
	// "why this cap" error message.
	IdleSlotsPerBucket int
}

type relayEndpoint struct {
	url                 string
	account             string // optional human-readable Google account label, "" = unlabeled
	blacklistedTill     time.Time
	localNetworkOffline bool
	failCount           int
	statsOK             uint64
	statsFail           uint64

	// Per-quota-window counters. dailyCount is the number of HTTP responses
	// received from Apps Script in the current window; dailyResetAt is the
	// next midnight Pacific (the boundary at which Apps Script resets the
	// per-account UrlFetch quota). Both are managed via touchDailyWindow.
	dailyCount   uint64
	dailyResetAt time.Time

	// Script-reported per-day invocation count, fetched hourly via doGet on
	// the same /exec URL. scriptCountAt is zero until the first successful
	// fetch; scriptStatsErrLogged suppresses repeat "needs redeploy" warnings
	// when the deployed Code.gs is the legacy version that doesn't return JSON.
	scriptCount          uint64
	scriptCountAt        time.Time
	scriptStatsErrLogged bool
}

// workersPerEndpoint is the number of concurrent poll goroutines spawned for
// each configured script URL. Total workers = workersPerEndpoint × len(endpoints).
// Scaling with endpoint count means adding more deployment IDs increases
// parallelism rather than just spreading the same fixed pool thinner.
const workersPerEndpoint = 3

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
	cfg                Config
	aead               *frame.Crypto
	httpClients        []*http.Client // one per SNI host; round-robined per request
	nextHTTP           atomic.Uint64  // round-robin index into httpClients
	debugTiming        bool
	numWorkers         int // (workersPerEndpoint + idleSlotsPerBucket - 1) × bucketCount
	bucketCount        int // distinct account labels in endpoints; unlabeled all share one bucket
	idleSlotsPerBucket int // resolved from Config.IdleSlotsPerBucket, default 1
	clientVersion      string

	// clientID is a random 16-byte identifier minted once per process. It is
	// embedded in every encrypted batch so the server can route downstream
	// frames back to the correct client when several clients share one server.
	clientID [frame.ClientIDLen]byte

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

	// Adaptive kick coalescing (see Config.CoalesceStep/Max). When step <= 0
	// these fields are unused and kick() broadcasts immediately.
	coalesceStep     time.Duration
	coalesceMax      time.Duration
	coalesceMu       sync.Mutex
	coalesceTimer    *time.Timer // armed during a coalesce window; nil otherwise
	coalesceDeadline time.Time   // hard cap for the in-flight window

	recoveryProbeAddr string
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
	for i, raw := range cfg.ScriptURLs {
		url := strings.TrimSpace(raw)
		if url == "" {
			continue
		}
		if _, ok := seen[url]; ok {
			continue
		}
		seen[url] = struct{}{}
		account := ""
		if i < len(cfg.ScriptAccounts) {
			account = strings.TrimSpace(cfg.ScriptAccounts[i])
		}
		endpoints = append(endpoints, relayEndpoint{url: url, account: account})
	}
	if len(endpoints) == 0 {
		return nil, fmt.Errorf("at least one script URL is required")
	}

	// Concurrency scales with distinct Google account "buckets", not endpoint
	// count. Apps Script's per-second concurrency cap and ~20k UrlFetchApp/day
	// quota are per-account: scaling workers/idle-slots by endpoint count
	// (pre-fix behavior) overloads users who deploy multiple IDs under one
	// account, causing Apps Script to return HTML error pages instead of the
	// encrypted batch (issue #56). Unlabeled endpoints all share one anonymous
	// bucket so legacy configs default to v1.2.0-equivalent load.
	accountSeen := make(map[string]struct{}, len(endpoints))
	labeled := 0
	for _, ep := range endpoints {
		accountSeen[ep.account] = struct{}{}
		if ep.account != "" {
			labeled++
		}
	}
	bucketCount := len(accountSeen)

	var clientID [frame.ClientIDLen]byte
	if _, err := rand.Read(clientID[:]); err != nil {
		// crypto/rand failure is unrecoverable; fail fast rather than emitting
		// an all-zero ID that would collide with every other unupgraded client.
		return nil, fmt.Errorf("crypto/rand: %w", err)
	}

	idleSlotsPerBucket := cfg.IdleSlotsPerBucket
	if idleSlotsPerBucket <= 0 {
		idleSlotsPerBucket = 1
	}
	// Worker count scales with idleSlotsPerBucket so the TX pool isn't
	// drained when the user opts up the RX cap. With workersPerEndpoint=3
	// and idleSlotsPerBucket=1, this reduces to the old 3×bucketCount.
	// At idleSlotsPerBucket=2, each bucket gets +1 worker so the same
	// number of workers stay free for TX after the extra idle slot is
	// camped — the alternative (fixed worker count) starves session
	// establishment under TX bursts when more workers are tied to long
	// polls.
	numWorkers := (workersPerEndpoint + idleSlotsPerBucket - 1) * bucketCount
	log.Printf("[carrier] %d worker(s) across %d account bucket(s) (%d endpoint(s)), %d idle slot(s)/bucket",
		numWorkers, bucketCount, len(endpoints), idleSlotsPerBucket)
	if labeled == 0 && len(endpoints) > 1 {
		log.Printf("[carrier] WARN: %d deployments configured with no account labels — treating as one bucket. "+
			"If these deployments are under different Google accounts, label them in script_keys "+
			"as {\"id\": \"...\", \"account\": \"A\"} to unlock per-account parallelism.",
			len(endpoints))
	}

	return &Client{
		cfg:                cfg,
		aead:               aead,
		httpClients:        NewFrontedClients(cfg.Fronting, pollTimeout, endpoints[0].url),
		debugTiming:        cfg.DebugTiming,
		numWorkers:         numWorkers,
		bucketCount:        bucketCount,
		idleSlotsPerBucket: idleSlotsPerBucket,
		clientVersion:      cfg.ClientVersion,
		clientID:           clientID,
		sessions:           make(map[[frame.SessionIDLen]byte]*session.Session),
		inFlight:           make(map[[frame.SessionIDLen]byte]bool),
		txReady:            make(map[[frame.SessionIDLen]byte]struct{}),
		endpoints:          endpoints,
		wake:               newWaker(),
		coalesceStep:       cfg.CoalesceStep,
		coalesceMax:        cfg.CoalesceMax,
		recoveryProbeAddr:  recoveryProbeAddress(cfg),
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

// Shutdown sends an RST frame for every active session so the server can
// release the corresponding upstream connections immediately rather than
// waiting for its idle-session GC. Intended to be called from a SIGINT/SIGTERM
// handler before canceling the main context. ctx bounds how long we'll wait
// for the final POST to complete.
//
// Best-effort: if the POST fails (network gone, server unreachable) we just
// return — the server's idle GC is the safety net for that case.
func (c *Client) Shutdown(ctx context.Context) {
	c.mu.Lock()
	if len(c.sessions) == 0 {
		c.mu.Unlock()
		return
	}
	rsts := make([]*frame.Frame, 0, len(c.sessions))
	for id := range c.sessions {
		rsts = append(rsts, &frame.Frame{
			SessionID: id,
			Flags:     frame.FlagRST,
		})
	}
	c.mu.Unlock()

	body, err := frame.EncodeBatch(c.aead, c.clientID, rsts)
	if err != nil {
		log.Printf("[carrier] shutdown: encode failed: %v", err)
		return
	}

	_, scriptURL := c.pickRelayEndpoint()
	if scriptURL == "" {
		return
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, scriptURL, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "text/plain")

	log.Printf("[carrier] shutdown: sending RST for %d active sessions", len(rsts))
	resp, err := c.pickHTTPClient().Do(req)
	if err != nil {
		log.Printf("[carrier] shutdown: send failed (server idle GC will clean up): %v", err)
		return
	}
	_ = resp.Body.Close()
}

// Run spawns c.numWorkers concurrent poll goroutines and blocks until ctx is
// canceled. Worker count scales with the number of configured endpoints so that
// adding more script URLs increases parallelism rather than spreading the same
// fixed pool thinner.
func (c *Client) Run(ctx context.Context) error {
	var wg sync.WaitGroup
	for i := 0; i < c.numWorkers; i++ {
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
	// Hourly fetch of each deployment's self-reported invocation count.
	// Logged in the next [stats] line as `script=N` next to the existing
	// client-side `today=N` so the user sees both perspectives.
	wg.Add(1)
	go func() {
		defer wg.Done()
		c.runScriptStatsLoop(ctx)
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		c.runEndpointRecoveryLoop(ctx)
	}()
	wg.Wait()
	return ctx.Err()
}

func (c *Client) runWorker(ctx context.Context) {
	consecutiveIdle := 0
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		didWork := c.pollOnce(ctx)
		c.gcDoneSessions()
		if didWork {
			consecutiveIdle = 0
			continue
		}
		consecutiveIdle++
		// Capture the wake channel before entering select so we cannot
		// miss a Broadcast() that fires between drainAll() returning
		// empty and us entering the wait. The wake takes precedence over
		// the timer, so backoff never delays the response to new TX.
		wakeCh := c.wake.C()
		select {
		case <-ctx.Done():
			return
		case <-wakeCh:
			consecutiveIdle = 0
		case <-time.After(idleBackoff(consecutiveIdle)):
		}
	}
}

func (c *Client) runEndpointRecoveryLoop(ctx context.Context) {
	if c.recoveryProbeAddr == "" {
		return
	}
	t := time.NewTicker(localNetworkRecoveryProbeEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if c.runEndpointRecoveryProbeOnce(ctx) {
				c.wake.Broadcast()
			}
		}
	}
}

func (c *Client) runEndpointRecoveryProbeOnce(ctx context.Context) bool {
	if c.recoveryProbeAddr == "" || !c.shouldRunLocalNetworkRecoveryProbe() {
		return false
	}
	probeCtx, cancel := context.WithTimeout(ctx, localNetworkRecoveryProbeTO)
	defer cancel()
	dialer := net.Dialer{Timeout: localNetworkRecoveryProbeTO}
	conn, err := dialer.DialContext(probeCtx, "tcp", c.recoveryProbeAddr)
	if err != nil {
		return false
	}
	_ = conn.Close()
	cleared := c.resetLocalNetworkFailures()
	if cleared > 0 {
		log.Printf("[carrier] local network appears reachable again; cleared %d local-offline endpoint backoff(s)", cleared)
	}
	return cleared > 0
}

func (c *Client) shouldRunLocalNetworkRecoveryProbe() bool {
	c.endpointMu.Lock()
	defer c.endpointMu.Unlock()
	if len(c.endpoints) == 0 {
		return false
	}
	now := time.Now()
	allUnavailable := true
	hasLocalOffline := false
	for i := range c.endpoints {
		ep := &c.endpoints[i]
		if !ep.blacklistedTill.After(now) {
			allUnavailable = false
			break
		}
		if ep.localNetworkOffline && ep.blacklistedTill.After(now) {
			hasLocalOffline = true
		}
	}
	return allUnavailable && hasLocalOffline
}

// idleBackoff returns how long a worker should sleep after n consecutive
// no-work polls. The wake channel is selected against this timer so any
// new TX (kick) cancels the sleep immediately and any held server-side
// long-poll receives downstream chunks without needing a fresh poll —
// so even a 1s tail does not add user-visible latency.
func idleBackoff(n int) time.Duration {
	switch {
	case n < 3:
		return pollIdleSleep
	case n < 10:
		return 50 * time.Millisecond
	case n < 30:
		return 250 * time.Millisecond
	default:
		return time.Second
	}
}

// pollOnce drains pending tx frames, POSTs them as a batch, and routes any
// response frames back to their sessions. Returns true if any work was done
// (frames sent or received) so the Run loop can decide whether to sleep.
func (c *Client) pollOnce(ctx context.Context) bool {
	frames, drainedIDs, snaps := c.drainAll()
	if len(drainedIDs) > 0 {
		defer c.releaseInFlight(drainedIDs)
	}
	// rollbackPending: set to false on success paths (batch delivered to the
	// exit server, response received) so snapshots are discarded. Stays true
	// on every other return path so unsent frames are restored to their
	// sessions and resent on the next poll cycle.
	rollbackPending := len(snaps) > 0
	defer func() {
		if rollbackPending {
			c.rollbackDrained(snaps)
		}
	}()
	isIdlePoll := len(frames) == 0
	if isIdlePoll {
		// Allow idleSlotsPerBucket idle long-poll slots per *account bucket* so
		// each Google account's quota gets the configured number of standing
		// polls for downstream push. History: a fixed cap of 1 (v1.2.0) starved
		// multi-deployment configs. Issue #41's fix to numWorkers-1 woke every
		// long-poll on every chunk and amplified upload bandwidth N-fold.
		// Issue #73's fix to max(2, len(endpoints)) gave each deployment a slot
		// — but when multiple deployments shared one Google account, that
		// overloaded the per-account concurrency cap (issue #56). Scaling by
		// bucket count is the natural unit Apps Script throttles on; the
		// idleSlotsPerBucket multiplier lets users who've validated their
		// accounts can sustain >1 simultaneous poll opt up. pureDownloadIdleCap
		// is the floor that keeps a single-bucket config from regressing to a
		// single standing poll.
		c.mu.Lock()
		idleCap := c.bucketCount * c.idleSlotsPerBucket
		if len(c.txReady) == 0 && idleCap < pureDownloadIdleCap {
			idleCap = pureDownloadIdleCap
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

	body, err := frame.EncodeBatch(c.aead, c.clientID, frames)
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
			c.endpointMu.Lock()
			anyConfigured := len(c.endpoints) > 0
			c.endpointMu.Unlock()
			if !anyConfigured {
				log.Printf("[carrier] no relay script URLs are configured")
			}
			// Otherwise: all endpoints are blacklisted; per-endpoint blacklist
			// logs were already emitted at the failing transitions. Returning
			// false here lets the worker's idle-backoff wait out the soonest
			// TTL without sending any traffic to flagged deployments.
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
		if err == nil {
			// Apps Script counts every doPost invocation, regardless of status,
			// so bump the daily counter once we know the request reached it.
			c.bumpDailyCount(endpointIdx)
		}
		if err != nil {
			if ctx.Err() != nil {
				return false
			}
			if isLocalNetworkOffline(err) {
				c.markEndpointLocalNetworkFailure(endpointIdx)
			} else {
				c.markEndpointFailure(endpointIdx)
			}
			if attempt < maxAttempts {
				log.Printf("[carrier] relay request failed via %s (attempt %d/%d): %v; retrying alternate script", shortScriptKey(scriptURL), attempt, maxAttempts, err)
				continue
			}
			log.Printf("[carrier] relay request failed via %s: %v (check internet access, script_keys, and google_host)", shortScriptKey(scriptURL), err)
			time.Sleep(time.Second) // back off on transport errors
			return false
		}

		respBody, readErr := readRelayResponseBody(resp.Body, resp.ContentLength, maxRelayResponseBodyBytes)
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
			rollbackPending = false // batch delivered; server returned no body
			countFrameBytes(&c.stats.framesOut, &c.stats.bytesOut, frames)
			return len(frames) > 0
		}
		if resp.StatusCode != http.StatusOK {
			switch resp.StatusCode {
			case http.StatusForbidden: // 403
				c.markEndpoint403(endpointIdx)
				if attempt < maxAttempts {
					log.Printf("[carrier] relay returned HTTP 403 via %s (attempt %d/%d); retrying alternate script", shortScriptKey(scriptURL), attempt, maxAttempts)
					continue
				}
				log.Printf("[carrier] relay returned HTTP 403 via %s (Apps Script quota exhausted or deployment not set to 'Anyone'; quota resets at midnight Pacific — consider adding more script deployments or waiting for reset)", shortScriptKey(scriptURL))
			case http.StatusTooManyRequests: // 429
				c.markEndpoint429(endpointIdx)
				if attempt < maxAttempts {
					log.Printf("[carrier] relay returned HTTP 429 (rate-limited) via %s (attempt %d/%d); retrying alternate script", shortScriptKey(scriptURL), attempt, maxAttempts)
					continue
				}
				log.Printf("[carrier] relay returned HTTP 429 (rate-limited) via %s; backing off and will retry automatically", shortScriptKey(scriptURL))
			default:
				c.markEndpointFailure(endpointIdx)
				if attempt < maxAttempts {
					log.Printf("[carrier] relay returned HTTP %d via %s (attempt %d/%d); retrying alternate script", resp.StatusCode, shortScriptKey(scriptURL), attempt, maxAttempts)
					continue
				}
				log.Printf("[carrier] relay returned HTTP %d via %s (verify Apps Script deployment is live and access is set to Anyone)", resp.StatusCode, shortScriptKey(scriptURL))
			}
			return false
		}
		if len(respBody) > maxRelayResponseBodyBytes {
			c.markEndpointFailure(endpointIdx)
			if attempt < maxAttempts {
				log.Printf("[carrier] relay response too large via %s (attempt %d/%d); retrying alternate script", shortScriptKey(scriptURL), attempt, maxAttempts)
				continue
			}
			log.Printf("[carrier] relay response too large via %s (%d bytes > %d); dropping batch to protect stability", shortScriptKey(scriptURL), len(respBody), maxRelayResponseBodyBytes)
			rollbackPending = false // request reached the server; we just can't ingest the response
			return len(frames) > 0
		}
		if isLikelyNonBatchRelayPayload(respBody) {
			errReason, errHard := classifyRelayErrorBody(respBody)
			if errHard {
				c.markEndpointHardFailure(endpointIdx)
			} else {
				c.markEndpointFailure(endpointIdx)
			}
			if attempt < maxAttempts {
				log.Printf("[carrier] relay returned non-batch payload via %s (attempt %d/%d); retrying alternate script", shortScriptKey(scriptURL), attempt, maxAttempts)
				continue
			}
			if errReason != "" {
				log.Printf("[carrier] relay returned non-batch payload via %s: %s", shortScriptKey(scriptURL), errReason)
			} else {
				log.Printf("[carrier] relay returned non-batch payload via %s (likely HTML/JSON error page), dropping response", shortScriptKey(scriptURL))
			}
			return len(frames) > 0
		}

		_, rxFrames, decodeErr := frame.DecodeBatch(c.aead, respBody)
		if decodeErr != nil {
			c.markEndpointFailure(endpointIdx)
			if attempt < maxAttempts {
				log.Printf("[carrier] relay response was invalid via %s (attempt %d/%d): %v; retrying alternate script", shortScriptKey(scriptURL), attempt, maxAttempts, decodeErr)
				continue
			}
			log.Printf("[carrier] relay response was invalid via %s (possibly HTML/error page instead of encrypted data): %v", shortScriptKey(scriptURL), decodeErr)
			rollbackPending = false // Apps Script returned a normal-looking 200; the exit server most likely processed the batch even though we can't ingest the response
			return len(frames) > 0
		}

		for _, f := range rxFrames {
			c.routeRx(f)
		}
		c.markEndpointSuccess(endpointIdx)
		pollOK = true
		rollbackPending = false // batch delivered, response decoded
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
		ep := &c.endpoints[idx]
		if ep.blacklistedTill.After(now) {
			continue
		}
		c.nextEndpoint = (idx + 1) % n
		return idx, ep.url
	}

	// All endpoints are temporarily blacklisted. Refuse to send rather than
	// hammer already-flagged deployments. The worker loop will idle-backoff
	// until the soonest TTL elapses; at that point the first loop above
	// picks the newly-available endpoint. Hammering during outages plausibly
	// extends Apps Script's per-deployment cooldown beyond the 24h daily
	// reset window (see issues #121 and #126).
	return -1, ""
}

func (c *Client) resetLocalNetworkFailures() int {
	c.endpointMu.Lock()
	defer c.endpointMu.Unlock()
	cleared := 0
	for i := range c.endpoints {
		ep := &c.endpoints[i]
		if !ep.localNetworkOffline {
			continue
		}
		ep.blacklistedTill = time.Time{}
		ep.failCount = 0
		ep.localNetworkOffline = false
		cleared++
	}
	return cleared
}

func (c *Client) markEndpointSuccess(endpointIdx int) {
	c.endpointMu.Lock()
	if endpointIdx < 0 || endpointIdx >= len(c.endpoints) {
		c.endpointMu.Unlock()
		return
	}
	ep := &c.endpoints[endpointIdx]
	wasFailing := ep.failCount > 0
	ep.statsOK++
	url := ep.url
	ep.failCount = 0
	ep.blacklistedTill = time.Time{}
	ep.localNetworkOffline = false
	c.endpointMu.Unlock()
	if wasFailing {
		log.Printf("[carrier] endpoint %s recovered (back in rotation)", shortScriptKey(url))
	}
}

// markEndpointFailure applies the standard exponential backoff ramp (3 s → 1 h)
// for transient failures (network errors, 5xx, decode failures).
func (c *Client) markEndpointFailure(endpointIdx int) {
	c.markEndpointFailureWith(endpointIdx, 0)
}

func (c *Client) markEndpointLocalNetworkFailure(endpointIdx int) {
	c.endpointMu.Lock()
	if endpointIdx < 0 || endpointIdx >= len(c.endpoints) {
		c.endpointMu.Unlock()
		return
	}
	ep := &c.endpoints[endpointIdx]
	wasHealthy := ep.failCount == 0 && !ep.blacklistedTill.After(time.Now())
	ep.failCount = 0
	ep.statsFail++
	ep.localNetworkOffline = true
	ep.blacklistedTill = time.Now().Add(localNetworkOfflineBlacklistTTL)
	url := ep.url
	peerCount := len(c.endpoints) - 1
	c.endpointMu.Unlock()
	if wasHealthy {
		log.Printf("[carrier] endpoint %s local network offline; retrying in %s (still rotating across %d others)",
			shortScriptKey(url), localNetworkOfflineBlacklistTTL.Round(time.Second), peerCount)
	}
}

// markEndpoint403 handles HTTP 403 (quota exhausted or deployment misconfigured).
// Quota walls don't self-heal in seconds; they persist until midnight Pacific.
// Jump straight to the 5-minute tier (failCount floor = 5 → next hit → 6 → 5 min)
// to avoid hammering a dead endpoint and wasting the failover slot on peers.
func (c *Client) markEndpoint403(endpointIdx int) {
	c.markEndpointFailureWith(endpointIdx, 5)
}

// markEndpoint429 handles HTTP 429 (rate-limited). Shorter self-heal than a
// full quota exhaustion: jump to failCount floor = 3 → next hit → 4 → 24 s TTL.
func (c *Client) markEndpoint429(endpointIdx int) {
	c.markEndpointFailureWith(endpointIdx, 3)
}

// markEndpointHardFailure is used when classifyRelayErrorBody identifies a quota
// or auth error inside an HTML/JSON error page (even when HTTP status was 200).
// Same backoff tier as markEndpoint403.
func (c *Client) markEndpointHardFailure(endpointIdx int) {
	c.markEndpointFailureWith(endpointIdx, 5)
}

// markEndpointFailureWith is the shared implementation. minFailCount is a floor
// applied before incrementing so callers can skip the slow 3-48 s ramp for
// failure classes known not to self-heal quickly (quota, auth, rate-limit).
// Pass 0 for the standard ramp.
func (c *Client) markEndpointFailureWith(endpointIdx, minFailCount int) {
	c.endpointMu.Lock()
	if endpointIdx < 0 || endpointIdx >= len(c.endpoints) {
		c.endpointMu.Unlock()
		return
	}
	ep := &c.endpoints[endpointIdx]
	wasHealthy := ep.failCount == 0
	if minFailCount > 0 && ep.failCount < minFailCount {
		ep.failCount = minFailCount
	}
	ep.failCount++
	ep.statsFail++
	ep.localNetworkOffline = false
	ttl := endpointBlacklistTTL(ep.failCount)
	ep.blacklistedTill = time.Now().Add(ttl)
	url := ep.url
	failCount := ep.failCount
	c.endpointMu.Unlock()
	// Only log on the healthy → blacklisted transition; subsequent failures
	// of an already-blacklisted endpoint would be log noise.
	if wasHealthy {
		log.Printf("[carrier] endpoint %s blacklisted for %s (still rotating across %d others)",
			shortScriptKey(url), ttl.Round(100*time.Millisecond), len(c.endpoints)-1)
	} else if failCount == 8 {
		// Notify once when an endpoint reaches hour-scale backoff so the operator
		// knows this deployment is likely quota-exhausted or dead.
		log.Printf("[carrier] endpoint %s repeatedly failing (%d consecutive); now at extended backoff (%s). Consider re-deploying that script.",
			shortScriptKey(url), failCount, ttl.Round(time.Second))
	}
}

func endpointBlacklistTTL(failCount int) time.Duration {
	if failCount <= 0 {
		return 0
	}
	if failCount <= 5 {
		return endpointBlacklistBaseTTL << (failCount - 1)
	}
	switch failCount {
	case 6:
		return 5 * time.Minute
	case 7:
		return 30 * time.Minute
	default:
		return endpointBlacklistMaxTTL
	}
}

func (c *Client) drainAll() ([]*frame.Frame, [][frame.SessionIDLen]byte, map[[frame.SessionIDLen]byte]*session.DrainSnapshot) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []*frame.Frame
	var drainedIDs [][frame.SessionIDLen]byte
	snaps := map[[frame.SessionIDLen]byte]*session.DrainSnapshot{}
	batchCap := maxDrainFramesPerBatch
	if len(c.sessions) >= busySessionThreshold {
		batchCap = maxDrainFramesPerBatchBusy
	}
	remaining := batchCap

	// Snapshot and sort active sessions by queue age to ensure fairness.
	type sessionRef struct {
		id       [frame.SessionIDLen]byte
		queuedAt time.Time
	}
	refs := make([]sessionRef, 0, len(c.txReady))
	for id := range c.txReady {
		if s, ok := c.sessions[id]; ok {
			refs = append(refs, sessionRef{id: id, queuedAt: s.FirstQueuedAt()})
		} else {
			delete(c.txReady, id)
		}
	}
	sort.Slice(refs, func(i, j int) bool {
		return refs[i].queuedAt.Before(refs[j].queuedAt)
	})

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
		frames, snap := s.DrainTxLimitedTxn(MaxFramePayload, perSessionCap)
		delete(c.txReady, id) // remove now; OnTx re-adds if more data arrives
		if len(frames) == 0 {
			return
		}
		c.inFlight[id] = true
		drainedIDs = append(drainedIDs, id)
		if snap != nil {
			snaps[id] = snap
		}
		out = append(out, frames...)
		remaining -= len(frames)
	}

	// First pass: SYN sessions only. New connections claim batch slots before
	// ongoing data transfers so a large upload/download cannot push SYN frames
	// out of the batch and delay connection setup by a full poll cycle.
	for _, r := range refs {
		drain(r.id, true)
	}
	// Second pass: remaining data sessions.
	for _, r := range refs {
		drain(r.id, false)
	}
	return out, drainedIDs, snaps
}

// rollbackDrained restores every session named in snaps to its pre-drain
// state. Used on failure paths where the batch never reached the exit server
// (transport error, Apps Script rejection, etc.) so the SYN/payload can be
// retransmitted on the next poll instead of being silently lost.
func (c *Client) rollbackDrained(snaps map[[frame.SessionIDLen]byte]*session.DrainSnapshot) {
	if len(snaps) == 0 {
		return
	}
	c.mu.Lock()
	type pending struct {
		s    *session.Session
		snap *session.DrainSnapshot
	}
	out := make([]pending, 0, len(snaps))
	for id, snap := range snaps {
		if s, ok := c.sessions[id]; ok {
			out = append(out, pending{s: s, snap: snap})
		}
	}
	c.mu.Unlock()
	for _, p := range out {
		p.s.RollbackDrain(p.snap)
	}
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
//
// When adaptive coalescing is enabled (coalesceStep > 0) kicks within a
// burst are collapsed into a single delayed wake: the first kick arms a
// step-ms timer and records a hard deadline (now + coalesceMax); subsequent
// kicks reset the step timer (capped at the hard deadline) so a steady
// stream of arrivals does not delay the wake past coalesceMax. When step
// is 0 the wake fires immediately as before.
func (c *Client) kick() {
	if c.coalesceStep <= 0 {
		c.wake.Broadcast()
		return
	}

	c.coalesceMu.Lock()
	defer c.coalesceMu.Unlock()

	now := time.Now()
	if c.coalesceTimer == nil {
		// First kick of a burst: set hard deadline and arm the step timer.
		c.coalesceDeadline = now.Add(c.coalesceMax)
		c.coalesceTimer = time.AfterFunc(c.coalesceStep, c.fireCoalesceWake)
		return
	}

	// Subsequent kick: extend the step timer, but never past the hard cap.
	nextFire := now.Add(c.coalesceStep)
	if nextFire.After(c.coalesceDeadline) {
		nextFire = c.coalesceDeadline
	}
	wait := nextFire.Sub(now)
	if wait <= 0 {
		// Already at or past the hard deadline — let the existing timer fire.
		return
	}
	c.coalesceTimer.Reset(wait)
}

// fireCoalesceWake clears the timer and broadcasts the wake. Called from
// the time.AfterFunc goroutine when the coalesce window closes.
func (c *Client) fireCoalesceWake() {
	c.coalesceMu.Lock()
	c.coalesceTimer = nil
	c.coalesceMu.Unlock()
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

// classifyRelayErrorBody inspects a non-batch response body (HTML or JSON error
// page returned by Apps Script instead of an encrypted payload) and returns a
// human-readable explanation and whether the failure is "hard" (quota / auth /
// admin — won't self-heal in seconds) or "soft" (transient Google-side error).
//
// Pattern tables are ported from MasterHttpRelayVPN relay_response.py and cover
// the error categories documented at:
//
//	developers.google.com/apps-script/guides/support/troubleshooting
//	developers.google.com/apps-script/guides/services/quotas
func classifyRelayErrorBody(body []byte) (reason string, hard bool) {
	lower := strings.ToLower(string(bytes.TrimSpace(body)))

	// ── Quota / rate-limit ─────────────────────────────────────────────────
	// "Service invoked too many times for one day: urlfetch."
	// "Bandwidth quota exceeded"
	quotaPatterns := []string{
		"service invoked too many times",
		"invoked too many times",
		"bandwidth quota exceeded",
		"too much upload bandwidth",
		"too much traffic",
		"urlfetch",
		"quota",
		"exceeded",
		"daily",
		"rate limit",
	}
	for _, p := range quotaPatterns {
		if strings.Contains(lower, p) {
			return "Apps Script quota exhausted (20k requests/day limit) — " +
				"wait up to 24h for the quota to reset at midnight Pacific, " +
				"or deploy Code.gs under a second Google account and add it to script_keys", true
		}
	}

	// ── Auth / permission ──────────────────────────────────────────────────
	// "Authorization is required to perform that action."
	authPatterns := []string{
		"authorization is required",
		"unauthorized",
		"not authorized",
		"permission denied",
		"access denied",
	}
	for _, p := range authPatterns {
		if strings.Contains(lower, p) {
			return "Apps Script auth error — check: (1) AES key matches on both sides, " +
				"(2) deployment is set to 'Execute as: Me / Anyone can access', " +
				"(3) script_keys uses the Deployment ID (not the Script ID), " +
				"(4) the owning Google account has authorised the script by running it manually", true
		}
	}

	// ── Deployment not found ───────────────────────────────────────────────
	// "Error occurred due to a missing library version or a deployment version.
	//  Error code Not_Found"
	deployPatterns := []string{
		"error code not_found",
		"not_found",
		"deployment",
		"script id",
		"scriptid",
		"no script",
	}
	for _, p := range deployPatterns {
		if strings.Contains(lower, p) {
			return "Apps Script deployment not found — verify script_keys is the Deployment ID " +
				"(not the Script ID), the deployment is active, and you re-deployed after editing Code.gs", true
		}
	}

	// ── Admin / Workspace policy ───────────────────────────────────────────
	// "UrlFetch calls to <URL> are not permitted by your admin"
	adminPatterns := []string{
		"not permitted by your admin",
		"contact your administrator",
		"disabled. please contact",
		"domain policy has disabled",
		"administrator to enable",
	}
	for _, p := range adminPatterns {
		if strings.Contains(lower, p) {
			return "Apps Script blocked by a Google Workspace admin policy — " +
				"either the target URL is not on the admin's UrlFetch allowlist " +
				"or a required Google service has been disabled by the domain admin", true
		}
	}

	// ── Transient Google-side errors ───────────────────────────────────────
	// "Server not available." / "Server error occurred, please try again."
	transientPatterns := []string{
		"server not available",
		"server error occurred",
		"please try again",
		"temporarily unavailable",
	}
	for _, p := range transientPatterns {
		if strings.Contains(lower, p) {
			return "Google Apps Script server temporarily unavailable — will retry", false
		}
	}

	return "", false
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
