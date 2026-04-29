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

	// pollIdleSleepHot is the abbreviated breather used when activity was
	// observed within pollHotWindow. While hot, downstream data is likely to
	// arrive any moment, so we want to spend more time inside long-polls and
	// less time in the gap between them. 5 ms is short enough to be invisible
	// to interactive users yet large enough that an idle worker does not
	// busy-spin against the kernel scheduler.
	pollIdleSleepHot = 5 * time.Millisecond

	// pollHotWindow is how long after the last activity event we keep using
	// the abbreviated sleep. 500 ms covers typical interactive bursts (TLS
	// handshakes, REST request/reply pairs) without keeping a fully-idle
	// tunnel hot indefinitely.
	pollHotWindow = 500 * time.Millisecond

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
	//
	// Cap reduced from 1h to 5m after the production cascade observed on
	// 2026-04-29: a per-source-IP throttle at Google's edge made both Apps
	// Script deployments return HTML interstitials simultaneously, which the
	// previous 1h cap turned into a self-pinning DoS — every fail rolled the
	// blacklist deadline forward another hour. With a 5m cap, plus monotonic
	// blacklist updates and worker-sleep-until-expiry below, a transient
	// throttle clears within ~5 minutes instead of forcing the user to wait
	// out the full hour-long backoff.
	endpointBlacklistBaseTTL = 3 * time.Second
	endpointBlacklistMaxTTL  = 5 * time.Minute
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
	statsOK         uint64
	statsFail       uint64

	// ewmaRTT is the exponentially-weighted moving average of recent
	// successful poll latencies. Used by power-of-two-choices endpoint
	// selection so the fastest healthy endpoint receives more traffic
	// without starving alternates entirely.
	ewmaRTT     time.Duration
	lastSuccess time.Time
	firstFail   time.Time // when the most recent failure streak began

	// loggedNonBatchSnippetAt rate-limits the diagnostic body-snippet
	// log so a sustained failure stream produces at most one snippet
	// per loggedNonBatchSnippetCooldown — enough to identify the root
	// cause (quota page, SSO interstitial, dead deployment) without
	// flooding the log with the same snippet thousands of times.
	loggedNonBatchSnippetAt time.Time
}

// loggedNonBatchSnippetCooldown is how long an endpoint waits before logging
// another body snippet. Operators want to see what changed (e.g. throttle
// page → quota page) without log spam.
const loggedNonBatchSnippetCooldown = 30 * time.Second

// workersPerEndpoint is the number of concurrent poll goroutines spawned for
// each configured script URL. Total workers = workersPerEndpoint × len(endpoints).
// Scaling with endpoint count means adding more deployment IDs increases
// parallelism rather than just spreading the same fixed pool thinner.
const workersPerEndpoint = 3

// ewmaRTTAlpha is the smoothing constant for the per-endpoint RTT EWMA.
// 0.2 = recent samples are 20% of the new average; older samples decay over
// ~5 polls. Aggressive enough to react to deployment-region quota churn
// (Apps Script quotas reset on hourly windows) without being noisy.
const ewmaRTTAlpha = 0.2

// permanentDisableAfter is how long an endpoint can be in continuous failure
// before we stop probing it entirely. Past this point we have very strong
// evidence the deployment is dead/misconfigured and the per-failure backoff
// already maxes out at endpointBlacklistMaxTTL anyway.
const permanentDisableAfter = 24 * time.Hour

// noEligibleEndpointSleep bounds how long a worker waits between checks for
// an eligible endpoint when *all* endpoints are blacklisted, so a recovering
// endpoint is detected within this window even if its scheduled blacklist
// deadline lies much further out. Keeps recovery interactive without
// hammering throttled endpoints.
const noEligibleEndpointSleep = 30 * time.Second

// waker is a broadcast notifier: Broadcast() wakes all goroutines currently
// blocked on C() simultaneously, unlike a buffered chan which only wakes one.
//
// Generation counter eliminates the subtle wake-race: a worker that calls
// Generation() before pollOnce, then Broadcast() fires while the poll is
// in-flight, must short-circuit the subsequent wait so the new event is not
// lost. Without the counter, the previous design captured the wake channel
// after the drain returned empty, allowing a Broadcast that fired during the
// drain to be missed entirely — causing up to pollIdleSleep dead air on a
// freshly-arriving SYN.
type waker struct {
	mu  sync.Mutex
	ch  chan struct{}
	gen atomic.Uint64
}

func newWaker() *waker { return &waker{ch: make(chan struct{})} }

// snapshot captures the current channel and generation. Workers should call
// this *before* draining work so that any Broadcast fired during the drain
// bumps the generation and the subsequent wait can return immediately.
func (w *waker) snapshot() (<-chan struct{}, uint64) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.ch, w.gen.Load()
}

// generation returns just the current generation counter without taking the
// mutex. Used by waiters to detect whether a Broadcast happened since the
// snapshot.
func (w *waker) generation() uint64 { return w.gen.Load() }

// Broadcast unblocks all goroutines currently waiting on the snapshot channel
// and bumps the generation counter.
func (w *waker) Broadcast() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.gen.Add(1)
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
	numWorkers  int // workersPerEndpoint × len(endpoints)

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

	// drainCursor rotates the start of the txReady iteration order so no
	// session is permanently starved when the batch cap is hit on every
	// drain.
	drainCursor uint64

	idlePollMu       sync.Mutex
	idlePollInFlight int

	wake    *waker // broadcasts to all idle poll goroutines simultaneously
	stats   clientStats
	pollRTT pollRTTHistogram

	// lastActivityNanos is the UnixNano timestamp of the most recent event
	// that suggests downstream data may be on the way: a session creation,
	// a TX frame queued by an upstream caller, or a non-empty poll response.
	// runWorker reads it to decide whether to use the long pollIdleSleep
	// (cold) or a much shorter wakeup interval (hot) between polls.
	lastActivityNanos atomic.Int64
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
		numWorkers:  workersPerEndpoint * len(endpoints),
		sessions:    make(map[[frame.SessionIDLen]byte]*session.Session),
		inFlight:    make(map[[frame.SessionIDLen]byte]bool),
		txReady:     make(map[[frame.SessionIDLen]byte]struct{}),
		endpoints:   endpoints,
		wake:        newWaker(),
	}, nil
}

// NewSession creates a tunneled session for target ("host:port") and registers
// it with the long-poll loop. Returns the session for the caller (typically
// the SOCKS adapter) to wrap in a VirtualConn. Returns nil if crypto/rand
// fails — the SOCKS adapter must check and refuse the connection cleanly
// instead of crashing the process (a panic here would kill the whole
// listener for what may be a transient resource exhaustion).
func (c *Client) NewSession(target string) *session.Session {
	var id [frame.SessionIDLen]byte
	if _, err := rand.Read(id[:]); err != nil {
		log.Printf("[carrier] crypto/rand failed for session id: %v — refusing connection", err)
		return nil
	}
	s := session.New(id, target, true)
	s.SetOnTx(func() {
		c.mu.Lock()
		c.txReady[id] = struct{}{}
		c.mu.Unlock()
		c.markActivity()
		c.kick()
	})
	c.mu.Lock()
	c.sessions[id] = s
	c.txReady[id] = struct{}{} // SYN is pending immediately on creation
	c.mu.Unlock()
	c.stats.sessionsOpen.Add(1)
	if c.debugTiming {
		c.debugStarts.Store(id, time.Now())
	}
	c.markActivity()
	c.kick()
	return s
}

// markActivity records that something happened that suggests we should
// stay hot for a short while: a new session was opened, a TX frame was
// queued by an upstream goroutine, or a poll just returned non-empty.
// Reads in runWorker are unsynchronized vs writes here — a slightly stale
// read just biases the next sleep one way or the other; correctness is
// not affected.
func (c *Client) markActivity() {
	c.lastActivityNanos.Store(time.Now().UnixNano())
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

	body, err := frame.EncodeBatch(c.aead, rsts)
	if err != nil {
		log.Printf("[carrier] shutdown: encode failed: %v", err)
		return
	}

	// Shutdown is best-effort: try each endpoint in order, ignoring
	// blacklist state, until one accepts the RST batch. We deliberately
	// bypass pickRelayEndpoint() here because every endpoint may be
	// blacklisted (this is exactly the production scenario that triggered
	// the cascade) and the server's idle GC is the safety net if all
	// sends fail.
	c.endpointMu.Lock()
	urls := make([]string, len(c.endpoints))
	for i, e := range c.endpoints {
		urls[i] = e.url
	}
	c.endpointMu.Unlock()
	if len(urls) == 0 {
		return
	}

	log.Printf("[carrier] shutdown: sending RST for %d active sessions", len(rsts))
	for _, scriptURL := range urls {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, scriptURL, bytes.NewReader(body))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "text/plain")
		resp, err := c.pickHTTPClient().Do(req)
		if err != nil {
			log.Printf("[carrier] shutdown: send via %s failed: %v", shortScriptKey(scriptURL), err)
			continue
		}
		_ = resp.Body.Close()
		return // first success wins
	}
	log.Printf("[carrier] shutdown: all %d endpoints failed (server idle GC will clean up)", len(urls))
}

// prewarmEndpoints fires one short-deadline HEAD per endpoint in parallel so
// the TCP+TLS+HTTP/2 stack to each Google PoP is warm before the first
// user-visible poll. Without this, the very first SOCKS connection after
// `goose-client` boot pays the full cold-handshake cost (~150 ms RTT over a
// residential connection to the nearest GFE), which the user feels as a
// sluggish first click.
//
// HEAD is critical here: a POST with an empty body would be treated by the
// exit server as a normal idle poll and held for LongPollWindow seconds,
// during which the prewarm goroutine could win a race with a real poll
// worker for downstream data drained from a session — and then discard it.
// The exit server short-circuits non-POST methods to 405 (and Apps Script
// has no doHead handler so it falls through similarly), so HEAD returns
// immediately while still leaving a hot conn in the keep-alive pool.
//
// Best-effort: failures are logged but not surfaced. The warmup goroutine
// also exits cleanly if ctx is canceled before the dials complete.
func (c *Client) prewarmEndpoints(ctx context.Context) {
	c.endpointMu.Lock()
	urls := make([]string, len(c.endpoints))
	for i, e := range c.endpoints {
		urls[i] = e.url
	}
	c.endpointMu.Unlock()
	for _, scriptURL := range urls {
		go func(u string) {
			pctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			req, err := http.NewRequestWithContext(pctx, http.MethodHead, u, nil)
			if err != nil {
				return
			}
			resp, err := c.pickHTTPClient().Do(req)
			if err != nil {
				if c.debugTiming {
					log.Printf("[carrier] prewarm %s failed: %v", shortScriptKey(u), err)
				}
				return
			}
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4*1024))
			_ = resp.Body.Close()
			if c.debugTiming {
				log.Printf("[carrier] prewarm %s status=%d", shortScriptKey(u), resp.StatusCode)
			}
		}(scriptURL)
	}
}

// Run spawns c.numWorkers concurrent poll goroutines and blocks until ctx is
// canceled. Worker count scales with the number of configured endpoints so that
// adding more script URLs increases parallelism rather than spreading the same
// fixed pool thinner.
func (c *Client) Run(ctx context.Context) error {
	c.prewarmEndpoints(ctx)
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
		// Snapshot the waker BEFORE doing work. If Broadcast() fires while
		// pollOnce/drainAll is in flight, the generation counter advances and
		// the subsequent wait detects "work happened during my drain, skip
		// sleeping" — closing the wake-channel race that previously caused
		// up to pollIdleSleep (50 ms) of dead air on freshly-arriving SYN.
		wakeCh, genBefore := c.wake.snapshot()
		didWork := c.pollOnce(ctx)
		c.gcDoneSessions()
		if !didWork {
			if c.wake.generation() != genBefore {
				// Broadcast fired during pollOnce — loop immediately so we
				// don't sit on pollIdleSleep with new data already queued.
				continue
			}
			sleep := pollIdleSleep
			if last := c.lastActivityNanos.Load(); last != 0 &&
				time.Since(time.Unix(0, last)) < pollHotWindow {
				// Recent activity: cycle back into the long-poll quickly so a
				// downstream byte cannot be stranded for a full 50 ms in the
				// gap between polls. The wake-channel still short-circuits
				// this when an OnTx callback fires.
				sleep = pollIdleSleepHot
			}
			// If every endpoint is blacklisted, sleep until the soonest
			// blacklist expires (capped at noEligibleEndpointSleep). Without
			// this, six workers would spin in a tight loop calling
			// pickRelayEndpoint() → (-1, "") → returning false from pollOnce
			// → sleeping pollIdleSleep (50ms) → looping again. That's the
			// CPU-burn / log-spam side of the production cascade. With this
			// branch, the loop quiesces to one wake every 30s (or earlier on
			// session activity / blacklist expiry).
			if soonest := c.earliestEligibleAt(); !soonest.IsZero() {
				wait := time.Until(soonest)
				if wait > noEligibleEndpointSleep {
					wait = noEligibleEndpointSleep
				}
				if wait > sleep {
					sleep = wait
				}
			}
			select {
			case <-ctx.Done():
				return
			case <-wakeCh:
				// woken by new session data
			case <-time.After(sleep):
			}
		}
	}
}

// pollOnce drains pending tx frames, POSTs them as a batch, and routes any
// response frames back to their sessions. Returns true if any work was done
// (frames sent or received) so the Run loop can decide whether to sleep.
func (c *Client) pollOnce(ctx context.Context) bool {
	// Check endpoint eligibility BEFORE draining frames. If every endpoint
	// is blacklisted, return immediately without popping frames out of
	// session tx queues — they'd be lost (no requeue path back into the
	// session's per-stream sequence ordering). Frames stay in the session's
	// txBuf and get drained next time an endpoint recovers.
	//
	// This is also the gate that quiesces the worker loop during a
	// throttle event: pollOnce returns false → runWorker sees nothing
	// eligible → sleeps until earliestEligibleAt() instead of spinning.
	endpointIdx, scriptURL, eligibleCount := c.pickRelayEndpointWithEligibility()
	if endpointIdx < 0 || scriptURL == "" {
		if len(c.endpoints) == 0 {
			log.Printf("[carrier] no relay script URLs are configured")
		}
		return false
	}

	frames, drainedIDs := c.drainAll()
	if len(drainedIDs) > 0 {
		defer c.releaseInFlight(drainedIDs)
	}
	isIdlePoll := len(frames) == 0
	if isIdlePoll {
		// Allow one idle long-poll slot per endpoint so each deployment can push
		// downstream data concurrently. In pure-download mode (no pending TX)
		// raise the cap to numWorkers-1 so most workers are long-polling for
		// higher bulk throughput, reserving one for any TX that arrives.
		c.mu.Lock()
		idleCap := len(c.endpoints)
		if len(c.txReady) == 0 {
			idleCap = c.numWorkers - 1
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
	if eligibleCount > 1 {
		// Same-poll alternate-script failover only makes sense when there's
		// at least one OTHER eligible endpoint to fall back to. Retrying onto
		// a blacklisted endpoint just compounds the failure cascade without
		// any chance of success.
		maxAttempts = 2
	}

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		if attempt > 1 {
			endpointIdx, scriptURL = c.pickRelayEndpoint()
			if endpointIdx < 0 || scriptURL == "" {
				// Alternate became blacklisted between attempts; bail.
				return false
			}
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, scriptURL, bytes.NewReader(body))
		if err != nil {
			log.Printf("[carrier] failed to build relay request: %v", err)
			return false
		}
		req.Header.Set("Content-Type", "text/plain")
		attempted = true

		pollStart := time.Now()
		resp, err := c.pickHTTPClient().Do(req)
		// Per-poll RTT is always captured (cost: 2 time.Now calls). Used by
		// EWMA endpoint health → power-of-two-choices selection. Debug logs
		// also surface it when DebugTiming is on.
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

		// LimitReader caps the response body so a misbehaving relay (HTML error
		// page from a quota-exhausted Apps Script deployment, gateway timeouts,
		// etc.) cannot OOM the carrier. The cap is the same value we already
		// log-and-drop on (maxRelayResponseBodyBytes) — reading past that point
		// is wasted work because we discard the result anyway.
		respBody, readErr := io.ReadAll(io.LimitReader(resp.Body, maxRelayResponseBodyBytes+1))
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
			c.markEndpointSuccessRTT(endpointIdx, time.Since(pollStart))
			c.recordPollRTT(time.Since(pollStart))
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
			// On the healthy → non-batch transition, log a snippet of the
			// actual response body so the operator can identify whether it's
			// an Apps Script quota page, a Google interstitial, an
			// "unauthorized" SSO redirect, or a misdeployed script. Without
			// this, the only signal was "(likely HTML/JSON error page)" which
			// gives the operator zero diagnostic data.
			c.maybeLogRelayBodySnippet(endpointIdx, scriptURL, respBody)
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
		rtt := time.Since(pollStart)
		c.markEndpointSuccessRTT(endpointIdx, rtt)
		c.recordPollRTT(rtt)
		pollOK = true
		countFrameBytes(&c.stats.framesOut, &c.stats.bytesOut, frames)
		countFrameBytes(&c.stats.framesIn, &c.stats.bytesIn, rxFrames)
		if c.debugTiming {
			log.Printf("[timing] poll rtt=%dms tx_frames=%d rx_frames=%d resp_bytes=%d via %s",
				rtt.Milliseconds(), len(frames), len(rxFrames), len(respBody), shortScriptKey(scriptURL))
		}
		didWork := len(frames) > 0 || len(rxFrames) > 0
		if didWork {
			c.markActivity()
		}
		return didWork
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

// pickRelayEndpoint selects an eligible endpoint or returns (-1, "") if
// none are currently eligible (all blacklisted or permanently disabled).
//
// CRITICAL: never returns a blacklisted endpoint. The previous "pick whose
// backoff expires soonest as a last resort" fallback caused the 2026-04-29
// cascade — under a per-source-IP edge throttle, the fallback poll always
// failed, which compounded markEndpointFailure() and pinned both endpoints
// at 1h blacklist indefinitely. The caller is expected to treat (-1, "")
// as "sleep until earliestEligibleAt() returns a non-zero time".
func (c *Client) pickRelayEndpoint() (int, string) {
	idx, url, _ := c.pickRelayEndpointWithEligibility()
	return idx, url
}

// pickRelayEndpointWithEligibility is the same as pickRelayEndpoint but
// also returns the count of currently-eligible endpoints so the caller
// can decide whether the same-poll alternate-script retry (maxAttempts=2)
// is worth attempting. Retrying onto a blacklisted endpoint just compounds
// the cascade without any chance of success.
func (c *Client) pickRelayEndpointWithEligibility() (int, string, int) {
	c.endpointMu.Lock()
	defer c.endpointMu.Unlock()

	n := len(c.endpoints)
	if n == 0 {
		return -1, "", 0
	}
	now := time.Now()

	// Build the set of currently-eligible (non-blacklisted, not permanently
	// disabled) endpoints. Power-of-two-choices then samples two of them and
	// takes the lower-RTT one — a well-known load-balancing technique that
	// closely approximates the optimal "pick the fastest" without the
	// fairness pathologies of strict greedy selection (one endpoint hot,
	// others cold). On ties or no RTT data we fall back to round-robin
	// for backward-compatible behavior on first traffic.
	eligible := make([]int, 0, n)
	for i := 0; i < n; i++ {
		ep := &c.endpoints[i]
		if ep.blacklistedTill.After(now) {
			continue
		}
		if !ep.firstFail.IsZero() && now.Sub(ep.firstFail) > permanentDisableAfter && ep.lastSuccess.Before(ep.firstFail) {
			continue
		}
		eligible = append(eligible, i)
	}
	if len(eligible) == 0 {
		return -1, "", 0
	}
	if len(eligible) == 1 {
		idx := eligible[0]
		c.nextEndpoint = (idx + 1) % n
		return idx, c.endpoints[idx].url, 1
	}
	// Power-of-two-choices: random sample two distinct candidates and pick
	// whichever has the lower EWMA RTT. If neither has been measured yet
	// (cold start), fall back to round-robin so the very first polls fan out.
	a := eligible[c.nextEndpoint%len(eligible)]
	b := eligible[(c.nextEndpoint+1)%len(eligible)]
	if a == b {
		c.nextEndpoint = (a + 1) % n
		return a, c.endpoints[a].url, len(eligible)
	}
	rttA := c.endpoints[a].ewmaRTT
	rttB := c.endpoints[b].ewmaRTT
	var chosen int
	switch {
	case rttA == 0 && rttB == 0:
		chosen = a // both cold; round-robin order picks 'a'
	case rttA == 0:
		chosen = a // give untested endpoints a chance to be measured
	case rttB == 0:
		chosen = b
	case rttA <= rttB:
		chosen = a
	default:
		chosen = b
	}
	c.nextEndpoint = (chosen + 1) % n
	return chosen, c.endpoints[chosen].url, len(eligible)
}

// earliestEligibleAt returns the earliest time at which at least one
// endpoint will become eligible again, or the zero time if any endpoint is
// already eligible. Permanently-disabled endpoints are skipped — if every
// endpoint is permanently disabled, returns the zero time too (the caller
// will keep sleeping at the bounded ceiling rather than block forever).
func (c *Client) earliestEligibleAt() time.Time {
	c.endpointMu.Lock()
	defer c.endpointMu.Unlock()
	now := time.Now()
	var soonest time.Time
	for i := range c.endpoints {
		ep := &c.endpoints[i]
		if !ep.firstFail.IsZero() && now.Sub(ep.firstFail) > permanentDisableAfter && ep.lastSuccess.Before(ep.firstFail) {
			continue
		}
		if !ep.blacklistedTill.After(now) {
			return time.Time{}
		}
		if soonest.IsZero() || ep.blacklistedTill.Before(soonest) {
			soonest = ep.blacklistedTill
		}
	}
	return soonest
}

// markEndpointSuccessRTT records a success and updates the per-endpoint
// EWMA RTT used by power-of-two-choices selection. rtt may be zero (e.g.
// from a non-poll path) in which case only the success counters update.
func (c *Client) markEndpointSuccessRTT(endpointIdx int, rtt time.Duration) {
	c.endpointMu.Lock()
	if endpointIdx < 0 || endpointIdx >= len(c.endpoints) {
		c.endpointMu.Unlock()
		return
	}
	ep := &c.endpoints[endpointIdx]
	wasFailing := ep.failCount > 0
	ep.statsOK++
	ep.lastSuccess = time.Now()
	ep.firstFail = time.Time{}
	url := ep.url
	ep.failCount = 0
	ep.blacklistedTill = time.Time{}
	if rtt > 0 {
		if ep.ewmaRTT == 0 {
			ep.ewmaRTT = rtt
		} else {
			// EWMA: new = α*sample + (1-α)*old
			ep.ewmaRTT = time.Duration(float64(rtt)*ewmaRTTAlpha + float64(ep.ewmaRTT)*(1.0-ewmaRTTAlpha))
		}
	}
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
	now := time.Now()
	wasHealthy := ep.failCount == 0
	ep.failCount++
	ep.statsFail++
	if ep.firstFail.IsZero() {
		ep.firstFail = now
	}
	// Monotonic blacklist: only extend the deadline forward. Without this,
	// every fail rolled the deadline to now+ttl, so any worker that polled a
	// blacklisted endpoint pinned it at the max TTL indefinitely. With
	// pickRelayEndpoint() now refusing to return blacklisted endpoints, this
	// is also defense-in-depth against future regressions that re-introduce
	// the fallback.
	ttl := endpointBlacklistTTL(ep.failCount)
	newDeadline := now.Add(ttl)
	if newDeadline.After(ep.blacklistedTill) {
		ep.blacklistedTill = newDeadline
	}
	url := ep.url
	failCount := ep.failCount
	c.endpointMu.Unlock()
	// Only log on the healthy → blacklisted transition; subsequent failures
	// of an already-blacklisted endpoint would be log noise.
	if wasHealthy {
		log.Printf("[carrier] endpoint %s blacklisted for %s (still rotating across %d others)",
			shortScriptKey(url), ttl.Round(100*time.Millisecond), len(c.endpoints)-1)
	} else if failCount == 8 {
		// Notify once when an endpoint repeatedly hits the max-cap backoff so
		// the operator knows this deployment is likely quota-exhausted or dead.
		log.Printf("[carrier] endpoint %s repeatedly failing (%d consecutive); now at capped backoff (%s). Consider re-deploying that script or checking source-IP rate limits at Google's edge.",
			shortScriptKey(url), failCount, ttl.Round(time.Second))
	}
}

func endpointBlacklistTTL(failCount int) time.Duration {
	if failCount <= 0 {
		return 0
	}
	if failCount <= 5 {
		ttl := endpointBlacklistBaseTTL << (failCount - 1)
		if ttl > endpointBlacklistMaxTTL {
			return endpointBlacklistMaxTTL
		}
		return ttl
	}
	// failCount=6+: cap at endpointBlacklistMaxTTL (5 min). Faster
	// recovery from transient per-source-IP throttles than the previous
	// 30min/1h ramp, which turned a 5-minute Apps Script throttle into
	// an hour of degraded service.
	return endpointBlacklistMaxTTL
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

	// Snapshot keys + sort/rotate to ensure round-robin fairness across
	// drains. Map iteration order in Go is randomised per range loop, which
	// already provides some fairness, but does not give *progress* guarantees:
	// a session that always lands at the back can be starved on every batch
	// when the batch cap is hit. Cursor-based round-robin gives every session
	// a fair shot at the front position.
	ids := make([][frame.SessionIDLen]byte, 0, len(c.txReady))
	for id := range c.txReady {
		ids = append(ids, id)
	}
	if len(ids) > 0 && c.drainCursor < uint64(len(ids)) {
		start := int(c.drainCursor % uint64(len(ids)))
		if start > 0 {
			ids = append(ids[start:], ids[:start]...)
		}
	}
	c.drainCursor++

	// First pass: SYN sessions only. New connections claim batch slots before
	// ongoing data transfers so a large upload/download cannot push SYN frames
	// out of the batch and delay connection setup by a full poll cycle.
	for _, id := range ids {
		drain(id, true)
	}
	// Second pass: remaining data sessions.
	for _, id := range ids {
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
	if !s.ProcessRx(f) {
		// Per-session inbox/queue exceeded its memory cap. Drop the session
		// locally; the rxOverflow flag is set so subsequent frames are dropped
		// silently. The SOCKS reader will see EOF on RxChan via the deliverRx
		// path closing it.
		log.Printf("[carrier] session %x rx-overflow, dropping locally", f.SessionID[:4])
		s.Stop()
		c.mu.Lock()
		delete(c.sessions, f.SessionID)
		delete(c.txReady, f.SessionID)
		c.mu.Unlock()
		c.stats.sessionsClose.Add(1)
	}
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

// maybeLogRelayBodySnippet logs the first ~200 chars of a non-batch
// response body to help the operator identify what Apps Script is actually
// returning (quota page vs SSO redirect vs dead deployment vs Google
// interstitial). Rate-limited per endpoint to avoid log flooding under
// sustained failure: at most one snippet per loggedNonBatchSnippetCooldown.
//
// Output is ASCII-clean (control chars stripped), so a binary blob doesn't
// trash the operator's terminal.
func (c *Client) maybeLogRelayBodySnippet(endpointIdx int, scriptURL string, body []byte) {
	c.endpointMu.Lock()
	if endpointIdx < 0 || endpointIdx >= len(c.endpoints) {
		c.endpointMu.Unlock()
		return
	}
	ep := &c.endpoints[endpointIdx]
	now := time.Now()
	if !ep.loggedNonBatchSnippetAt.IsZero() && now.Sub(ep.loggedNonBatchSnippetAt) < loggedNonBatchSnippetCooldown {
		c.endpointMu.Unlock()
		return
	}
	ep.loggedNonBatchSnippetAt = now
	c.endpointMu.Unlock()

	const maxLen = 200
	t := bytes.TrimSpace(body)
	if len(t) > maxLen {
		t = t[:maxLen]
	}
	out := make([]byte, 0, len(t)+3)
	for _, ch := range t {
		if ch < 0x20 || ch == 0x7f {
			out = append(out, ' ')
			continue
		}
		out = append(out, ch)
	}
	if len(body) > maxLen {
		out = append(out, '.', '.', '.')
	}
	log.Printf("[carrier] non-batch body via %s (%d bytes total): %s",
		shortScriptKey(scriptURL), len(body), string(out))
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
