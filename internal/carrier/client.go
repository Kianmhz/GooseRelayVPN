package carrier

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kianmhz/GooseRelayVPN/internal/frame"
	"github.com/kianmhz/GooseRelayVPN/internal/metrics"
	"github.com/kianmhz/GooseRelayVPN/internal/protocol"
	"github.com/kianmhz/GooseRelayVPN/internal/session"
)

const (
	// MaxFramePayload caps the bytes per frame; larger writes are chunked.
	// Raised from 128KB: single-seal means no per-frame crypto cost, so fewer
	// larger frames are strictly better (less length-prefix overhead, fewer
	// Unmarshal calls). Must match the value in internal/exit/exit.go.
	MaxFramePayload = protocol.MaxFramePayload

	// pollIdleSleep is the breather between polls when nothing is happening.
	// 10ms instead of 50ms: keeps workers responsive to kick() misses and
	// idle-slot retry at negligible CPU cost at true idle. Adaptive backoff
	// (see idleBackoff) extends this when consecutive polls return no work.
	pollIdleSleep = time.Duration(protocol.DefaultPollIdleSleepMs) * time.Millisecond

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

	sessionGCInterval = 15 * time.Second

	// maxDrainFramesPerSession keeps one busy session from monopolizing a poll
	// cycle when many short-lived sessions are active (e.g., chat apps).
	maxDrainFramesPerSession = 8

	// maxDrainFramesPerBatch bounds total frames sent in one poll request so
	// very high session fan-out does not create oversized POST bodies.
	maxDrainFramesPerBatch = protocol.MaxDrainFramesPerBatch

	// Under high fan-out (mobile apps opening many parallel connections), allow
	// a larger but still bounded batch to reduce queueing delay.
	busySessionThreshold       = protocol.BusySessionThreshold
	maxDrainFramesPerBatchBusy = protocol.MaxDrainFramesPerBatchBusy

	// Hard cap for one relay response body to avoid spending CPU/memory on
	// unexpectedly huge non-frame payloads (HTML error pages, quota pages, etc).
	maxRelayResponseBodyBytes = 32 * 1024 * 1024

	// Endpoint failure backoff to shed unhealthy deployments during quota spikes
	// or tail-latency events without changing protocol behavior.
	endpointBlacklistBaseTTL = time.Duration(protocol.DefaultEndpointBlacklistBaseMs) * time.Millisecond
	endpointBlacklistMaxTTL  = time.Duration(protocol.DefaultEndpointBlacklistMaxMs) * time.Millisecond
)

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
	TransportMode string   // auto, apps_script, direct_post, direct_stream

	// DirectStreamURLs are first-class VPS WebSocket endpoints. They are
	// direct-only; Apps Script cannot proxy persistent WebSocket connections.
	DirectStreamURLs []string

	// ScriptAccounts is an optional parallel slice to ScriptURLs labeling each
	// deployment with the Google account it lives under. When set, the periodic
	// stats line aggregates today/script counts by account so the operator can
	// see how much of each account's ~20k/day quota has been spent. nil or
	// shorter slices are tolerated; missing entries are treated as unlabeled.
	ScriptAccounts []string

	Fronting     FrontingConfig
	AESKeyHex    string // 64-char hex, must match server
	DebugTiming  bool   // when true, log per-session TTFB and per-poll Apps Script RTT
	UseFronting  bool   // Apps Script mode uses domain-fronted Google transports
	BinaryDirect bool   // direct relay_urls mode can skip base64 text bodies
	AutoTune     bool   // conservative runtime tuning within fixed latency-safe caps

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
	IdleSlotsPerBucket       int
	WorkersPerEndpoint       int
	PollIdleSleep            time.Duration
	EndpointBlacklistBaseTTL time.Duration
	EndpointBlacklistMaxTTL  time.Duration
	EndpointOutageGrace      time.Duration
	MaxRequestBytesPreEncode int
	StreamConnectTimeout     time.Duration
	StreamPingInterval       time.Duration
	StreamReconnectBackoff   time.Duration
}

type relayEndpoint struct {
	url             string
	account         string // optional human-readable Google account label, "" = unlabeled
	blacklistedTill time.Time
	failCount       int
	statsOK         uint64
	statsFail       uint64
	rttEWMA         time.Duration

	// Per-quota-window counters. dailyCount is the number of HTTP responses
	// received from Apps Script in the current window; dailyResetAt is the
	// next midnight Pacific (the boundary at which Apps Script resets the
	// per-account UrlFetch quota). Both are managed via touchDailyWindow.
	dailyCount          uint64
	dailyResetAt        time.Time
	quotaExhaustedUntil time.Time

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
const workersPerEndpoint = protocol.DefaultWorkersPerEndpoint

const (
	appsScriptDailyQuota       = 20000
	quotaRotateAwayPermille    = 850
	quotaScorePenaltyPerMille  = time.Millisecond
	endpointLoadPenaltyPerPoll = 5 * time.Millisecond
	maxActiveClientSessions    = 1024
	maxNewSessionsPerSecond    = 80
	sessionCreateBurst         = 160
)

const (
	transportModeAuto         = "auto"
	transportModeAppsScript   = "apps_script"
	transportModeDirectPost   = "direct_post"
	transportModeDirectStream = "direct_stream"
)

// waker is a broadcast notifier: Broadcast() wakes all goroutines currently
// blocked on C() simultaneously, unlike a buffered chan which only wakes one.
type waker struct {
	ch atomic.Pointer[chan struct{}]
}

func newWaker() *waker {
	w := &waker{}
	ch := make(chan struct{})
	w.ch.Store(&ch)
	return w
}

// C returns the current channel to select on. Must be captured before
// entering select so a concurrent Broadcast() cannot be missed.
func (w *waker) C() <-chan struct{} {
	return *w.ch.Load()
}

// Broadcast unblocks all goroutines currently waiting on C().
func (w *waker) Broadcast() {
	next := make(chan struct{})
	old := w.ch.Swap(&next)
	close(*old)
}

// Client owns the session map and the long-poll loop.
type Client struct {
	cfg                      Config
	aead                     *frame.Crypto
	httpClients              []*http.Client // one per SNI host; round-robined per request
	nextHTTP                 atomic.Uint64  // round-robin index into httpClients
	debugTiming              bool
	binaryDirect             bool
	autoTune                 bool
	transportMode            string
	directStreamURLs         []string
	streamConnectTimeout     time.Duration
	streamPingInterval       time.Duration
	streamReconnectBackoff   time.Duration
	streamActive             atomic.Bool
	numWorkers               int // (workersPerEndpoint + idleSlotsPerBucket - 1) × bucketCount
	bucketCount              int // distinct account labels in endpoints; unlabeled all share one bucket
	idleSlotsPerBucket       int // resolved from Config.IdleSlotsPerBucket, default 1
	pollIdleSleep            time.Duration
	endpointBlacklistBaseTTL time.Duration
	endpointBlacklistMaxTTL  time.Duration
	endpointOutageGrace      time.Duration
	endpointOutageStarted    time.Time
	maxRequestBytesPreEncode int
	clientVersion            string

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
	// txReadyOrder preserves first-ready order so drainAll does not sort the
	// ready map every poll. txReady remains the membership source of truth;
	// stale queue entries are compacted lazily after drains.
	txReadyOrder [][frame.SessionIDLen]byte

	sessionCreateTokens float64
	sessionCreateAt     time.Time

	endpointMu   sync.Mutex
	endpoints    []relayEndpoint
	nextEndpoint int

	idlePollInFlight atomic.Int32

	wake  *waker // broadcasts to all idle poll goroutines simultaneously
	stats clientStats

	// Adaptive kick coalescing (see Config.CoalesceStep/Max). When step <= 0
	// these fields are unused and kick() broadcasts immediately.
	coalesceStep     time.Duration
	coalesceMax      time.Duration
	coalesceMu       sync.Mutex
	coalesceTimer    *time.Timer // armed during a coalesce window; nil otherwise
	coalesceDeadline time.Time   // hard cap for the in-flight window
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
	streamOK      atomic.Uint64
	streamFail    atomic.Uint64
	streamDrops   atomic.Uint64
	postFallbacks atomic.Uint64

	ttfb        metrics.DurationWindow
	endpointRTT metrics.DurationWindow
	queueWait   metrics.DurationWindow
	encode      metrics.DurationWindow
	decode      metrics.DurationWindow
	reqSize     metrics.SizeBuckets
	respSize    metrics.SizeBuckets
	wireRatio   metrics.RatioBuckets
}

func dedupeEndpointStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

func buildRelayEndpoints(urls, accounts []string, preserve map[string]relayEndpoint) []relayEndpoint {
	endpoints := make([]relayEndpoint, 0, len(urls))
	seen := make(map[string]struct{}, len(urls))
	for i, raw := range urls {
		url := strings.TrimSpace(raw)
		if url == "" {
			continue
		}
		if _, ok := seen[url]; ok {
			continue
		}
		seen[url] = struct{}{}
		account := ""
		if i < len(accounts) {
			account = strings.TrimSpace(accounts[i])
		}
		ep, ok := preserve[url]
		if !ok {
			ep = relayEndpoint{url: url}
		}
		ep.url = url
		ep.account = account
		endpoints = append(endpoints, ep)
	}
	return endpoints
}

func endpointBucketStats(endpoints []relayEndpoint) (bucketCount int, labeled int) {
	accountSeen := make(map[string]struct{}, len(endpoints))
	for _, ep := range endpoints {
		accountSeen[ep.account] = struct{}{}
		if ep.account != "" {
			labeled++
		}
	}
	return len(accountSeen), labeled
}

func (c *Client) streamEnabled() bool {
	if len(c.directStreamURLs) == 0 {
		return false
	}
	return c.transportMode == transportModeAuto || c.transportMode == transportModeDirectStream
}

func (c *Client) postEnabled() bool {
	c.endpointMu.Lock()
	hasEndpoints := len(c.endpoints) > 0
	c.endpointMu.Unlock()
	if !hasEndpoints {
		return false
	}
	return c.transportMode == transportModeAuto ||
		c.transportMode == transportModeAppsScript ||
		c.transportMode == transportModeDirectPost
}

func (c *Client) relayEndpointCount() int {
	c.endpointMu.Lock()
	defer c.endpointMu.Unlock()
	return len(c.endpoints)
}

// New constructs a Client. The HTTP client is preconfigured for domain
// fronting per cfg.Fronting.
func New(cfg Config) (*Client, error) {
	aead, err := frame.NewCryptoFromHexKey(cfg.AESKeyHex)
	if err != nil {
		return nil, err
	}

	transportMode := strings.TrimSpace(strings.ToLower(cfg.TransportMode))
	if transportMode == "" {
		transportMode = transportModeAuto
	}
	switch transportMode {
	case transportModeAuto, transportModeAppsScript, transportModeDirectPost, transportModeDirectStream:
	default:
		return nil, fmt.Errorf("unknown transport mode %q", cfg.TransportMode)
	}

	endpoints := buildRelayEndpoints(cfg.ScriptURLs, cfg.ScriptAccounts, nil)
	directStreamURLs := dedupeEndpointStrings(cfg.DirectStreamURLs)
	if len(endpoints) == 0 && len(directStreamURLs) == 0 {
		return nil, fmt.Errorf("at least one relay endpoint or direct stream URL is required")
	}
	if transportMode == transportModeDirectStream && len(directStreamURLs) == 0 {
		return nil, fmt.Errorf("direct_stream transport requires at least one direct stream URL")
	}
	if transportMode == transportModeDirectPost && len(endpoints) == 0 {
		return nil, fmt.Errorf("direct_post transport requires at least one relay URL")
	}

	// Concurrency scales with distinct Google account "buckets", not endpoint
	// count. Apps Script's per-second concurrency cap and ~20k UrlFetchApp/day
	// quota are per-account: scaling workers/idle-slots by endpoint count
	// (pre-fix behavior) overloads users who deploy multiple IDs under one
	// account, causing Apps Script to return HTML error pages instead of the
	// encrypted batch (issue #56). Unlabeled endpoints all share one anonymous
	// bucket so legacy configs default to v1.2.0-equivalent load.
	bucketCount, labeled := endpointBucketStats(endpoints)
	if bucketCount <= 0 {
		bucketCount = 1
	}

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
	resolvedWorkersPerEndpoint := cfg.WorkersPerEndpoint
	if resolvedWorkersPerEndpoint <= 0 {
		resolvedWorkersPerEndpoint = workersPerEndpoint
	}
	resolvedPollIdleSleep := cfg.PollIdleSleep
	if resolvedPollIdleSleep <= 0 {
		resolvedPollIdleSleep = pollIdleSleep
	}
	resolvedBlacklistBaseTTL := cfg.EndpointBlacklistBaseTTL
	if resolvedBlacklistBaseTTL <= 0 {
		resolvedBlacklistBaseTTL = endpointBlacklistBaseTTL
	}
	resolvedBlacklistMaxTTL := cfg.EndpointBlacklistMaxTTL
	if resolvedBlacklistMaxTTL <= 0 {
		resolvedBlacklistMaxTTL = endpointBlacklistMaxTTL
	}
	if resolvedBlacklistMaxTTL < resolvedBlacklistBaseTTL {
		resolvedBlacklistMaxTTL = resolvedBlacklistBaseTTL
	}
	resolvedEndpointOutageGrace := cfg.EndpointOutageGrace
	if resolvedEndpointOutageGrace <= 0 {
		resolvedEndpointOutageGrace = time.Duration(protocol.DefaultEndpointOutageGraceMs) * time.Millisecond
	}
	resolvedMaxRequestBytesPreEncode := cfg.MaxRequestBytesPreEncode
	if resolvedMaxRequestBytesPreEncode <= 0 {
		resolvedMaxRequestBytesPreEncode = protocol.MaxRequestBytesPreEncode
	}
	resolvedStreamConnectTimeout := cfg.StreamConnectTimeout
	if resolvedStreamConnectTimeout <= 0 {
		resolvedStreamConnectTimeout = time.Duration(protocol.DefaultStreamConnectTimeoutMs) * time.Millisecond
	}
	resolvedStreamPingInterval := cfg.StreamPingInterval
	if resolvedStreamPingInterval <= 0 {
		resolvedStreamPingInterval = time.Duration(protocol.DefaultStreamPingIntervalMs) * time.Millisecond
	}
	resolvedStreamReconnectBackoff := cfg.StreamReconnectBackoff
	if resolvedStreamReconnectBackoff <= 0 {
		resolvedStreamReconnectBackoff = time.Duration(protocol.DefaultStreamReconnectBackoffMs) * time.Millisecond
	}
	// Worker count scales with idleSlotsPerBucket so the TX pool isn't
	// drained when the user opts up the RX cap. With workersPerEndpoint=3
	// and idleSlotsPerBucket=1, this reduces to the old 3×bucketCount.
	// At idleSlotsPerBucket=2, each bucket gets +1 worker so the same
	// number of workers stay free for TX after the extra idle slot is
	// camped — the alternative (fixed worker count) starves session
	// establishment under TX bursts when more workers are tied to long
	// polls.
	numWorkers := (resolvedWorkersPerEndpoint + idleSlotsPerBucket - 1) * bucketCount
	if transportMode == transportModeDirectStream || len(endpoints) == 0 {
		numWorkers = 0
	}
	log.Printf("[carrier] transport=%s stream_endpoints=%d post_workers=%d account_bucket(s)=%d post_endpoint(s)=%d idle_slot(s)/bucket=%d",
		transportMode, len(directStreamURLs), numWorkers, bucketCount, len(endpoints), idleSlotsPerBucket)
	if labeled == 0 && len(endpoints) > 1 {
		log.Printf("[carrier] WARN: %d deployments configured with no account labels — treating as one bucket. "+
			"If these deployments are under different Google accounts, label them in script_keys "+
			"as {\"id\": \"...\", \"account\": \"A\"} to unlock per-account parallelism.",
			len(endpoints))
	}

	httpClients := NewDirectClients(pollTimeout, resolvedWorkersPerEndpoint)
	if cfg.UseFronting && len(endpoints) > 0 {
		httpClients = NewFrontedClients(cfg.Fronting, pollTimeout, endpoints[0].url)
	}

	return &Client{
		cfg:                      cfg,
		aead:                     aead,
		httpClients:              httpClients,
		debugTiming:              cfg.DebugTiming,
		binaryDirect:             cfg.BinaryDirect,
		autoTune:                 cfg.AutoTune,
		transportMode:            transportMode,
		directStreamURLs:         directStreamURLs,
		streamConnectTimeout:     resolvedStreamConnectTimeout,
		streamPingInterval:       resolvedStreamPingInterval,
		streamReconnectBackoff:   resolvedStreamReconnectBackoff,
		numWorkers:               numWorkers,
		bucketCount:              bucketCount,
		idleSlotsPerBucket:       idleSlotsPerBucket,
		pollIdleSleep:            resolvedPollIdleSleep,
		endpointBlacklistBaseTTL: resolvedBlacklistBaseTTL,
		endpointBlacklistMaxTTL:  resolvedBlacklistMaxTTL,
		endpointOutageGrace:      resolvedEndpointOutageGrace,
		maxRequestBytesPreEncode: resolvedMaxRequestBytesPreEncode,
		clientVersion:            cfg.ClientVersion,
		clientID:                 clientID,
		sessions:                 make(map[[frame.SessionIDLen]byte]*session.Session),
		inFlight:                 make(map[[frame.SessionIDLen]byte]bool),
		txReady:                  make(map[[frame.SessionIDLen]byte]struct{}),
		endpoints:                endpoints,
		wake:                     newWaker(),
		coalesceStep:             cfg.CoalesceStep,
		coalesceMax:              cfg.CoalesceMax,
	}, nil
}

// UpdateEndpoints swaps the relay endpoint list at runtime. It preserves
// health/quota state for URLs that remain present and gives newly-added
// deployment IDs a clean slate so users can add a fresh account without
// restarting the client process.
func (c *Client) UpdateEndpoints(urls, accounts []string) int {
	c.endpointMu.Lock()
	preserve := make(map[string]relayEndpoint, len(c.endpoints))
	for _, ep := range c.endpoints {
		preserve[ep.url] = ep
	}
	next := buildRelayEndpoints(urls, accounts, preserve)
	if len(next) == 0 {
		c.endpointMu.Unlock()
		return len(c.endpoints)
	}
	c.endpoints = next
	if c.nextEndpoint >= len(c.endpoints) {
		c.nextEndpoint = 0
	}
	c.endpointMu.Unlock()

	bucketCount, _ := endpointBucketStats(next)
	if bucketCount <= 0 {
		bucketCount = 1
	}
	c.mu.Lock()
	c.bucketCount = bucketCount
	c.mu.Unlock()
	c.wake.Broadcast()
	return len(next)
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
		c.markTxReadyLocked(id)
		c.mu.Unlock()
		c.kick()
	}
	c.mu.Lock()
	if len(c.sessions) >= maxActiveClientSessions || !c.allowSessionCreateLocked(time.Now()) {
		c.mu.Unlock()
		log.Printf("[carrier] rejecting new session %x for %s: local session storm guard active", id[:4], target)
		s.Abort()
		return s
	}
	c.sessions[id] = s
	c.markTxReadyLocked(id) // SYN is pending immediately on creation
	c.mu.Unlock()
	c.stats.sessionsOpen.Add(1)
	c.debugStarts.Store(id, time.Now())
	c.kickUrgent()
	return s
}

func (c *Client) allowSessionCreateLocked(now time.Time) bool {
	if c.sessionCreateAt.IsZero() {
		c.sessionCreateAt = now
		c.sessionCreateTokens = sessionCreateBurst
	}
	elapsed := now.Sub(c.sessionCreateAt).Seconds()
	if elapsed > 0 {
		c.sessionCreateTokens += elapsed * maxNewSessionsPerSecond
		if c.sessionCreateTokens > sessionCreateBurst {
			c.sessionCreateTokens = sessionCreateBurst
		}
		c.sessionCreateAt = now
	}
	if c.sessionCreateTokens < 1 {
		return false
	}
	c.sessionCreateTokens--
	return true
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

	body, err := c.encodeBatch(rsts)
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
	req.Header.Set("Content-Type", c.requestContentType())

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
	if c.streamEnabled() {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.runStreamLoop(ctx)
		}()
	}
	if c.autoTune {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.runAutoTuneLoop(ctx)
		}()
	}
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
	wg.Add(1)
	go func() {
		defer wg.Done()
		c.runSessionGCLoop(ctx)
	}()
	// Hourly fetch of each deployment's self-reported invocation count.
	// Logged in the next [stats] line as `script=N` next to the existing
	// client-side `today=N` so the user sees both perspectives.
	wg.Add(1)
	go func() {
		defer wg.Done()
		c.runScriptStatsLoop(ctx)
	}()
	wg.Wait()
	return ctx.Err()
}

func (c *Client) runWorker(ctx context.Context) {
	consecutiveIdle := 0
	idleTimer := time.NewTimer(time.Hour)
	if !idleTimer.Stop() {
		<-idleTimer.C
	}
	defer idleTimer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		didWork := c.pollOnce(ctx)
		if c.closeSessionsIfAllEndpointsBlacklisted("all relay endpoints are temporarily unavailable") {
			consecutiveIdle = 0
			continue
		}
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
		resetTimer(idleTimer, c.idleBackoff(consecutiveIdle))
		select {
		case <-ctx.Done():
			return
		case <-wakeCh:
			stopTimer(idleTimer)
			consecutiveIdle = 0
		case <-idleTimer.C:
		}
	}
}

func stopTimer(t *time.Timer) {
	if !t.Stop() {
		select {
		case <-t.C:
		default:
		}
	}
}

func resetTimer(t *time.Timer, d time.Duration) {
	stopTimer(t)
	t.Reset(d)
}

// idleBackoff returns how long a worker should sleep after n consecutive
// no-work polls. The wake channel is selected against this timer so any
// new TX (kick) cancels the sleep immediately and any held server-side
// long-poll receives downstream chunks without needing a fresh poll —
// so even a 1s tail does not add user-visible latency.
func idleBackoff(n int) time.Duration {
	return idleBackoffWithBase(n, pollIdleSleep)
}

func (c *Client) idleBackoff(n int) time.Duration {
	c.mu.Lock()
	base := c.pollIdleSleep
	c.mu.Unlock()
	return idleBackoffWithBase(n, base)
}

func idleBackoffWithBase(n int, base time.Duration) time.Duration {
	switch {
	case n < 3:
		return base
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
	if c.streamActive.Load() || !c.postEnabled() {
		return false
	}
	if c.allEndpointsBlacklisted() {
		return false
	}
	frames, drainedIDs := c.drainAll()
	if len(drainedIDs) > 0 {
		defer c.releaseInFlight(drainedIDs)
	}
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
		noPendingTX := len(c.txReady) == 0
		c.mu.Unlock()
		availableBuckets := c.availableRelayBucketCount()
		if availableBuckets <= 0 {
			return false
		}
		idleCap := availableBuckets * c.idleSlotsPerBucket
		if noPendingTX && idleCap < pureDownloadIdleCap {
			idleCap = pureDownloadIdleCap
		}
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

	body, err := c.encodeBatch(frames)
	if err != nil {
		log.Printf("[carrier] failed to prepare encrypted request batch: %v", err)
		return c.failDrainedBatch(frames, drainedIDs, "failed to encode drained TX batch")
	}

	maxAttempts := 1
	endpointCount := c.relayEndpointCount()
	if endpointCount > 1 {
		// TX batches have already been drained out of session buffers. Try every
		// configured endpoint before giving up so one exhausted deployment (or
		// even several) cannot discard that payload while a later deployment is
		// still healthy. Idle polls keep the old single alternate attempt to avoid
		// burning quota across the whole fleet when there is no upstream payload
		// to preserve.
		if len(frames) > 0 {
			maxAttempts = endpointCount
		} else {
			maxAttempts = 2
		}
	}

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		endpointIdx, scriptURL := c.pickRelayEndpoint()
		if endpointIdx < 0 || scriptURL == "" {
			log.Printf("[carrier] no relay script URLs are configured")
			return c.failDrainedBatch(frames, drainedIDs, "no relay endpoints available after draining TX batch")
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, scriptURL, bytes.NewReader(body))
		if err != nil {
			log.Printf("[carrier] failed to build relay request: %v", err)
			return c.failDrainedBatch(frames, drainedIDs, "failed to build drained TX request")
		}
		req.Header.Set("Content-Type", c.requestContentType())
		attempted = true

		pollStart := time.Now()
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
			c.markEndpointFailure(endpointIdx)
			if attempt < maxAttempts {
				log.Printf("[carrier] relay request failed via %s (attempt %d/%d): %v; retrying alternate script", shortScriptKey(scriptURL), attempt, maxAttempts, err)
				continue
			}
			log.Printf("[carrier] relay request failed via %s: %v (check internet access, script_keys, and google_host)", shortScriptKey(scriptURL), err)
			c.sleepWithContext(ctx, time.Second)
			return c.failDrainedBatch(frames, drainedIDs, "all relay request attempts failed after draining TX batch")
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
			return c.failDrainedBatch(frames, drainedIDs, "failed to read relay response after draining TX batch")
		}

		if resp.StatusCode == http.StatusNoContent || len(respBody) == 0 {
			c.markEndpointSuccessWithRTT(endpointIdx, time.Since(pollStart), false)
			pollOK = true
			countFrameBytes(&c.stats.framesOut, &c.stats.bytesOut, frames)
			return len(frames) > 0
		}
		if resp.StatusCode != http.StatusOK {
			switch resp.StatusCode {
			case http.StatusForbidden: // 403
				c.markEndpointQuotaExhausted(endpointIdx)
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
			return c.failDrainedBatch(frames, drainedIDs, "relay returned terminal HTTP error after draining TX batch")
		}
		if len(respBody) > maxRelayResponseBodyBytes {
			c.markEndpointFailure(endpointIdx)
			if attempt < maxAttempts {
				log.Printf("[carrier] relay response too large via %s (attempt %d/%d); retrying alternate script", shortScriptKey(scriptURL), attempt, maxAttempts)
				continue
			}
			log.Printf("[carrier] relay response too large via %s (%d bytes > %d); dropping batch to protect stability", shortScriptKey(scriptURL), len(respBody), maxRelayResponseBodyBytes)
			return c.failDrainedBatch(frames, drainedIDs, "relay response too large after draining TX batch")
		}
		if !c.binaryDirect && isLikelyNonBatchRelayPayload(respBody) {
			errReason, errHard := classifyRelayErrorBody(respBody)
			if errHard {
				if strings.Contains(strings.ToLower(errReason), "quota") {
					c.markEndpointQuotaExhausted(endpointIdx)
				} else {
					c.markEndpointHardFailure(endpointIdx)
				}
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
			return c.failDrainedBatch(frames, drainedIDs, "relay returned non-batch payload after draining TX batch")
		}

		_, rxFrames, decodeErr := c.decodeBatch(respBody)
		if decodeErr != nil {
			c.markEndpointFailure(endpointIdx)
			if attempt < maxAttempts {
				log.Printf("[carrier] relay response was invalid via %s (attempt %d/%d): %v; retrying alternate script", shortScriptKey(scriptURL), attempt, maxAttempts, decodeErr)
				continue
			}
			log.Printf("[carrier] relay response was invalid via %s (possibly HTML/error page instead of encrypted data): %v", shortScriptKey(scriptURL), decodeErr)
			return c.failDrainedBatch(frames, drainedIDs, "relay returned invalid batch after draining TX batch")
		}

		for _, f := range rxFrames {
			c.routeRx(f)
		}
		c.markEndpointSuccessWithRTT(endpointIdx, time.Since(pollStart), len(rxFrames) > 0)
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

func (c *Client) failDrainedBatch(frames []*frame.Frame, drainedIDs [][frame.SessionIDLen]byte, reason string) bool {
	if len(frames) == 0 || len(drainedIDs) == 0 {
		return false
	}
	c.abortSessions(drainedIDs, reason)
	return false
}

func (c *Client) sleepWithContext(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}

func (c *Client) allEndpointsBlacklisted() bool {
	c.endpointMu.Lock()
	defer c.endpointMu.Unlock()
	if len(c.endpoints) == 0 {
		return false
	}
	now := time.Now()
	for i := range c.endpoints {
		if !c.endpointUnavailableLocked(&c.endpoints[i], now) {
			return false
		}
	}
	return true
}

func (c *Client) availableRelayBucketCount() int {
	c.endpointMu.Lock()
	defer c.endpointMu.Unlock()
	if len(c.endpoints) == 0 {
		return 0
	}
	now := time.Now()
	buckets := make(map[string]struct{}, len(c.endpoints))
	for i := range c.endpoints {
		ep := &c.endpoints[i]
		if c.endpointUnavailableLocked(ep, now) {
			continue
		}
		buckets[ep.account] = struct{}{}
	}
	return len(buckets)
}

func (c *Client) closeSessionsIfAllEndpointsBlacklisted(reason string) bool {
	if !c.allEndpointsBlacklisted() {
		c.mu.Lock()
		c.endpointOutageStarted = time.Time{}
		c.mu.Unlock()
		return false
	}
	now := time.Now()
	c.mu.Lock()
	if c.endpointOutageStarted.IsZero() {
		c.endpointOutageStarted = now
		grace := c.endpointOutageGrace
		c.mu.Unlock()
		log.Printf("[carrier] %s; holding active sessions for up to %s while endpoints recover", reason, grace.Round(time.Second))
		return false
	}
	elapsed := now.Sub(c.endpointOutageStarted)
	grace := c.endpointOutageGrace
	c.mu.Unlock()
	if elapsed < grace {
		return false
	}
	return c.abortAllSessions(reason) > 0
}

func (c *Client) abortAllSessions(reason string) int {
	c.mu.Lock()
	sessions := make([]*session.Session, 0, len(c.sessions))
	for _, s := range c.sessions {
		sessions = append(sessions, s)
	}
	if len(sessions) == 0 {
		c.mu.Unlock()
		return 0
	}
	c.sessions = make(map[[frame.SessionIDLen]byte]*session.Session)
	c.inFlight = make(map[[frame.SessionIDLen]byte]bool)
	c.txReady = make(map[[frame.SessionIDLen]byte]struct{})
	c.txReadyOrder = nil
	c.mu.Unlock()

	log.Printf("[carrier] %s; closing %d local session(s) so the SOCKS client can reconnect", reason, len(sessions))
	for _, s := range sessions {
		s.Abort()
		c.stats.sessionsClose.Add(1)
	}
	c.wake.Broadcast()
	return len(sessions)
}

func (c *Client) abortSessions(ids [][frame.SessionIDLen]byte, reason string) int {
	if len(ids) == 0 {
		return 0
	}
	c.mu.Lock()
	sessions := make([]*session.Session, 0, len(ids))
	for _, id := range ids {
		s, ok := c.sessions[id]
		if !ok {
			continue
		}
		sessions = append(sessions, s)
		delete(c.sessions, id)
		delete(c.inFlight, id)
		delete(c.txReady, id)
		c.debugStarts.Delete(id)
	}
	c.compactReadyOrderLocked()
	c.mu.Unlock()

	if len(sessions) == 0 {
		return 0
	}
	log.Printf("[carrier] %s; closing %d affected local session(s) so the SOCKS client can reconnect", reason, len(sessions))
	for _, s := range sessions {
		s.Abort()
		c.stats.sessionsClose.Add(1)
	}
	c.wake.Broadcast()
	return len(sessions)
}

func (c *Client) encodeBatch(frames []*frame.Frame) ([]byte, error) {
	start := time.Now()
	plainSize := encodedBatchPlainSize(frames)
	var (
		body []byte
		err  error
	)
	if c.binaryDirect {
		body, err = frame.EncodeBatchBinary(c.aead, c.clientID, frames)
	} else {
		body, err = frame.EncodeBatch(c.aead, c.clientID, frames)
	}
	c.stats.encode.Add(time.Since(start))
	if err == nil {
		c.stats.reqSize.Add(len(body))
		c.stats.wireRatio.Add(len(body), plainSize)
	}
	return body, err
}

func (c *Client) decodeBatch(body []byte) ([frame.ClientIDLen]byte, []*frame.Frame, error) {
	start := time.Now()
	defer func() {
		c.stats.decode.Add(time.Since(start))
		c.stats.respSize.Add(len(body))
	}()
	if c.binaryDirect {
		return frame.DecodeBatchBinary(c.aead, body)
	}
	return frame.DecodeBatch(c.aead, body)
}

func encodedBatchPlainSize(frames []*frame.Frame) int {
	size := 1 + frame.ClientIDLen + 2
	for _, f := range frames {
		size += 4 + f.EncodedLen()
	}
	return size
}

func (c *Client) requestContentType() string {
	if c.binaryDirect {
		return "application/octet-stream"
	}
	return "text/plain"
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
	quotaPressure := c.accountQuotaPressureLocked(now)
	hasUnderQuotaCandidate := false
	for i := 0; i < n; i++ {
		ep := &c.endpoints[i]
		if c.endpointUnavailableLocked(ep, now) {
			continue
		}
		if quotaPressure[ep.account] < quotaRotateAwayPermille {
			hasUnderQuotaCandidate = true
			break
		}
	}
	bestIdx := -1
	var bestScore time.Duration
	for i := 0; i < n; i++ {
		idx := (start + i) % n
		ep := &c.endpoints[idx]
		if c.endpointUnavailableLocked(ep, now) {
			continue
		}
		pressure := quotaPressure[ep.account]
		if hasUnderQuotaCandidate && pressure >= quotaRotateAwayPermille {
			continue
		}
		score := ep.rttEWMA
		if score <= 0 {
			score = 100 * time.Millisecond
		}
		if ep.failCount > 0 {
			score += time.Duration(ep.failCount) * 250 * time.Millisecond
		}
		score += time.Duration(pressure) * quotaScorePenaltyPerMille
		// Keep traffic spread across healthy deployments in the same account.
		// RTT alone can make one script "win" forever by a few milliseconds,
		// burning that deployment's execution/concurrency budget while its
		// sibling stays almost idle. A small per-deployment usage penalty still
		// prefers genuinely faster endpoints, but rotates away from a deployment
		// that has already handled hundreds more polls today.
		score += time.Duration(ep.dailyCount) * endpointLoadPenaltyPerPoll
		if bestIdx < 0 || score < bestScore {
			bestIdx = idx
			bestScore = score
		}
	}
	if bestIdx >= 0 {
		c.nextEndpoint = (bestIdx + 1) % n
		return bestIdx, c.endpoints[bestIdx].url
	}

	return -1, ""
}

func (c *Client) endpointUnavailableLocked(ep *relayEndpoint, now time.Time) bool {
	if c.touchDailyWindow(ep, now) {
		return false
	}
	return ep.blacklistedTill.After(now) || ep.quotaExhaustedUntil.After(now)
}

func (c *Client) markEndpointSuccess(endpointIdx int) {
	c.markEndpointSuccessWithRTT(endpointIdx, 0, false)
}

func (c *Client) accountQuotaPressureLocked(now time.Time) map[string]int {
	type scriptKey struct {
		account string
		count   uint64
	}
	localUsageByAccount := make(map[string]uint64, len(c.endpoints))
	scriptUsageByAccount := make(map[string]uint64, len(c.endpoints))
	seenScriptCounts := make(map[scriptKey]struct{}, len(c.endpoints))
	for i := range c.endpoints {
		ep := &c.endpoints[i]
		c.touchDailyWindow(ep, now)
		localUsageByAccount[ep.account] += ep.dailyCount
		if !ep.scriptCountAt.IsZero() {
			key := scriptKey{account: ep.account, count: ep.scriptCount}
			if _, seen := seenScriptCounts[key]; !seen {
				seenScriptCounts[key] = struct{}{}
				scriptUsageByAccount[ep.account] += ep.scriptCount
			}
		}
	}
	pressure := make(map[string]int, len(localUsageByAccount))
	for account, localUsage := range localUsageByAccount {
		usage := localUsage
		if scriptUsageByAccount[account] > usage {
			usage = scriptUsageByAccount[account]
		}
		p := int((usage * 1000) / appsScriptDailyQuota)
		if p > 1000 {
			p = 1000
		}
		pressure[account] = p
	}
	for account, scriptUsage := range scriptUsageByAccount {
		if _, ok := pressure[account]; ok {
			continue
		}
		p := int((scriptUsage * 1000) / appsScriptDailyQuota)
		if p > 1000 {
			p = 1000
		}
		pressure[account] = p
	}
	return pressure
}

func (c *Client) markEndpointSuccessWithRTT(endpointIdx int, rtt time.Duration, returnedData bool) {
	if rtt > 0 {
		c.stats.endpointRTT.Add(rtt)
	}
	c.endpointMu.Lock()
	if endpointIdx < 0 || endpointIdx >= len(c.endpoints) {
		c.endpointMu.Unlock()
		return
	}
	ep := &c.endpoints[endpointIdx]
	wasFailing := ep.failCount > 0
	ep.statsOK++
	if rtt > 0 {
		if ep.rttEWMA <= 0 {
			ep.rttEWMA = rtt
		} else {
			ep.rttEWMA = (ep.rttEWMA*7 + rtt) / 8
		}
	}
	url := ep.url
	account := ep.account
	ep.failCount = 0
	ep.blacklistedTill = time.Time{}
	ep.quotaExhaustedUntil = time.Time{}
	for i := range c.endpoints {
		if i == endpointIdx || c.endpoints[i].account != account {
			continue
		}
		c.endpoints[i].quotaExhaustedUntil = time.Time{}
	}
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

func (c *Client) markEndpointQuotaExhausted(endpointIdx int) {
	c.endpointMu.Lock()
	if endpointIdx < 0 || endpointIdx >= len(c.endpoints) {
		c.endpointMu.Unlock()
		return
	}
	now := time.Now()
	ep := &c.endpoints[endpointIdx]
	c.touchDailyWindow(ep, now)
	resetAt := ep.dailyResetAt
	if resetAt.IsZero() {
		resetAt = nextQuotaReset(now)
	}
	url := ep.url
	account := ep.account
	for i := range c.endpoints {
		if c.endpoints[i].account != account {
			continue
		}
		peer := &c.endpoints[i]
		c.touchDailyWindow(peer, now)
		peer.quotaExhaustedUntil = resetAt
		peer.blacklistedTill = resetAt
		if i == endpointIdx {
			peer.failCount++
			peer.statsFail++
		}
	}
	c.endpointMu.Unlock()
	log.Printf("[carrier] endpoint %s account=%q quota exhausted until %s Pacific; rotating away",
		shortScriptKey(url), account, resetAt.In(quotaResetTZ).Format(time.RFC3339))
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
	ttl := c.endpointBlacklistTTL(ep.failCount)
	ttl = endpointBlacklistTTLWithJitter(ttl, c.endpointBlacklistMaxTTL, ep.url, ep.failCount)
	ep.blacklistedTill = time.Now().Add(ttl)
	url := ep.url
	failCount := ep.failCount
	peerCount := len(c.endpoints) - 1
	c.endpointMu.Unlock()
	// Only log on the healthy → blacklisted transition; subsequent failures
	// of an already-blacklisted endpoint would be log noise.
	if wasHealthy {
		log.Printf("[carrier] endpoint %s blacklisted for %s (still rotating across %d others)",
			shortScriptKey(url), ttl.Round(100*time.Millisecond), peerCount)
	} else if failCount == 8 {
		// Notify once when an endpoint reaches hour-scale backoff so the operator
		// knows this deployment is likely quota-exhausted or dead.
		log.Printf("[carrier] endpoint %s repeatedly failing (%d consecutive); now at extended backoff (%s). Consider re-deploying that script.",
			shortScriptKey(url), failCount, ttl.Round(time.Second))
	}
}

func endpointBlacklistTTL(failCount int) time.Duration {
	return endpointBlacklistTTLWithBounds(failCount, endpointBlacklistBaseTTL, endpointBlacklistMaxTTL)
}

func (c *Client) endpointBlacklistTTL(failCount int) time.Duration {
	return endpointBlacklistTTLWithBounds(failCount, c.endpointBlacklistBaseTTL, c.endpointBlacklistMaxTTL)
}

func endpointBlacklistTTLWithJitter(ttl, max time.Duration, key string, failCount int) time.Duration {
	if ttl <= 0 {
		return 0
	}
	if max > 0 && ttl >= max {
		return max
	}
	h := fnv.New32a()
	_, _ = fmt.Fprintf(h, "%s#%d", key, failCount)
	spreadPercent := int(h.Sum32()%41) - 20 // deterministic +/-20% spread per endpoint/failure tier.
	jittered := ttl + ttl*time.Duration(spreadPercent)/100
	if jittered <= 0 {
		return ttl
	}
	if max > 0 && jittered > max {
		return max
	}
	return jittered
}

func endpointBlacklistTTLWithBounds(failCount int, base, max time.Duration) time.Duration {
	if failCount <= 0 {
		return 0
	}
	if failCount <= 5 {
		ttl := base << (failCount - 1)
		if ttl > max {
			return max
		}
		return ttl
	}
	switch failCount {
	case 6:
		if 5*time.Minute > max {
			return max
		}
		return 5 * time.Minute
	case 7:
		if 30*time.Minute > max {
			return max
		}
		return 30 * time.Minute
	default:
		return max
	}
}

func (c *Client) markTxReadyLocked(id [frame.SessionIDLen]byte) {
	if _, ok := c.txReady[id]; !ok {
		c.txReadyOrder = append(c.txReadyOrder, id)
	}
	c.txReady[id] = struct{}{}
}

func (c *Client) readyOrderSnapshotLocked() [][frame.SessionIDLen]byte {
	if len(c.txReady) == 0 {
		return nil
	}
	ids := make([][frame.SessionIDLen]byte, 0, len(c.txReady))
	seen := make(map[[frame.SessionIDLen]byte]struct{}, len(c.txReady))
	for _, id := range c.txReadyOrder {
		if _, ready := c.txReady[id]; !ready {
			continue
		}
		if _, ok := c.sessions[id]; !ok {
			delete(c.txReady, id)
			continue
		}
		ids = append(ids, id)
		seen[id] = struct{}{}
	}
	for id := range c.txReady {
		if _, ok := seen[id]; ok {
			continue
		}
		if _, ok := c.sessions[id]; !ok {
			delete(c.txReady, id)
			continue
		}
		ids = append(ids, id)
		c.txReadyOrder = append(c.txReadyOrder, id)
	}
	return ids
}

func (c *Client) compactReadyOrderLocked() {
	if len(c.txReadyOrder) == 0 {
		return
	}
	out := c.txReadyOrder[:0]
	for _, id := range c.txReadyOrder {
		if _, ok := c.txReady[id]; ok {
			out = append(out, id)
		}
	}
	c.txReadyOrder = out
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
	remainingBytes := c.maxRequestBytesPreEncode
	if remainingBytes <= 0 {
		remainingBytes = protocol.MaxRequestBytesPreEncode
	}

	refs := c.readyOrderSnapshotLocked()
	defer c.compactReadyOrderLocked()

	drain := func(id [frame.SessionIDLen]byte, synOnly bool) {
		if remaining <= 0 || remainingBytes <= 0 {
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
		if queuedAt := s.FirstQueuedAt(); !queuedAt.IsZero() {
			c.stats.queueWait.Add(time.Since(queuedAt))
		}
		frames := s.DrainTxLimitedByBudget(MaxFramePayload, perSessionCap, remainingBytes)
		delete(c.txReady, id) // remove now; OnTx re-adds if more data arrives
		if len(frames) == 0 {
			return
		}
		c.inFlight[id] = true
		drainedIDs = append(drainedIDs, id)
		out = append(out, frames...)
		for _, f := range frames {
			remainingBytes -= len(f.Payload)
		}
		remaining -= len(frames)
	}

	// First pass: SYN sessions only. New connections claim batch slots before
	// ongoing data transfers so a large upload/download cannot push SYN frames
	// out of the batch and delay connection setup by a full poll cycle.
	for _, id := range refs {
		drain(id, true)
	}
	// Second pass: remaining data sessions.
	for _, id := range refs {
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
			c.markTxReadyLocked(id)
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
	if len(f.Payload) > 0 {
		// First downstream frame for a session implies time-to-first-byte.
		// LoadAndDelete ensures we record/log this exactly once per session.
		if start, loaded := c.debugStarts.LoadAndDelete(f.SessionID); loaded {
			ttfb := time.Since(start.(time.Time))
			c.stats.ttfb.Add(ttfb)
			if c.debugTiming {
				log.Printf("[timing] %x ttfb=%dms target=%s",
					f.SessionID[:4], ttfb.Milliseconds(), s.Target)
			}
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
		c.debugStarts.Delete(f.SessionID)
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
			c.debugStarts.Delete(id)
			c.stats.sessionsClose.Add(1)
		}
	}
}

func (c *Client) runSessionGCLoop(ctx context.Context) {
	t := time.NewTicker(sessionGCInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			c.gcDoneSessions()
		}
	}
}

func (c *Client) acquireIdlePollSlot(cap int) bool {
	for {
		n := c.idlePollInFlight.Load()
		if int(n) >= cap {
			return false
		}
		if c.idlePollInFlight.CompareAndSwap(n, n+1) {
			return true
		}
	}
}

func (c *Client) releaseIdlePollSlot() {
	for {
		n := c.idlePollInFlight.Load()
		if n <= 0 {
			return
		}
		if c.idlePollInFlight.CompareAndSwap(n, n-1) {
			return
		}
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

func (c *Client) kickUrgent() {
	if c.coalesceStep > 0 {
		c.coalesceMu.Lock()
		if c.coalesceTimer != nil {
			c.coalesceTimer.Stop()
			c.coalesceTimer = nil
		}
		c.coalesceDeadline = time.Time{}
		c.coalesceMu.Unlock()
	}
	c.wake.Broadcast()
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
	if bytes.HasPrefix(l, []byte("relay_loop_detected")) {
		return true
	}
	if bytes.HasPrefix(l, []byte("exception:")) {
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
	trimmed := bytes.TrimSpace(body)
	var upstream struct {
		E      string `json:"e"`
		Status int    `json:"status"`
		Body   string `json:"body"`
	}
	if len(trimmed) > 0 && trimmed[0] == '{' && json.Unmarshal(trimmed, &upstream) == nil && upstream.E == "upstream_status" {
		switch upstream.Status {
		case http.StatusNoContent:
			return "VPS rejected the encrypted batch with HTTP 204 - most likely tunnel_key mismatch between client_config.json and server_config.json", true
		case http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout, http.StatusInternalServerError:
			return fmt.Sprintf("Apps Script reached the relay URL, but the VPS returned HTTP %d - check goose-server, firewall, and the RELAY_URLS /tunnel address", upstream.Status), false
		default:
			if upstream.Body != "" {
				return fmt.Sprintf("Apps Script relay upstream returned HTTP %d: %s", upstream.Status, snippet([]byte(upstream.Body))), false
			}
			return fmt.Sprintf("Apps Script relay upstream returned HTTP %d", upstream.Status), false
		}
	}

	lower := strings.ToLower(string(trimmed))
	if strings.Contains(lower, "relay_loop_detected") {
		return "Apps Script relay loop detected - RELAY_URLS must point to the VPS /tunnel endpoint, not another Apps Script URL", true
	}

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
