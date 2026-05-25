package carrier

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"log"
	"net"
	"net/http"
	neturl "net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
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
	// allowed in pure-download mode (no pending TX). Multi-endpoint configs can
	// use additional idle capacity through account/URL buckets, but each bucket
	// is still capped to avoid burning Apps Script simultaneous executions while
	// the client is simply waiting for downstream data.
	pureDownloadIdleCap = 2

	// pollTimeout is the per-request HTTP ceiling. It must comfortably exceed
	// the server's long-poll window and leave room for large Apps Script
	// responses on bad mobile networks, otherwise a timed-out response can
	// strand downstream sequence numbers.
	pollTimeout = time.Duration(protocol.DefaultPollTimeoutMs) * time.Millisecond

	sessionGCInterval = 15 * time.Second

	// maxDrainFramesPerSession keeps one busy session from monopolizing a poll
	// cycle when many short-lived sessions are active (e.g., chat apps).
	maxDrainFramesPerSession = 8

	batchPlainBaseOverhead     = 1 + frame.ClientIDLen + 2
	maxBatchFramePlainOverhead = 4 + frame.SessionIDLen + 8 + 1 + 1 + 255 + 4

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

	// Local offline failures should not ramp a mobile client into the 30m/1h
	// endpoint penalty box. Keep the pause long enough to avoid a tight retry
	// loop while airplane mode is on, but short enough that new sessions recover
	// quickly when the network returns.
	localNetworkOfflineBlacklistTTL = 15 * time.Second
	localNetworkRecoveryProbeEvery  = 5 * time.Second
	localNetworkRecoveryProbeTO     = 2 * time.Second
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

func batchFramePlainLen(f *frame.Frame) int {
	if f == nil {
		return 0
	}
	return 4 + f.EncodedLen()
}

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
		"tls handshake timeout",
		"http2: client connection lost",
		"connection attempt failed because the connected party did not properly respond",
		"connected host has failed to respond",
	} {
		if strings.Contains(msg, needle) {
			return true
		}
	}
	return false
}

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
	if !cfg.UseFronting {
		return ""
	}
	addr := strings.TrimSpace(cfg.Fronting.GoogleIP)
	if addr == "" {
		return ""
	}
	if _, _, err := net.SplitHostPort(addr); err == nil {
		return addr
	}
	return net.JoinHostPort(addr, "443")
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
	StatsJSON    bool   // when true, emit periodic stats as JSON log lines
	IdlePollMode string // always, adaptive, off
	// DownstreamReplayMode controls experimental downstream ACK/replay.
	// "off" disables it. "auto" enables it only after Diagnose observes a
	// server version feature advertising downstream_replay_v1.
	DownstreamReplayMode string
	// FreshStartReset asks a compatible server to close stale sessions from a
	// previous run of the same stable ClientInstanceID during pre-flight.
	FreshStartReset  bool
	ClientInstanceID string
	ClientRunID      string
	QuotaStatePath   string

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
	IdlePollMaxBuckets       int
	TxSlotsPerBucket         int
	WorkersPerEndpoint       int
	PollIdleSleep            time.Duration
	PollTimeout              time.Duration
	EndpointBlacklistBaseTTL time.Duration
	EndpointBlacklistMaxTTL  time.Duration
	EndpointOutageGrace      time.Duration
	MaxRequestBytesPreEncode int
	TxBufferBudgetBytes      int
	StreamConnectTimeout     time.Duration
	StreamPingInterval       time.Duration
	StreamReconnectBackoff   time.Duration
}

type relayEndpoint struct {
	url             string
	account         string // optional human-readable Google account label, "" = unlabeled
	bucket          string // in-flight bucket: "acct:<account>" or "url:<url>" for unlabeled deployments
	blacklistedTill time.Time
	failCount       int
	slowSuccesses   int
	lastSlowAt      time.Time
	statsOK         uint64
	statsFail       uint64
	failureReasons  [endpointFailureReasonCount]uint64
	rttEWMA         time.Duration
	lastUsefulAt    time.Time

	// Per-quota-window counters. dailyCount is the number of HTTP responses
	// received from Apps Script in the current local accounting window;
	// dailyResetAt is a client-side rollover point used for stats/backoff.
	// Google documents Apps Script quotas as per-user windows that reset 24
	// hours after first use, so this local window is an approximation.
	dailyCount          uint64
	dailyResetAt        time.Time
	quotaExhaustedUntil time.Time

	// Script-reported per-day invocation count, fetched periodically via doGet on
	// the same /exec URL. scriptCountAt is zero until the first successful
	// fetch; scriptStatsErrLogged suppresses repeat "needs redeploy" warnings
	// when the deployed Code.gs is the legacy version that doesn't return JSON.
	scriptCount          uint64
	scriptCountAt        time.Time
	scriptStatsErrLogged bool
	localNetworkOffline  bool
}

type endpointLease struct {
	idx        int
	url        string
	bucket     string
	generation uint64
	check      bool
}

func (l endpointLease) valid() bool {
	return l.idx >= 0 && l.url != ""
}

type endpointFailureReason int

const (
	endpointFailureLocalOffline endpointFailureReason = iota
	endpointFailureNonBatch
	endpointFailureQuota
	endpointFailureRateLimit
	endpointFailureEmpty204
	endpointFailureHTTPError
	endpointFailureDecodeError
	endpointFailureReadError
	endpointFailureReasonCount
)

var endpointFailureReasonLabels = [...]string{
	endpointFailureLocalOffline: "local_offline",
	endpointFailureNonBatch:     "non_batch",
	endpointFailureQuota:        "quota",
	endpointFailureRateLimit:    "rate_limit",
	endpointFailureEmpty204:     "empty_204",
	endpointFailureHTTPError:    "http_error",
	endpointFailureDecodeError:  "decode_error",
	endpointFailureReadError:    "read_error",
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
	endpointUsefulBonus        = 75 * time.Millisecond
	endpointUsefulWindow       = 15 * time.Second
	endpointSlowRTT            = 2 * time.Second
	endpointSlowWindow         = 2 * time.Minute
	endpointSlowPenalty        = 400 * time.Millisecond
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

const (
	downstreamReplayModeOff  = "off"
	downstreamReplayModeAuto = "auto"

	downstreamACKRefreshInterval = 15 * time.Second

	relayEndpointOutageGraceMax = time.Minute
)

const (
	idlePollModeAlways   = "always"
	idlePollModeAdaptive = "adaptive"
	idlePollModeOff      = "off"

	adaptiveIdleQuietAfter = 30 * time.Second
	adaptiveIdleSleepAfter = 5 * time.Minute
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
	useFronting              bool
	autoTune                 bool
	statsJSON                bool
	idlePollMode             string
	transportMode            string
	downstreamReplayMode     string
	downstreamReplayActive   atomic.Bool
	directStreamURLs         []string
	streamConnectTimeout     time.Duration
	streamPingInterval       time.Duration
	streamReconnectBackoff   time.Duration
	streamActive             atomic.Bool
	numWorkers               int // workersPerEndpoint × endpoint count when POST transport is enabled
	bucketCount              int // distinct idle buckets: labeled accounts plus one bucket per unlabeled endpoint
	idleSlotsPerBucket       int // resolved from Config.IdleSlotsPerBucket, default 1
	idlePollMaxBuckets       int // max account buckets used by idle polls when no sessions exist
	txSlotsPerBucket         int // max concurrent active POSTs per account bucket
	pollIdleSleep            time.Duration
	endpointBlacklistBaseTTL time.Duration
	endpointBlacklistMaxTTL  time.Duration
	endpointOutageGrace      time.Duration
	endpointOutageStarted    time.Time
	maxRequestBytesPreEncode int
	txBudget                 *session.TxBudget
	clientVersion            string
	clientInstanceID         string
	clientRunID              string
	freshStartReset          bool
	quotaStatePath           string
	quotaStateMu             sync.Mutex
	recoveryProbeAddr        string

	// clientID is a random 16-byte identifier minted once per process. It is
	// embedded in every encrypted batch so the server can route downstream
	// frames back to the correct client when several clients share one server.
	clientID [frame.ClientIDLen]byte

	// debugStarts tracks session start times when debugTiming is on so we can
	// log time-to-first-byte once each session receives its first downstream
	// frame. Entries are deleted on first rx.
	debugStarts sync.Map

	mu          sync.Mutex
	sessions    map[[frame.SessionIDLen]byte]*session.Session
	inFlight    map[[frame.SessionIDLen]byte]bool
	txReady     map[[frame.SessionIDLen]byte]struct{} // sessions with pending TX frames
	ackReady    map[[frame.SessionIDLen]byte]uint64   // sessions whose downstream rxSeq advanced and need ACK
	ackLatest   map[[frame.SessionIDLen]byte]uint64   // newest downstream ACK sequence per active session
	ackLastSent map[[frame.SessionIDLen]byte]time.Time
	// txReadyOrder preserves first-ready order so drainAll does not sort the
	// ready map every poll. txReady remains the membership source of truth;
	// stale queue entries are compacted lazily after drains.
	txReadyOrder [][frame.SessionIDLen]byte

	sessionCreateTokens float64
	sessionCreateAt     time.Time
	noSessionSince      time.Time

	endpointMu     sync.Mutex
	endpoints      []relayEndpoint
	endpointGen    uint64
	nextEndpoint   int
	idleByBucket   map[string]int
	activeByBucket map[string]int

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
	framesOut         atomic.Uint64
	framesIn          atomic.Uint64
	bytesOut          atomic.Uint64
	bytesIn           atomic.Uint64
	pollsOK           atomic.Uint64
	pollsFail         atomic.Uint64
	usefulPolls       atomic.Uint64
	emptyPolls        atomic.Uint64
	idlePolls         atomic.Uint64
	idleSuppressed    atomic.Uint64
	idleSlotBusy      atomic.Uint64
	activeSlotBusy    atomic.Uint64
	rstFromServer     atomic.Uint64
	rxInboxTimeout    atomic.Uint64
	rxReorderOverflow atomic.Uint64
	rxAbortOther      atomic.Uint64
	ackSent           atomic.Uint64
	ackOnlyPosts      atomic.Uint64
	ackOnlyFrames     atomic.Uint64
	sessionsOpen      atomic.Uint64
	sessionsClose     atomic.Uint64
	streamOK          atomic.Uint64
	streamFail        atomic.Uint64
	streamDrops       atomic.Uint64
	postFallbacks     atomic.Uint64
	compressAttempted atomic.Uint64
	compressUsed      atomic.Uint64
	compressSkipped   atomic.Uint64
	compressRaw       atomic.Uint64
	compressZstd      atomic.Uint64
	compressRawBytes  atomic.Uint64
	compressBodyBytes atomic.Uint64
	compressWireBytes atomic.Uint64
	compressSaved     atomic.Uint64
	compressLost      atomic.Uint64

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
		oldQuotaKey := ""
		oldQuotaUntil := time.Time{}
		if !ok {
			ep = relayEndpoint{url: url}
		} else {
			oldQuotaKey = endpointQuotaKey(&ep)
			oldQuotaUntil = ep.quotaExhaustedUntil
		}
		ep.url = url
		ep.account = account
		if account != "" {
			ep.bucket = "acct:" + account
		} else {
			ep.bucket = "url:" + url
		}
		if ok && endpointQuotaKey(&ep) != oldQuotaKey {
			ep.quotaExhaustedUntil = time.Time{}
			if !oldQuotaUntil.IsZero() && ep.blacklistedTill.Equal(oldQuotaUntil) {
				ep.blacklistedTill = time.Time{}
				ep.localNetworkOffline = false
			}
		}
		endpoints = append(endpoints, ep)
	}
	return endpoints
}

func endpointBucketStats(endpoints []relayEndpoint) (bucketCount int, labeled int) {
	bucketSeen := make(map[string]struct{}, len(endpoints))
	for _, ep := range endpoints {
		bucketSeen[ep.bucket] = struct{}{}
		if ep.account != "" {
			labeled++
		}
	}
	return len(bucketSeen), labeled
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

func newClientRunID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return ""
	}
	return hex.EncodeToString(b[:])
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
	idlePollMode := strings.TrimSpace(strings.ToLower(cfg.IdlePollMode))
	if idlePollMode == "" {
		idlePollMode = idlePollModeAlways
	}
	switch idlePollMode {
	case idlePollModeAlways, idlePollModeAdaptive, idlePollModeOff:
	default:
		return nil, fmt.Errorf("unknown idle poll mode %q", cfg.IdlePollMode)
	}
	downstreamReplayMode := strings.TrimSpace(strings.ToLower(cfg.DownstreamReplayMode))
	if downstreamReplayMode == "" {
		downstreamReplayMode = downstreamReplayModeOff
	}
	switch downstreamReplayMode {
	case downstreamReplayModeOff, downstreamReplayModeAuto:
	default:
		return nil, fmt.Errorf("downstream_replay_mode must be off or auto (got %q)", cfg.DownstreamReplayMode)
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

	// Labeled deployments share one throttle bucket per Google account.
	// Unlabeled deployments get one implicit bucket per URL, matching the
	// official v1.5 behavior for legacy multi-endpoint configs where the client
	// cannot prove the deployments share a quota account.
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
	idlePollMaxBuckets := cfg.IdlePollMaxBuckets
	if idlePollMaxBuckets <= 0 {
		idlePollMaxBuckets = protocol.DefaultIdlePollMaxBuckets
	}
	if idlePollMaxBuckets > protocol.DefaultIdlePollMaxBuckets {
		idlePollMaxBuckets = protocol.DefaultIdlePollMaxBuckets
	}
	resolvedWorkersPerEndpoint := cfg.WorkersPerEndpoint
	if resolvedWorkersPerEndpoint <= 0 {
		resolvedWorkersPerEndpoint = workersPerEndpoint
	}
	txSlotsPerBucket := cfg.TxSlotsPerBucket
	if txSlotsPerBucket <= 0 {
		txSlotsPerBucket = protocol.DefaultWorkersPerEndpoint
	}
	resolvedPollIdleSleep := cfg.PollIdleSleep
	if resolvedPollIdleSleep <= 0 {
		resolvedPollIdleSleep = pollIdleSleep
	}
	resolvedPollTimeout := cfg.PollTimeout
	if resolvedPollTimeout <= 0 {
		resolvedPollTimeout = pollTimeout
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
	resolvedTxBufferBudgetBytes := cfg.TxBufferBudgetBytes
	if resolvedTxBufferBudgetBytes <= 0 {
		resolvedTxBufferBudgetBytes = protocol.DefaultTxBufferBudgetBytes
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
	clientRunID := strings.TrimSpace(cfg.ClientRunID)
	if clientRunID == "" && cfg.FreshStartReset && strings.TrimSpace(cfg.ClientInstanceID) != "" {
		clientRunID = newClientRunID()
	}
	// Active POST worker count scales with endpoint count, matching the latest
	// official worker-scaling fix. Idle polling is still capped by buckets below
	// so multiple deployments under one labeled account do not camp excessive
	// standing long-polls.
	numWorkers := resolvedWorkersPerEndpoint * len(endpoints)
	if transportMode == transportModeDirectStream || len(endpoints) == 0 {
		numWorkers = 0
	}
	log.Printf("[carrier] transport=%s stream_endpoints=%d post_workers=%d account_bucket(s)=%d post_endpoint(s)=%d idle_slot(s)/bucket=%d tx_slot(s)/bucket=%d",
		transportMode, len(directStreamURLs), numWorkers, bucketCount, len(endpoints), idleSlotsPerBucket, txSlotsPerBucket)
	if labeled == 0 && len(endpoints) > 1 {
		log.Printf("[carrier] WARN: %d deployments configured with no account labels - treating each deployment as its own throttle bucket. "+
			"If multiple deployments are under the same Google account, label them in script_keys "+
			"as {\"id\": \"...\", \"account\": \"A\"} to share that account's idle-poll cap.",
			len(endpoints))
	}

	httpClients := NewDirectClients(resolvedPollTimeout, resolvedWorkersPerEndpoint)
	if cfg.UseFronting && len(endpoints) > 0 {
		httpClients = NewFrontedClients(cfg.Fronting, resolvedPollTimeout, endpoints[0].url, resolvedWorkersPerEndpoint)
	}

	c := &Client{
		cfg:                      cfg,
		aead:                     aead,
		httpClients:              httpClients,
		debugTiming:              cfg.DebugTiming,
		binaryDirect:             cfg.BinaryDirect,
		useFronting:              cfg.UseFronting,
		autoTune:                 cfg.AutoTune,
		statsJSON:                cfg.StatsJSON,
		idlePollMode:             idlePollMode,
		transportMode:            transportMode,
		downstreamReplayMode:     downstreamReplayMode,
		directStreamURLs:         directStreamURLs,
		streamConnectTimeout:     resolvedStreamConnectTimeout,
		streamPingInterval:       resolvedStreamPingInterval,
		streamReconnectBackoff:   resolvedStreamReconnectBackoff,
		numWorkers:               numWorkers,
		bucketCount:              bucketCount,
		idleSlotsPerBucket:       idleSlotsPerBucket,
		idlePollMaxBuckets:       idlePollMaxBuckets,
		txSlotsPerBucket:         txSlotsPerBucket,
		pollIdleSleep:            resolvedPollIdleSleep,
		endpointBlacklistBaseTTL: resolvedBlacklistBaseTTL,
		endpointBlacklistMaxTTL:  resolvedBlacklistMaxTTL,
		endpointOutageGrace:      resolvedEndpointOutageGrace,
		maxRequestBytesPreEncode: resolvedMaxRequestBytesPreEncode,
		txBudget:                 session.NewTxBudget(resolvedTxBufferBudgetBytes),
		clientVersion:            cfg.ClientVersion,
		clientInstanceID:         strings.TrimSpace(cfg.ClientInstanceID),
		clientRunID:              clientRunID,
		freshStartReset:          cfg.FreshStartReset,
		quotaStatePath:           strings.TrimSpace(cfg.QuotaStatePath),
		recoveryProbeAddr:        recoveryProbeAddress(cfg),
		clientID:                 clientID,
		sessions:                 make(map[[frame.SessionIDLen]byte]*session.Session),
		inFlight:                 make(map[[frame.SessionIDLen]byte]bool),
		txReady:                  make(map[[frame.SessionIDLen]byte]struct{}),
		ackReady:                 make(map[[frame.SessionIDLen]byte]uint64),
		ackLatest:                make(map[[frame.SessionIDLen]byte]uint64),
		ackLastSent:              make(map[[frame.SessionIDLen]byte]time.Time),
		endpoints:                endpoints,
		endpointGen:              1,
		idleByBucket:             make(map[string]int, bucketCount),
		activeByBucket:           make(map[string]int, bucketCount),
		wake:                     newWaker(),
		coalesceStep:             cfg.CoalesceStep,
		coalesceMax:              cfg.CoalesceMax,
	}
	if c.quotaStatePath != "" {
		if err := c.loadQuotaState(c.quotaStatePath); err != nil {
			log.Printf("[carrier] WARN: quota state load skipped: %v", err)
		}
	}
	return c, nil
}

// UpdateEndpoints swaps the relay endpoint list at runtime. It preserves
// health/quota state for URLs that remain present, carries same-account quota
// quarantine onto replacement URLs, and gives newly-added fresh accounts a
// clean slate without restarting the client process.
func (c *Client) UpdateEndpoints(urls, accounts []string) int {
	c.endpointMu.Lock()
	preserve := make(map[string]relayEndpoint, len(c.endpoints))
	quotaByKey := make(map[string]time.Time, len(c.endpoints))
	now := time.Now()
	for _, ep := range c.endpoints {
		preserve[ep.url] = ep
		if ep.quotaExhaustedUntil.After(now) {
			key := endpointQuotaKey(&ep)
			if prev := quotaByKey[key]; prev.IsZero() || ep.quotaExhaustedUntil.After(prev) {
				quotaByKey[key] = ep.quotaExhaustedUntil
			}
		}
	}
	next := buildRelayEndpoints(urls, accounts, preserve)
	if len(next) == 0 {
		c.endpointMu.Unlock()
		return len(c.endpoints)
	}
	for i := range next {
		if until := quotaByKey[endpointQuotaKey(&next[i])]; until.After(now) {
			next[i].quotaExhaustedUntil = until
			next[i].blacklistedTill = until
			next[i].localNetworkOffline = false
		}
	}
	c.endpoints = next
	c.endpointGen++
	if c.nextEndpoint >= len(c.endpoints) {
		c.nextEndpoint = 0
	}
	if c.idleByBucket == nil {
		c.idleByBucket = make(map[string]int, len(next))
	}
	if c.activeByBucket == nil {
		c.activeByBucket = make(map[string]int, len(next))
	}
	bucketCount, _ := endpointBucketStats(next)
	if bucketCount <= 0 {
		bucketCount = 1
	}
	c.bucketCount = bucketCount
	c.endpointMu.Unlock()
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
	s.SetTxBudget(c.txBudget)
	s.OnTx = func() {
		c.mu.Lock()
		c.markTxReadyLocked(id)
		c.mu.Unlock()
		c.kick()
	}
	s.OnAbort = func(reason string) {
		c.recordReceiveAbort(reason)
		log.Printf("[carrier] session %x target=%s receive aborted: %s", id[:4], target, reason)
	}
	s.OnRxAdvance = func(nextSeq uint64) {
		c.recordDownstreamACK(id, nextSeq)
	}
	c.mu.Lock()
	if len(c.sessions) >= maxActiveClientSessions || !c.allowSessionCreateLocked(time.Now()) {
		c.mu.Unlock()
		log.Printf("[carrier] rejecting new session %x for %s: local session storm guard active", id[:4], target)
		s.Abort()
		return s
	}
	c.sessions[id] = s
	c.noSessionSince = time.Time{}
	c.markTxReadyLocked(id) // SYN is pending immediately on creation
	c.mu.Unlock()
	c.stats.sessionsOpen.Add(1)
	c.debugStarts.Store(id, time.Now())
	c.kickUrgent()
	return s
}

func (c *Client) recordDownstreamACK(id [frame.SessionIDLen]byte, nextSeq uint64) {
	if nextSeq == 0 || !c.downstreamReplayActive.Load() {
		return
	}
	c.mu.Lock()
	if _, ok := c.sessions[id]; ok {
		if nextSeq > c.ackLatest[id] {
			c.ackLatest[id] = nextSeq
		}
		if nextSeq > c.ackReady[id] {
			c.ackReady[id] = nextSeq
		}
	}
	c.mu.Unlock()
	c.kick()
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
		log.Printf("[carrier] shutdown: send failed (server idle GC will clean up): %s", safeLogError(err))
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
	wg.Add(1)
	go func() {
		defer wg.Done()
		c.runEndpointRecoveryLoop(ctx)
	}()
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
	if shouldRunScriptStats(c.useFronting, c.endpoints) {
		// Hourly fetch of each Apps Script deployment's self-reported invocation
		// count. Direct relay_urls do not expose that endpoint and must not be
		// treated as Apps Script quota sources.
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.runScriptStatsLoop(ctx)
		}()
	}
	wg.Wait()
	return ctx.Err()
}

func shouldRunScriptStats(useFronting bool, endpoints []relayEndpoint) bool {
	return useFronting && len(endpoints) > 0
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
		if !c.endpointUnavailableLocked(ep, now) {
			allUnavailable = false
			break
		}
		if ep.localNetworkOffline && ep.blacklistedTill.After(now) && !ep.quotaExhaustedUntil.After(now) {
			hasLocalOffline = true
		}
	}
	return allUnavailable && hasLocalOffline
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
	now := time.Now()
	activeSessions, noSessionFor, mode := c.idleSessionSnapshot(now)
	if mode == idlePollModeAdaptive && activeSessions == 0 && noSessionFor >= adaptiveIdleQuietAfter {
		return adaptiveNoSessionBackoff(n)
	}
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

func adaptiveNoSessionBackoff(n int) time.Duration {
	switch {
	case n < 2:
		return time.Second
	case n < 5:
		return 2 * time.Second
	case n < 10:
		return 5 * time.Second
	default:
		return 15 * time.Second
	}
}

func (c *Client) idleSessionSnapshot(now time.Time) (activeSessions int, noSessionFor time.Duration, mode string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	mode = c.idlePollMode
	activeSessions = len(c.sessions)
	if activeSessions > 0 {
		c.noSessionSince = time.Time{}
		return activeSessions, 0, mode
	}
	if c.noSessionSince.IsZero() {
		c.noSessionSince = now
	}
	noSessionFor = now.Sub(c.noSessionSince)
	if noSessionFor < 0 {
		noSessionFor = 0
	}
	return 0, noSessionFor, mode
}

func (c *Client) idlePollCap(now time.Time, noPendingTX bool, availableBuckets int, applyPureDownloadFloor bool) int {
	if availableBuckets <= 0 {
		return 0
	}
	activeSessions, noSessionFor, mode := c.idleSessionSnapshot(now)
	if activeSessions == 0 {
		switch mode {
		case idlePollModeOff:
			return 0
		case idlePollModeAdaptive:
			if noSessionFor >= adaptiveIdleSleepAfter {
				return 0
			}
		}
	}

	idleBuckets := availableBuckets
	if activeSessions == 0 && c.idlePollMaxBuckets > 0 && idleBuckets > c.idlePollMaxBuckets {
		idleBuckets = c.idlePollMaxBuckets
	}
	idleCap := idleBuckets * c.idleSlotsPerBucket
	if applyPureDownloadFloor && noPendingTX && idleCap < pureDownloadIdleCap {
		idleCap = pureDownloadIdleCap
	}
	if activeSessions == 0 && mode == idlePollModeAdaptive && noSessionFor >= adaptiveIdleQuietAfter && idleCap > 1 {
		idleCap = 1
	}
	return idleCap
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
	frames, drainedIDs, drainSnaps := c.drainAll()
	if len(drainedIDs) > 0 {
		defer c.releaseInFlight(drainedIDs)
	}
	isIdlePoll := len(frames) == 0
	ackOnlyFrameCount := countDownstreamACKFrames(frames)
	ackOnlyBatch := len(frames) > 0 && ackOnlyFrameCount == len(frames)
	slotLimitedPoll := isIdlePoll || ackOnlyBatch
	if slotLimitedPoll {
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
		// single standing poll. ACK-only batches share these slots because they
		// are reliability-control long-polls; otherwise many sessions can wake
		// at once and exceed the intended per-account Apps Script concurrency.
		c.mu.Lock()
		noPendingTX := len(c.txReady) == 0
		c.mu.Unlock()
		availableBuckets := c.availableRelayBucketCount()
		if availableBuckets <= 0 {
			return c.rollbackDrainedBatch(frames, drainSnaps)
		}
		idleCap := c.idlePollCap(time.Now(), noPendingTX, availableBuckets, isIdlePoll)
		if idleCap <= 0 {
			c.stats.idleSuppressed.Add(1)
			return c.rollbackDrainedBatch(frames, drainSnaps)
		}
		if !c.acquireIdlePollSlot(idleCap) {
			c.stats.idleSlotBusy.Add(1)
			return c.rollbackDrainedBatch(frames, drainSnaps)
		}
		if isIdlePoll {
			c.stats.idlePolls.Add(1)
		}
		defer c.releaseIdlePollSlot()
	}

	maxAttempts := 1
	endpointCount := c.relayEndpointCount()
	if endpointCount > 1 {
		// TX batches have already been drained out of session buffers. Try every
		// configured endpoint before giving up so one exhausted deployment (or
		// even several) cannot discard that payload while a later deployment is
		// still healthy. Idle/ACK-only polls keep the old single alternate attempt
		// to avoid burning quota across the whole fleet when there is no upstream
		// payload to preserve.
		if len(drainedIDs) > 0 {
			maxAttempts = endpointCount
		} else {
			maxAttempts = 2
		}
	}

	var idleBucket string
	var activeBucket string
	var firstActiveLease endpointLease
	firstActiveLeaseHeld := false
	firstActiveLeaseUsed := false
	defer func() {
		if idleBucket != "" {
			c.releaseIdleBucketSlot(idleBucket)
		}
		if activeBucket != "" {
			c.releaseActiveBucketSlot(activeBucket)
		}
	}()
	if !slotLimitedPoll {
		firstActiveLease = c.pickRelayEndpointForActivePollLease()
		activeBucket = firstActiveLease.bucket
		firstActiveLeaseHeld = firstActiveLease.valid()
		if !firstActiveLeaseHeld {
			if c.activeSlotsSaturated() {
				c.stats.activeSlotBusy.Add(1)
			}
			return c.rollbackDrainedBatch(frames, drainSnaps)
		}
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

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		if idleBucket != "" {
			c.releaseIdleBucketSlot(idleBucket)
			idleBucket = ""
		}
		if activeBucket != "" && !(firstActiveLeaseHeld && !firstActiveLeaseUsed) {
			c.releaseActiveBucketSlot(activeBucket)
			activeBucket = ""
		}
		var lease endpointLease
		if slotLimitedPoll {
			lease = c.pickRelayEndpointForIdlePollLease(isIdlePoll)
			idleBucket = lease.bucket
			if !lease.valid() {
				c.stats.idleSlotBusy.Add(1)
			}
		} else {
			if firstActiveLeaseHeld && !firstActiveLeaseUsed {
				lease = firstActiveLease
				firstActiveLeaseUsed = true
			} else {
				lease = c.pickRelayEndpointForActivePollLease()
				activeBucket = lease.bucket
				if !lease.valid() && c.activeSlotsSaturated() {
					c.stats.activeSlotBusy.Add(1)
				}
			}
		}
		endpointIdx, scriptURL := lease.idx, lease.url
		if endpointIdx < 0 || scriptURL == "" {
			c.endpointMu.Lock()
			anyConfigured := len(c.endpoints) > 0
			c.endpointMu.Unlock()
			if anyConfigured {
				return c.rollbackDrainedBatch(frames, drainSnaps)
			}
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
		if ackOnlyBatch {
			c.stats.ackOnlyPosts.Add(1)
			c.stats.ackOnlyFrames.Add(uint64(ackOnlyFrameCount))
		}

		pollStart := time.Now()
		resp, err := c.pickHTTPClient().Do(req)
		if err == nil {
			// Count local request pressure once we know the request reached Apps
			// Script. Normal tunnel polls usually spend at least one UrlFetch
			// call, but exact Google quota burn can differ from this estimate.
			c.bumpDailyCountForLease(lease)
		}
		if err != nil {
			if ctx.Err() != nil {
				return c.rollbackDrainedBatch(frames, drainSnaps)
			}
			logErr := safeLogError(err)
			if isLocalNetworkOffline(err) {
				c.recordEndpointFailureReasonLease(lease, endpointFailureLocalOffline)
				c.markEndpointLocalNetworkFailureLease(lease)
			} else {
				c.recordEndpointFailureReasonLease(lease, endpointFailureHTTPError)
				c.markEndpointFailureLease(lease)
			}
			if attempt < maxAttempts {
				log.Printf("[carrier] relay request failed via %s (attempt %d/%d): %s; retrying alternate endpoint", shortScriptKey(scriptURL), attempt, maxAttempts, logErr)
				continue
			}
			if c.useFronting {
				log.Printf("[carrier] relay request failed via %s: %s (check internet access, script_keys, and google_host)", shortScriptKey(scriptURL), logErr)
			} else {
				log.Printf("[carrier] relay request failed via %s: %s (check relay_urls, goose-server reachability, and VPS firewall)", shortScriptKey(scriptURL), logErr)
			}
			c.sleepWithContext(ctx, time.Second)
			if isLocalNetworkOffline(err) {
				return c.rollbackDrainedBatch(frames, drainSnaps)
			}
			return c.failDrainedBatch(frames, drainedIDs, "all relay request attempts failed after draining TX batch")
		}

		respBody, readErr := readRelayResponseBody(resp.Body, resp.ContentLength, maxRelayResponseBodyBytes)
		_ = resp.Body.Close()
		if readErr != nil {
			localOffline := isLocalNetworkOffline(readErr)
			if localOffline {
				c.recordEndpointFailureReasonLease(lease, endpointFailureLocalOffline)
				c.markEndpointLocalNetworkFailureLease(lease)
			} else {
				c.recordEndpointFailureReasonLease(lease, endpointFailureReadError)
				c.markEndpointFailureLease(lease)
			}
			if attempt < maxAttempts {
				log.Printf("[carrier] failed to read relay response via %s (attempt %d/%d): %v; retrying alternate endpoint", shortScriptKey(scriptURL), attempt, maxAttempts, readErr)
				continue
			}
			log.Printf("[carrier] failed to read relay response: %v", readErr)
			if localOffline {
				return c.rollbackDrainedBatch(frames, drainSnaps)
			}
			return c.failDrainedBatch(frames, drainedIDs, "failed to read relay response after draining TX batch")
		}

		if resp.StatusCode == http.StatusNoContent {
			c.recordEndpointFailureReasonLease(lease, endpointFailureEmpty204)
			c.markEndpointHardFailureLease(lease)
			if attempt < maxAttempts {
				log.Printf("[carrier] relay returned HTTP 204 via %s (attempt %d/%d); retrying alternate endpoint", shortScriptKey(scriptURL), attempt, maxAttempts)
				continue
			}
			log.Printf("[carrier] relay returned HTTP 204 via %s (likely tunnel_key/protocol mismatch); dropping drained batch", shortScriptKey(scriptURL))
			return c.failDrainedBatch(frames, drainedIDs, "relay returned HTTP 204 after draining TX batch")
		}
		if resp.StatusCode != http.StatusOK {
			if !c.binaryDirect && len(respBody) > 0 && isLikelyNonBatchRelayPayload(respBody) {
				errReason, errKind := classifyRelayErrorBodyKind(respBody)
				switch errKind {
				case relayErrorDailyQuota:
					c.recordEndpointFailureReasonLease(lease, endpointFailureQuota)
					c.markEndpointQuotaExhaustedLease(lease)
				case relayErrorRateLimit:
					c.recordEndpointFailureReasonLease(lease, endpointFailureRateLimit)
					c.markEndpoint429Lease(lease)
				case relayErrorHard:
					c.recordEndpointFailureReasonLease(lease, endpointFailureNonBatch)
					c.markEndpointHardFailureLease(lease)
				default:
					c.recordEndpointFailureReasonLease(lease, endpointFailureHTTPError)
					c.markEndpointFailureLease(lease)
				}
				if attempt < maxAttempts {
					log.Printf("[carrier] relay returned HTTP %d non-batch payload via %s (attempt %d/%d); retrying alternate endpoint", resp.StatusCode, shortScriptKey(scriptURL), attempt, maxAttempts)
					continue
				}
				if errReason != "" {
					log.Printf("[carrier] relay returned HTTP %d non-batch payload via %s: %s", resp.StatusCode, shortScriptKey(scriptURL), errReason)
				} else {
					log.Printf("[carrier] relay returned HTTP %d non-batch payload via %s (likely HTML/JSON error page)", resp.StatusCode, shortScriptKey(scriptURL))
				}
				if errKind == relayErrorHard {
					return c.failDrainedBatch(frames, drainedIDs, "relay returned terminal hard error after draining TX batch")
				}
				return c.failOrRollbackRelayHTTPStatus(frames, drainedIDs, drainSnaps, "relay returned terminal HTTP error after draining TX batch")
			}
			switch resp.StatusCode {
			case http.StatusForbidden: // 403
				// A plain HTTP 403 is ambiguous: Apps Script may be quota-blocked,
				// but a single deployment can also be forbidden because its access
				// settings are stale/wrong. Daily quota HTML/JSON bodies are
				// classified below as account-wide quota; status-only 403 stays
				// endpoint-local so one bad deployment ID cannot quarantine healthy
				// siblings on the same Google account.
				c.recordEndpointFailureReasonLease(lease, endpointFailureHTTPError)
				c.markEndpointHardFailureLease(lease)
				if attempt < maxAttempts {
					log.Printf("[carrier] relay returned HTTP 403 via %s (attempt %d/%d); retrying alternate endpoint", shortScriptKey(scriptURL), attempt, maxAttempts)
					continue
				}
				if c.useFronting {
					log.Printf("[carrier] relay returned HTTP 403 via %s (deployment forbidden or quota/auth page without a readable body; verify Apps Script access is set to Anyone)", shortScriptKey(scriptURL))
				} else {
					log.Printf("[carrier] relay returned HTTP 403 via %s (direct relay forbidden; verify relay_urls points to your goose-server /tunnel URL and any reverse proxy allows POST)", shortScriptKey(scriptURL))
				}
			case http.StatusTooManyRequests: // 429
				c.recordEndpointFailureReasonLease(lease, endpointFailureRateLimit)
				c.markEndpoint429Lease(lease)
				if attempt < maxAttempts {
					log.Printf("[carrier] relay returned HTTP 429 (rate-limited) via %s (attempt %d/%d); retrying alternate endpoint", shortScriptKey(scriptURL), attempt, maxAttempts)
					continue
				}
				log.Printf("[carrier] relay returned HTTP 429 (rate-limited) via %s; backing off and will retry automatically", shortScriptKey(scriptURL))
			default:
				c.recordEndpointFailureReasonLease(lease, endpointFailureHTTPError)
				c.markEndpointFailureLease(lease)
				if attempt < maxAttempts {
					log.Printf("[carrier] relay returned HTTP %d via %s (attempt %d/%d); retrying alternate endpoint", resp.StatusCode, shortScriptKey(scriptURL), attempt, maxAttempts)
					continue
				}
				if c.useFronting {
					log.Printf("[carrier] relay returned HTTP %d via %s (verify Apps Script deployment is live and access is set to Anyone)", resp.StatusCode, shortScriptKey(scriptURL))
				} else {
					log.Printf("[carrier] relay returned HTTP %d via %s (verify relay_urls points to goose-server /tunnel and the VPS firewall allows the port)", resp.StatusCode, shortScriptKey(scriptURL))
				}
			}
			return c.failOrRollbackRelayHTTPStatus(frames, drainedIDs, drainSnaps, "relay returned terminal HTTP error after draining TX batch")
		}
		if len(respBody) == 0 {
			c.recordEndpointFailureReasonLease(lease, endpointFailureEmpty204)
			c.markEndpointHardFailureLease(lease)
			if attempt < maxAttempts {
				log.Printf("[carrier] relay returned empty 200 response via %s (attempt %d/%d); retrying alternate endpoint", shortScriptKey(scriptURL), attempt, maxAttempts)
				continue
			}
			log.Printf("[carrier] relay returned empty 200 response via %s (likely tunnel_key/protocol mismatch); dropping drained batch", shortScriptKey(scriptURL))
			return c.failDrainedBatch(frames, drainedIDs, "relay returned empty 200 response after draining TX batch")
		}
		if len(respBody) > maxRelayResponseBodyBytes {
			c.recordEndpointFailureReasonLease(lease, endpointFailureHTTPError)
			c.markEndpointFailureLease(lease)
			if attempt < maxAttempts {
				log.Printf("[carrier] relay response too large via %s (attempt %d/%d); retrying alternate endpoint", shortScriptKey(scriptURL), attempt, maxAttempts)
				continue
			}
			log.Printf("[carrier] relay response too large via %s (%d bytes > %d); dropping batch to protect stability", shortScriptKey(scriptURL), len(respBody), maxRelayResponseBodyBytes)
			return c.failDrainedBatch(frames, drainedIDs, "relay response too large after draining TX batch")
		}
		if !c.binaryDirect && isLikelyNonBatchRelayPayload(respBody) {
			errReason, errKind := classifyRelayErrorBodyKind(respBody)
			switch errKind {
			case relayErrorDailyQuota:
				c.recordEndpointFailureReasonLease(lease, endpointFailureQuota)
				c.markEndpointQuotaExhaustedLease(lease)
			case relayErrorRateLimit:
				c.recordEndpointFailureReasonLease(lease, endpointFailureRateLimit)
				c.markEndpoint429Lease(lease)
			case relayErrorHard:
				c.recordEndpointFailureReasonLease(lease, endpointFailureNonBatch)
				c.markEndpointHardFailureLease(lease)
			default:
				c.recordEndpointFailureReasonLease(lease, endpointFailureNonBatch)
				c.markEndpointFailureLease(lease)
			}
			if attempt < maxAttempts {
				log.Printf("[carrier] relay returned non-batch payload via %s (attempt %d/%d); retrying alternate endpoint", shortScriptKey(scriptURL), attempt, maxAttempts)
				continue
			}
			if errReason != "" {
				log.Printf("[carrier] relay returned non-batch payload via %s: %s", shortScriptKey(scriptURL), errReason)
			} else {
				log.Printf("[carrier] relay returned non-batch payload via %s (likely HTML/JSON error page), dropping response", shortScriptKey(scriptURL))
			}
			if c.useFronting && errKind != relayErrorHard {
				return c.rollbackDrainedBatch(frames, drainSnaps)
			}
			return c.failDrainedBatch(frames, drainedIDs, "relay returned non-batch payload after draining TX batch")
		}

		_, rxFrames, decodeErr := c.decodeBatch(respBody)
		if decodeErr != nil {
			c.recordEndpointFailureReasonLease(lease, endpointFailureDecodeError)
			c.markEndpointFailureLease(lease)
			if attempt < maxAttempts {
				log.Printf("[carrier] relay response was invalid via %s (attempt %d/%d): %v; retrying alternate endpoint", shortScriptKey(scriptURL), attempt, maxAttempts, decodeErr)
				continue
			}
			log.Printf("[carrier] relay response was invalid via %s (possibly HTML/error page instead of encrypted data): %v", shortScriptKey(scriptURL), decodeErr)
			return c.failDrainedBatch(frames, drainedIDs, "relay returned invalid batch after draining TX batch")
		}

		for _, f := range rxFrames {
			c.routeRx(f)
		}
		if len(frames) == 0 && len(rxFrames) == 0 {
			c.stats.emptyPolls.Add(1)
		} else {
			c.stats.usefulPolls.Add(1)
		}
		c.markEndpointSuccessWithRTTLease(lease, time.Since(pollStart), len(rxFrames) > 0)
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
	if len(frames) == 0 {
		return false
	}
	if hasDownstreamACKFrame(frames) {
		c.restoreDownstreamACKFrames(frames)
	}
	if len(drainedIDs) == 0 {
		return false
	}
	c.abortSessions(drainedIDs, reason)
	return false
}

func (c *Client) failOrRollbackRelayHTTPStatus(frames []*frame.Frame, drainedIDs [][frame.SessionIDLen]byte, snaps map[[frame.SessionIDLen]byte]*session.DrainSnapshot, reason string) bool {
	if c.binaryDirect || !c.useFronting {
		return c.failDrainedBatch(frames, drainedIDs, reason)
	}
	if len(frames) > 0 && len(drainedIDs) > 0 {
		log.Printf("[carrier] %s; restoring drained TX because Apps Script returned a wrapper-level HTTP status before a tunnel response", reason)
	}
	return c.rollbackDrainedBatch(frames, snaps)
}

func (c *Client) rollbackDrainedBatch(frames []*frame.Frame, snaps map[[frame.SessionIDLen]byte]*session.DrainSnapshot) bool {
	c.restoreDownstreamACKFrames(frames)
	if len(snaps) == 0 {
		return false
	}
	c.rollbackDrained(snaps)
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
	all, _ := c.allEndpointsBlacklistedState()
	return all
}

func (c *Client) allEndpointsBlacklistedState() (bool, bool) {
	c.endpointMu.Lock()
	defer c.endpointMu.Unlock()
	if len(c.endpoints) == 0 {
		return false, false
	}
	now := time.Now()
	allLocalNetworkOffline := true
	for i := range c.endpoints {
		ep := &c.endpoints[i]
		if !c.endpointUnavailableLocked(ep, now) {
			return false, false
		}
		if !ep.localNetworkOffline || ep.quotaExhaustedUntil.After(now) {
			allLocalNetworkOffline = false
		}
	}
	return true, allLocalNetworkOffline
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
		buckets[ep.bucket] = struct{}{}
	}
	return len(buckets)
}

func (c *Client) closeSessionsIfAllEndpointsBlacklisted(reason string) bool {
	if c.streamActive.Load() {
		c.mu.Lock()
		c.endpointOutageStarted = time.Time{}
		c.mu.Unlock()
		return false
	}
	allUnavailable, allLocalNetworkOffline := c.allEndpointsBlacklistedState()
	if !allUnavailable {
		c.mu.Lock()
		c.endpointOutageStarted = time.Time{}
		c.mu.Unlock()
		return false
	}
	now := time.Now()
	c.mu.Lock()
	grace := c.endpointOutageGrace
	if !allLocalNetworkOffline && grace > relayEndpointOutageGraceMax {
		grace = relayEndpointOutageGraceMax
	}
	if c.endpointOutageStarted.IsZero() {
		c.endpointOutageStarted = now
		c.mu.Unlock()
		log.Printf("[carrier] %s; holding active sessions for up to %s while endpoints recover", reason, grace.Round(time.Second))
		return false
	}
	elapsed := now.Sub(c.endpointOutageStarted)
	c.mu.Unlock()
	if elapsed < grace {
		return false
	}
	return c.abortAllSessions(reason) > 0
}

func (c *Client) resetLocalNetworkFailures() int {
	c.endpointMu.Lock()
	defer c.endpointMu.Unlock()
	now := time.Now()
	cleared := 0
	for i := range c.endpoints {
		ep := &c.endpoints[i]
		if !ep.localNetworkOffline || ep.quotaExhaustedUntil.After(now) {
			continue
		}
		ep.blacklistedTill = time.Time{}
		ep.failCount = 0
		ep.localNetworkOffline = false
		cleared++
	}
	return cleared
}

func (c *Client) abortAllSessions(reason string) int {
	c.mu.Lock()
	sessions := make([]*session.Session, 0, len(c.sessions))
	ids := make([][frame.SessionIDLen]byte, 0, len(c.sessions))
	for id, s := range c.sessions {
		sessions = append(sessions, s)
		ids = append(ids, id)
	}
	if len(sessions) == 0 {
		c.mu.Unlock()
		return 0
	}
	c.sessions = make(map[[frame.SessionIDLen]byte]*session.Session)
	c.inFlight = make(map[[frame.SessionIDLen]byte]bool)
	c.txReady = make(map[[frame.SessionIDLen]byte]struct{})
	c.ackReady = make(map[[frame.SessionIDLen]byte]uint64)
	c.ackLatest = make(map[[frame.SessionIDLen]byte]uint64)
	c.ackLastSent = make(map[[frame.SessionIDLen]byte]time.Time)
	c.txReadyOrder = nil
	for _, id := range ids {
		c.debugStarts.Delete(id)
	}
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
		delete(c.ackReady, id)
		delete(c.ackLatest, id)
		delete(c.ackLastSent, id)
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
		var encStats frame.BatchEncodeStats
		body, encStats, err = frame.EncodeBatchBinaryWithStats(c.aead, c.clientID, frames)
		if err == nil {
			c.recordCompressionStats(encStats)
		}
	} else {
		var encStats frame.BatchEncodeStats
		body, encStats, err = frame.EncodeBatchWithStats(c.aead, c.clientID, frames)
		if err == nil {
			c.recordCompressionStats(encStats)
		}
	}
	c.stats.encode.Add(time.Since(start))
	if err == nil {
		c.stats.reqSize.Add(len(body))
		c.stats.wireRatio.Add(len(body), plainSize)
	}
	return body, err
}

func (c *Client) recordCompressionStats(stats frame.BatchEncodeStats) {
	if stats.CompressionAttempted {
		c.stats.compressAttempted.Add(1)
	}
	if stats.CompressionUsed {
		c.stats.compressUsed.Add(1)
	}
	if stats.CompressionSkipped {
		c.stats.compressSkipped.Add(1)
	}
	switch stats.Mode {
	case "zstd":
		c.stats.compressZstd.Add(1)
	default:
		c.stats.compressRaw.Add(1)
	}
	if stats.RawBytes > 0 {
		c.stats.compressRawBytes.Add(uint64(stats.RawBytes))
	}
	if stats.EncodedBytes > 0 {
		c.stats.compressBodyBytes.Add(uint64(stats.EncodedBytes))
	}
	if stats.WireBytes > 0 {
		c.stats.compressWireBytes.Add(uint64(stats.WireBytes))
	}
	if stats.SavedBytes > 0 {
		c.stats.compressSaved.Add(uint64(stats.SavedBytes))
	}
	if stats.LostBytes > 0 {
		c.stats.compressLost.Add(uint64(stats.LostBytes))
	}
}

func (c *Client) decodeBatch(body []byte) ([frame.ClientIDLen]byte, []*frame.Frame, error) {
	start := time.Now()
	defer func() {
		c.stats.decode.Add(time.Since(start))
		c.stats.respSize.Add(len(body))
	}()
	var (
		clientID [frame.ClientIDLen]byte
		frames   []*frame.Frame
		err      error
	)
	if c.binaryDirect {
		clientID, frames, err = frame.DecodeBatchBinary(c.aead, body)
	} else {
		clientID, frames, err = frame.DecodeBatch(c.aead, body)
	}
	if err != nil {
		return clientID, nil, err
	}
	if err := c.validateResponseClientID(clientID); err != nil {
		return clientID, nil, err
	}
	return clientID, frames, nil
}

func (c *Client) validateResponseClientID(clientID [frame.ClientIDLen]byte) error {
	if clientID != c.clientID {
		return fmt.Errorf("batch: response client_id mismatch: got %x want %x", clientID[:4], c.clientID[:4])
	}
	return nil
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
// naturally spread requests across separate TLS sessions.
func (c *Client) pickHTTPClient() *http.Client {
	if len(c.httpClients) == 1 {
		return c.httpClients[0]
	}
	idx := c.nextHTTP.Add(1) - 1
	return c.httpClients[idx%uint64(len(c.httpClients))]
}

func (c *Client) pickRelayEndpoint() (int, string) {
	return c.pickRelayEndpointForPoll(false)
}

func (c *Client) pickRelayEndpointForPoll(isIdlePoll bool) (int, string) {
	lease := c.pickRelayEndpointForPollLease(isIdlePoll)
	return lease.idx, lease.url
}

func (c *Client) pickRelayEndpointForPollLease(isIdlePoll bool) endpointLease {
	now := time.Now()
	idleBucketLimit := 0
	if isIdlePoll {
		activeSessions, _, _ := c.idleSessionSnapshot(now)
		if activeSessions == 0 {
			idleBucketLimit = c.idlePollMaxBuckets
		}
	}

	c.endpointMu.Lock()
	defer c.endpointMu.Unlock()

	n := len(c.endpoints)
	if n == 0 {
		return endpointLease{idx: -1}
	}
	start := c.nextEndpoint % n
	allowedIdleBuckets := c.allowedIdleBucketsLocked(now, idleBucketLimit)
	quotaPressure := c.accountQuotaPressureLocked(now)
	hasUnderQuotaCandidate := false
	for i := 0; i < n; i++ {
		ep := &c.endpoints[i]
		if c.endpointUnavailableLocked(ep, now) {
			continue
		}
		if allowedIdleBuckets != nil {
			if _, ok := allowedIdleBuckets[ep.bucket]; !ok {
				continue
			}
		}
		if quotaPressure[endpointQuotaKey(ep)] < quotaRotateAwayPermille {
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
		if allowedIdleBuckets != nil {
			if _, ok := allowedIdleBuckets[ep.bucket]; !ok {
				continue
			}
		}
		pressure := quotaPressure[endpointQuotaKey(ep)]
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
		if ep.slowSuccesses > 0 && !ep.lastSlowAt.IsZero() && now.Sub(ep.lastSlowAt) <= endpointSlowWindow {
			score += time.Duration(ep.slowSuccesses) * endpointSlowPenalty
		}
		if !ep.lastUsefulAt.IsZero() && now.Sub(ep.lastUsefulAt) <= endpointUsefulWindow {
			score -= endpointUsefulBonus
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
		ep := c.endpoints[bestIdx]
		return endpointLease{
			idx:        bestIdx,
			url:        ep.url,
			bucket:     ep.bucket,
			generation: c.endpointGen,
			check:      true,
		}
	}

	return endpointLease{idx: -1}
}

func (c *Client) pickRelayEndpointForActivePoll() (int, string, string) {
	lease := c.pickRelayEndpointForActivePollLease()
	return lease.idx, lease.url, lease.bucket
}

func (c *Client) pickRelayEndpointForActivePollLease() endpointLease {
	now := time.Now()
	c.endpointMu.Lock()
	defer c.endpointMu.Unlock()

	n := len(c.endpoints)
	if n == 0 {
		return endpointLease{idx: -1}
	}
	slotLimit := c.txSlotsPerBucket
	if slotLimit <= 0 {
		return endpointLease{idx: -1}
	}
	start := c.nextEndpoint % n
	quotaPressure := c.accountQuotaPressureLocked(now)
	hasUnderQuotaCandidate := false
	for i := 0; i < n; i++ {
		ep := &c.endpoints[i]
		if c.endpointUnavailableLocked(ep, now) {
			continue
		}
		if c.activeByBucket[ep.bucket] >= slotLimit {
			continue
		}
		if quotaPressure[endpointQuotaKey(ep)] < quotaRotateAwayPermille {
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
		if c.activeByBucket[ep.bucket] >= slotLimit {
			continue
		}
		pressure := quotaPressure[endpointQuotaKey(ep)]
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
		if ep.slowSuccesses > 0 && !ep.lastSlowAt.IsZero() && now.Sub(ep.lastSlowAt) <= endpointSlowWindow {
			score += time.Duration(ep.slowSuccesses) * endpointSlowPenalty
		}
		if !ep.lastUsefulAt.IsZero() && now.Sub(ep.lastUsefulAt) <= endpointUsefulWindow {
			score -= endpointUsefulBonus
		}
		score += time.Duration(pressure) * quotaScorePenaltyPerMille
		score += time.Duration(ep.dailyCount) * endpointLoadPenaltyPerPoll
		if bestIdx < 0 || score < bestScore {
			bestIdx = idx
			bestScore = score
		}
	}
	if bestIdx < 0 {
		return endpointLease{idx: -1}
	}
	if c.activeByBucket == nil {
		c.activeByBucket = make(map[string]int, c.bucketCount)
	}
	ep := c.endpoints[bestIdx]
	bucket := ep.bucket
	c.activeByBucket[bucket]++
	c.nextEndpoint = (bestIdx + 1) % n
	return endpointLease{
		idx:        bestIdx,
		url:        ep.url,
		bucket:     ep.bucket,
		generation: c.endpointGen,
		check:      true,
	}
}

func (c *Client) pickRelayEndpointForIdlePoll(applyPureDownloadFloor bool) (int, string, string) {
	lease := c.pickRelayEndpointForIdlePollLease(applyPureDownloadFloor)
	return lease.idx, lease.url, lease.bucket
}

func (c *Client) pickRelayEndpointForIdlePollLease(applyPureDownloadFloor bool) endpointLease {
	now := time.Now()
	idleBucketLimit := 0
	activeSessions, _, _ := c.idleSessionSnapshot(now)
	if activeSessions == 0 {
		idleBucketLimit = c.idlePollMaxBuckets
	}

	c.endpointMu.Lock()
	defer c.endpointMu.Unlock()

	n := len(c.endpoints)
	if n == 0 {
		return endpointLease{idx: -1}
	}
	slotLimit := c.idleSlotsPerBucket
	if applyPureDownloadFloor && c.bucketCount <= 1 && slotLimit < pureDownloadIdleCap {
		slotLimit = pureDownloadIdleCap
	}
	if slotLimit <= 0 {
		return endpointLease{idx: -1}
	}
	start := c.nextEndpoint % n
	allowedIdleBuckets := c.allowedIdleBucketsLocked(now, idleBucketLimit)
	quotaPressure := c.accountQuotaPressureLocked(now)
	hasUnderQuotaCandidate := false
	for i := 0; i < n; i++ {
		ep := &c.endpoints[i]
		if c.endpointUnavailableLocked(ep, now) {
			continue
		}
		if allowedIdleBuckets != nil {
			if _, ok := allowedIdleBuckets[ep.bucket]; !ok {
				continue
			}
		}
		if c.idleByBucket[ep.bucket] >= slotLimit {
			continue
		}
		if quotaPressure[endpointQuotaKey(ep)] < quotaRotateAwayPermille {
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
		if allowedIdleBuckets != nil {
			if _, ok := allowedIdleBuckets[ep.bucket]; !ok {
				continue
			}
		}
		if c.idleByBucket[ep.bucket] >= slotLimit {
			continue
		}
		pressure := quotaPressure[endpointQuotaKey(ep)]
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
		if ep.slowSuccesses > 0 && !ep.lastSlowAt.IsZero() && now.Sub(ep.lastSlowAt) <= endpointSlowWindow {
			score += time.Duration(ep.slowSuccesses) * endpointSlowPenalty
		}
		if !ep.lastUsefulAt.IsZero() && now.Sub(ep.lastUsefulAt) <= endpointUsefulWindow {
			score -= endpointUsefulBonus
		}
		score += time.Duration(pressure) * quotaScorePenaltyPerMille
		score += time.Duration(ep.dailyCount) * endpointLoadPenaltyPerPoll
		if bestIdx < 0 || score < bestScore {
			bestIdx = idx
			bestScore = score
		}
	}
	if bestIdx < 0 {
		return endpointLease{idx: -1}
	}
	if c.idleByBucket == nil {
		c.idleByBucket = make(map[string]int, c.bucketCount)
	}
	ep := c.endpoints[bestIdx]
	bucket := ep.bucket
	c.idleByBucket[bucket]++
	c.nextEndpoint = (bestIdx + 1) % n
	return endpointLease{
		idx:        bestIdx,
		url:        ep.url,
		bucket:     ep.bucket,
		generation: c.endpointGen,
		check:      true,
	}
}

func (c *Client) releaseIdleBucketSlot(bucket string) {
	if bucket == "" {
		return
	}
	c.endpointMu.Lock()
	defer c.endpointMu.Unlock()
	if c.idleByBucket[bucket] > 0 {
		c.idleByBucket[bucket]--
	}
}

func (c *Client) releaseActiveBucketSlot(bucket string) {
	if bucket == "" {
		return
	}
	c.endpointMu.Lock()
	defer c.endpointMu.Unlock()
	if c.activeByBucket[bucket] > 0 {
		c.activeByBucket[bucket]--
	}
}

func (c *Client) activeSlotsSaturated() bool {
	c.endpointMu.Lock()
	defer c.endpointMu.Unlock()
	if c.txSlotsPerBucket <= 0 || len(c.endpoints) == 0 {
		return false
	}
	now := time.Now()
	available := false
	for i := range c.endpoints {
		ep := &c.endpoints[i]
		if c.endpointUnavailableLocked(ep, now) {
			continue
		}
		available = true
		if c.activeByBucket[ep.bucket] < c.txSlotsPerBucket {
			return false
		}
	}
	return available
}

func (c *Client) endpointLeaseMatchesLocked(lease endpointLease) bool {
	if lease.idx < 0 || lease.idx >= len(c.endpoints) {
		return false
	}
	if !lease.check {
		return true
	}
	ep := &c.endpoints[lease.idx]
	return c.endpointGen == lease.generation && ep.url == lease.url && ep.bucket == lease.bucket
}

func (c *Client) allowedIdleBucketsLocked(now time.Time, limit int) map[string]struct{} {
	if limit <= 0 {
		return nil
	}
	allowed := make(map[string]struct{}, limit)
	for i := range c.endpoints {
		ep := &c.endpoints[i]
		if c.endpointUnavailableLocked(ep, now) {
			continue
		}
		if _, ok := allowed[ep.bucket]; ok {
			continue
		}
		allowed[ep.bucket] = struct{}{}
		if len(allowed) >= limit {
			break
		}
	}
	if len(allowed) == 0 {
		return nil
	}
	return allowed
}

func (c *Client) endpointUnavailableLocked(ep *relayEndpoint, now time.Time) bool {
	c.touchDailyWindow(ep, now)
	return ep.blacklistedTill.After(now) || ep.quotaExhaustedUntil.After(now)
}

func endpointQuotaKey(ep *relayEndpoint) string {
	if ep.account != "" {
		return "acct:" + ep.account
	}
	sum := sha256.Sum256([]byte(ep.url))
	return "urlsha256:" + hex.EncodeToString(sum[:])
}

type quotaStateFile struct {
	Version int               `json:"version"`
	Entries []quotaStateEntry `json:"entries"`
}

type quotaStateEntry struct {
	Key   string    `json:"key"`
	Until time.Time `json:"until"`
}

func (c *Client) loadQuotaState(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	var state quotaStateFile
	if err := json.Unmarshal(b, &state); err != nil {
		return err
	}
	byKey := make(map[string]time.Time, len(state.Entries))
	now := time.Now()
	for _, entry := range state.Entries {
		key := strings.TrimSpace(entry.Key)
		if key == "" || !entry.Until.After(now) {
			continue
		}
		if prev := byKey[key]; prev.IsZero() || entry.Until.After(prev) {
			byKey[key] = entry.Until
		}
	}
	if len(byKey) == 0 {
		return nil
	}
	c.endpointMu.Lock()
	defer c.endpointMu.Unlock()
	for i := range c.endpoints {
		ep := &c.endpoints[i]
		until := byKey[endpointQuotaKey(ep)]
		if until.IsZero() {
			continue
		}
		ep.quotaExhaustedUntil = until
		ep.blacklistedTill = until
		ep.localNetworkOffline = false
	}
	return nil
}

func (c *Client) saveQuotaState() error {
	path := strings.TrimSpace(c.quotaStatePath)
	if path == "" {
		return nil
	}
	now := time.Now()
	byKey := make(map[string]time.Time)
	c.endpointMu.Lock()
	for i := range c.endpoints {
		ep := &c.endpoints[i]
		c.touchDailyWindow(ep, now)
		if !ep.quotaExhaustedUntil.After(now) {
			continue
		}
		key := endpointQuotaKey(ep)
		if prev := byKey[key]; prev.IsZero() || ep.quotaExhaustedUntil.After(prev) {
			byKey[key] = ep.quotaExhaustedUntil
		}
	}
	c.endpointMu.Unlock()

	state := quotaStateFile{Version: 1, Entries: make([]quotaStateEntry, 0, len(byKey))}
	for key, until := range byKey {
		state.Entries = append(state.Entries, quotaStateEntry{Key: key, Until: until})
	}
	body, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	c.quotaStateMu.Lock()
	defer c.quotaStateMu.Unlock()
	return writeFileAtomic(path, append(body, '\n'), 0o600)
}

func (c *Client) markEndpointSuccess(endpointIdx int) {
	c.markEndpointSuccessWithRTT(endpointIdx, 0, false)
}

func (c *Client) accountQuotaPressureLocked(now time.Time) map[string]int {
	type scriptKey struct {
		key   string
		count uint64
	}
	localUsageByKey := make(map[string]uint64, len(c.endpoints))
	scriptUsageByKey := make(map[string]uint64, len(c.endpoints))
	seenScriptCounts := make(map[scriptKey]struct{}, len(c.endpoints))
	for i := range c.endpoints {
		ep := &c.endpoints[i]
		c.touchDailyWindow(ep, now)
		key := endpointQuotaKey(ep)
		localUsageByKey[key] += ep.dailyCount
		if !ep.scriptCountAt.IsZero() {
			sk := scriptKey{key: key, count: ep.scriptCount}
			if _, seen := seenScriptCounts[sk]; !seen {
				seenScriptCounts[sk] = struct{}{}
				scriptUsageByKey[key] += ep.scriptCount
			}
		}
	}
	pressure := make(map[string]int, len(localUsageByKey))
	for key, localUsage := range localUsageByKey {
		usage := localUsage
		if scriptUsageByKey[key] > usage {
			usage = scriptUsageByKey[key]
		}
		p := int((usage * 1000) / appsScriptDailyQuota)
		if p > 1000 {
			p = 1000
		}
		pressure[key] = p
	}
	for key, scriptUsage := range scriptUsageByKey {
		if _, ok := pressure[key]; ok {
			continue
		}
		p := int((scriptUsage * 1000) / appsScriptDailyQuota)
		if p > 1000 {
			p = 1000
		}
		pressure[key] = p
	}
	return pressure
}

func (c *Client) markEndpointSuccessWithRTT(endpointIdx int, rtt time.Duration, returnedData bool) {
	c.markEndpointSuccessWithRTTLease(endpointLease{idx: endpointIdx}, rtt, returnedData)
}

func (c *Client) markEndpointSuccessWithRTTLease(lease endpointLease, rtt time.Duration, returnedData bool) {
	if rtt > 0 {
		c.stats.endpointRTT.Add(rtt)
	}
	c.endpointMu.Lock()
	if !c.endpointLeaseMatchesLocked(lease) {
		c.endpointMu.Unlock()
		return
	}
	ep := &c.endpoints[lease.idx]
	wasFailing := ep.failCount > 0
	ep.statsOK++
	if rtt > 0 {
		now := time.Now()
		slowOutlier := rtt >= endpointSlowRTT
		if slowOutlier {
			if ep.lastSlowAt.IsZero() || now.Sub(ep.lastSlowAt) > endpointSlowWindow {
				ep.slowSuccesses = 0
			}
			ep.slowSuccesses++
			ep.lastSlowAt = now
		} else if ep.slowSuccesses > 0 {
			ep.slowSuccesses--
			if ep.slowSuccesses == 0 {
				ep.lastSlowAt = time.Time{}
			}
		}
		if !slowOutlier {
			if ep.rttEWMA <= 0 {
				ep.rttEWMA = rtt
			} else {
				ep.rttEWMA = (ep.rttEWMA*7 + rtt) / 8
			}
		}
	}
	if returnedData {
		ep.lastUsefulAt = time.Now()
	}
	now := time.Now()
	url := ep.url
	quotaUntil := ep.quotaExhaustedUntil
	ep.failCount = 0
	if quotaUntil.After(now) {
		ep.blacklistedTill = quotaUntil
	} else {
		ep.blacklistedTill = time.Time{}
		ep.quotaExhaustedUntil = time.Time{}
	}
	ep.localNetworkOffline = false
	c.endpointMu.Unlock()
	if wasFailing && !quotaUntil.After(now) {
		log.Printf("[carrier] endpoint %s recovered (back in rotation)", shortScriptKey(url))
	}
}

// recordEndpointFailureReasonLease records endpoint failure classes against the
// exact endpoint generation that produced the response.
func (c *Client) recordEndpointFailureReasonLease(lease endpointLease, reason endpointFailureReason) {
	c.endpointMu.Lock()
	defer c.endpointMu.Unlock()
	if !c.endpointLeaseMatchesLocked(lease) {
		return
	}
	if reason < 0 || reason >= endpointFailureReasonCount {
		return
	}
	c.endpoints[lease.idx].failureReasons[reason]++
}

func (c *Client) markEndpointLocalNetworkFailure(endpointIdx int) {
	c.markEndpointLocalNetworkFailureLease(endpointLease{idx: endpointIdx})
}

func (c *Client) markEndpointLocalNetworkFailureLease(lease endpointLease) {
	c.endpointMu.Lock()
	if !c.endpointLeaseMatchesLocked(lease) {
		c.endpointMu.Unlock()
		return
	}
	ep := &c.endpoints[lease.idx]
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
// Quota walls don't self-heal in seconds; they can persist for many hours.
// Jump straight to the 5-minute tier (failCount floor = 5 → next hit → 6 → 5 min)
// to avoid hammering a dead endpoint and wasting the failover slot on peers.
func (c *Client) markEndpoint403(endpointIdx int) {
	c.markEndpointFailureWith(endpointIdx, 5)
}

// markEndpoint429Lease handles HTTP 429 (rate-limited). Shorter self-heal than
// a full quota exhaustion: jump to failCount floor = 3 -> next hit -> 4 -> 24 s TTL.
func (c *Client) markEndpoint429Lease(lease endpointLease) {
	c.markEndpointFailureWithLease(lease, 3)
}

// markEndpointHardFailure is used when the response indicates a durable relay
// problem such as auth/quota HTML, key mismatch, or protocol/decode failure.
// Same backoff tier as markEndpoint403.
func (c *Client) markEndpointHardFailure(endpointIdx int) {
	c.markEndpointFailureWith(endpointIdx, 5)
}

func (c *Client) markEndpointFailureLease(lease endpointLease) {
	c.markEndpointFailureWithLease(lease, 0)
}

func (c *Client) markEndpointHardFailureLease(lease endpointLease) {
	c.markEndpointFailureWithLease(lease, 5)
}

func (c *Client) markEndpointQuotaExhausted(endpointIdx int) {
	c.markEndpointQuotaExhaustedLease(endpointLease{idx: endpointIdx})
}

func (c *Client) markEndpointQuotaExhaustedLease(lease endpointLease) {
	c.endpointMu.Lock()
	if !c.endpointLeaseMatchesLocked(lease) {
		c.endpointMu.Unlock()
		return
	}
	now := time.Now()
	ep := &c.endpoints[lease.idx]
	c.touchDailyWindow(ep, now)
	resetAt := ep.dailyResetAt
	if resetAt.IsZero() {
		resetAt = nextQuotaReset(now)
	}
	url := ep.url
	account := ep.account
	scopeAccount := account != ""
	for i := range c.endpoints {
		if scopeAccount {
			if c.endpoints[i].account != account {
				continue
			}
		} else if i != lease.idx {
			continue
		}
		peer := &c.endpoints[i]
		c.touchDailyWindow(peer, now)
		peer.quotaExhaustedUntil = resetAt
		peer.blacklistedTill = resetAt
		peer.localNetworkOffline = false
		if i == lease.idx {
			peer.failCount++
			peer.statsFail++
		}
	}
	c.endpointMu.Unlock()
	log.Printf("[carrier] endpoint %s account=%q quota exhausted until approx %s; rotating away",
		shortScriptKey(url), account, resetAt.Format(time.RFC3339))
	if err := c.saveQuotaState(); err != nil {
		log.Printf("[carrier] WARN: quota state save failed: %v", err)
	}
}

// markEndpointFailureWith is the shared implementation. minFailCount is a floor
// applied before incrementing so callers can skip the slow 3-48 s ramp for
// failure classes known not to self-heal quickly (quota, auth, rate-limit).
// Pass 0 for the standard ramp.
func (c *Client) markEndpointFailureWith(endpointIdx, minFailCount int) {
	c.markEndpointFailureWithLease(endpointLease{idx: endpointIdx}, minFailCount)
}

func (c *Client) markEndpointFailureWithLease(lease endpointLease, minFailCount int) {
	c.endpointMu.Lock()
	if !c.endpointLeaseMatchesLocked(lease) {
		c.endpointMu.Unlock()
		return
	}
	ep := &c.endpoints[lease.idx]
	wasHealthy := ep.failCount == 0
	if minFailCount > 0 && ep.failCount < minFailCount {
		ep.failCount = minFailCount
	}
	ep.failCount++
	ep.statsFail++
	ep.localNetworkOffline = false
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
	} else if failCount == 9 {
		// Notify once when an endpoint reaches hour-scale backoff so the operator
		// knows this deployment is likely quota-exhausted or dead.
		log.Printf("[carrier] endpoint %s repeatedly failing (%d consecutive); now at extended backoff (%s). Consider re-deploying that script.",
			shortScriptKey(url), failCount, ttl.Round(time.Second))
	}
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
		if 15*time.Minute > max {
			return max
		}
		return 15 * time.Minute
	case 8:
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

func (c *Client) drainAll() ([]*frame.Frame, [][frame.SessionIDLen]byte, map[[frame.SessionIDLen]byte]*session.DrainSnapshot) {
	return c.drainAllWithDownstreamACK(true)
}

func (c *Client) drainAllForStream() ([]*frame.Frame, [][frame.SessionIDLen]byte, map[[frame.SessionIDLen]byte]*session.DrainSnapshot) {
	return c.drainAllWithDownstreamACK(false)
}

func (c *Client) drainAllWithDownstreamACK(includeDownstreamACK bool) ([]*frame.Frame, [][frame.SessionIDLen]byte, map[[frame.SessionIDLen]byte]*session.DrainSnapshot) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []*frame.Frame
	var drainedIDs [][frame.SessionIDLen]byte
	var drainSnaps map[[frame.SessionIDLen]byte]*session.DrainSnapshot
	batchCap := maxDrainFramesPerBatch
	if len(c.sessions) >= busySessionThreshold {
		batchCap = maxDrainFramesPerBatchBusy
	}
	remaining := batchCap
	remainingBytes := c.maxRequestBytesPreEncode
	if remainingBytes <= 0 {
		remainingBytes = protocol.MaxRequestBytesPreEncode
	}
	remainingBytes -= batchPlainBaseOverhead
	if remainingBytes < 0 {
		remainingBytes = 0
	}

	now := time.Now()
	if includeDownstreamACK && c.downstreamReplayActive.Load() {
		reserveForTX := 0
		if len(c.txReady) > 0 {
			reserveForTX = 1
		}
		c.refreshDownstreamACKsLocked(now)
		for id, nextSeq := range c.ackReady {
			if remaining <= reserveForTX || remainingBytes <= 0 {
				break
			}
			if _, ok := c.sessions[id]; !ok {
				delete(c.ackReady, id)
				delete(c.ackLatest, id)
				delete(c.ackLastSent, id)
				continue
			}
			payload := protocol.EncodeDownstreamACK(nextSeq)
			ackFrame := &frame.Frame{
				SessionID: id,
				Flags:     frame.FlagACK,
				Payload:   payload,
			}
			ackCost := batchFramePlainLen(ackFrame)
			if ackCost > remainingBytes {
				break
			}
			out = append(out, ackFrame)
			c.stats.ackSent.Add(1)
			c.ackLastSent[id] = now
			delete(c.ackReady, id)
			remaining--
			remainingBytes -= ackCost
		}
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
		payloadBudget := remainingBytes - perSessionCap*maxBatchFramePlainOverhead
		if payloadBudget <= 0 {
			return
		}
		if queuedAt := s.FirstQueuedAt(); !queuedAt.IsZero() {
			c.stats.queueWait.Add(time.Since(queuedAt))
		}
		frames, snap := s.DrainTxLimitedByBudgetTxn(MaxFramePayload, perSessionCap, payloadBudget)
		delete(c.txReady, id) // remove now; OnTx re-adds if more data arrives
		if len(frames) == 0 {
			return
		}
		c.inFlight[id] = true
		drainedIDs = append(drainedIDs, id)
		if snap != nil {
			if drainSnaps == nil {
				drainSnaps = make(map[[frame.SessionIDLen]byte]*session.DrainSnapshot)
			}
			drainSnaps[id] = snap
		}
		out = append(out, frames...)
		for _, f := range frames {
			remainingBytes -= batchFramePlainLen(f)
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
	return out, drainedIDs, drainSnaps
}

func (c *Client) rollbackDrained(snaps map[[frame.SessionIDLen]byte]*session.DrainSnapshot) {
	if len(snaps) == 0 {
		return
	}
	c.mu.Lock()
	type pending struct {
		s    *session.Session
		snap *session.DrainSnapshot
	}
	pendingRollbacks := make([]pending, 0, len(snaps))
	for id, snap := range snaps {
		if s, ok := c.sessions[id]; ok {
			pendingRollbacks = append(pendingRollbacks, pending{s: s, snap: snap})
		}
	}
	c.mu.Unlock()
	for _, p := range pendingRollbacks {
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
			c.markTxReadyLocked(id)
		}
	}
}

func (c *Client) restoreDownstreamACKFrames(frames []*frame.Frame) {
	if !c.downstreamReplayActive.Load() {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, f := range frames {
		if f == nil || !f.HasFlag(frame.FlagACK) {
			continue
		}
		id := f.SessionID
		nextSeq, ok := protocol.DecodeDownstreamACK(f.Payload)
		if !ok {
			nextSeq = c.ackLatest[id]
		}
		if latest := c.ackLatest[id]; latest > nextSeq {
			nextSeq = latest
		}
		if nextSeq == 0 {
			continue
		}
		if _, ok := c.sessions[id]; !ok {
			delete(c.ackReady, id)
			delete(c.ackLatest, id)
			delete(c.ackLastSent, id)
			continue
		}
		c.ackReady[id] = nextSeq
		delete(c.ackLastSent, id)
	}
}

func hasDownstreamACKFrame(frames []*frame.Frame) bool {
	return countDownstreamACKFrames(frames) > 0
}

func countDownstreamACKFrames(frames []*frame.Frame) int {
	var count int
	for _, f := range frames {
		if f == nil || !f.HasFlag(frame.FlagACK) {
			continue
		}
		if _, ok := protocol.DecodeDownstreamACK(f.Payload); ok {
			count++
		}
	}
	return count
}

func (c *Client) refreshDownstreamACKsLocked(now time.Time) {
	for id, nextSeq := range c.ackLatest {
		if nextSeq == 0 {
			continue
		}
		if _, ok := c.sessions[id]; !ok {
			delete(c.ackLatest, id)
			delete(c.ackLastSent, id)
			delete(c.ackReady, id)
			continue
		}
		if _, already := c.ackReady[id]; already {
			continue
		}
		lastSent := c.ackLastSent[id]
		if lastSent.IsZero() || now.Sub(lastSent) >= downstreamACKRefreshInterval {
			c.ackReady[id] = nextSeq
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
		c.mu.Lock()
		delete(c.sessions, f.SessionID)
		delete(c.txReady, f.SessionID)
		delete(c.ackReady, f.SessionID)
		delete(c.ackLatest, f.SessionID)
		delete(c.ackLastSent, f.SessionID)
		c.mu.Unlock()
		c.debugStarts.Delete(f.SessionID)
		s.Abort()
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
			delete(c.ackReady, id)
			delete(c.ackLatest, id)
			delete(c.ackLastSent, id)
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
	if hasASCIIPrefixFold(t, "<!doctype") || hasASCIIPrefixFold(t, "<html") {
		return true
	}
	if hasASCIIPrefixFold(t, "relay_loop_detected") {
		return true
	}
	if hasASCIIPrefixFold(t, "exception:") {
		return true
	}
	if hasASCIIPrefixFold(t, "upstream status ") {
		return true
	}
	if hasASCIIPrefixFold(t, "upstream fetch error:") {
		return true
	}
	const relayErrorPrefixScanBytes = 4096
	scan := t
	if len(scan) > relayErrorPrefixScanBytes {
		scan = scan[:relayErrorPrefixScanBytes]
	}
	lower := bytes.ToLower(scan)
	if bytes.Contains(lower, []byte("upstream status ")) || bytes.Contains(lower, []byte("upstream fetch error:")) {
		return true
	}
	// Base64 batches never begin with JSON object/array delimiters or raw HTTP.
	if t[0] == '{' || t[0] == '[' || bytes.HasPrefix(t, []byte("HTTP/")) {
		return true
	}
	return false
}

func hasASCIIPrefixFold(b []byte, prefix string) bool {
	if len(b) < len(prefix) {
		return false
	}
	for i := 0; i < len(prefix); i++ {
		c := b[i]
		if 'A' <= c && c <= 'Z' {
			c += 'a' - 'A'
		}
		if c != prefix[i] {
			return false
		}
	}
	return true
}

type relayErrorKind int

const (
	relayErrorSoft relayErrorKind = iota
	relayErrorHard
	relayErrorDailyQuota
	relayErrorRateLimit
)

// classifyRelayErrorBody inspects a non-batch response body (HTML or JSON error
// page returned by Apps Script instead of an encrypted payload) and returns a
// human-readable explanation and whether the failure should avoid the generic
// transient retry path. Callers that need exact recovery behavior should use
// classifyRelayErrorBodyKind.
//
// Pattern tables are ported from MasterHttpRelayVPN relay_response.py and cover
// the error categories documented at:
//
//	developers.google.com/apps-script/guides/support/troubleshooting
//	developers.google.com/apps-script/guides/services/quotas
func classifyRelayErrorBody(body []byte) (reason string, hard bool) {
	reason, kind := classifyRelayErrorBodyKind(body)
	return reason, kind != relayErrorSoft
}

func classifyRelayErrorBodyKind(body []byte) (reason string, kind relayErrorKind) {
	trimmed := bytes.TrimSpace(body)
	var upstream struct {
		E      string `json:"e"`
		Status int    `json:"status"`
		Body   string `json:"body"`
	}
	if len(trimmed) > 0 && trimmed[0] == '{' && json.Unmarshal(trimmed, &upstream) == nil && upstream.E == "upstream_status" {
		switch upstream.Status {
		case http.StatusNoContent:
			return "VPS rejected the encrypted batch with HTTP 204 - most likely tunnel_key mismatch between client_config.json and server_config.json", relayErrorHard
		case http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout, http.StatusInternalServerError:
			return fmt.Sprintf("Apps Script reached the relay URL, but the VPS returned HTTP %d - check goose-server, firewall, and the RELAY_URLS /tunnel address", upstream.Status), relayErrorSoft
		default:
			if upstream.Body != "" {
				return fmt.Sprintf("Apps Script relay upstream returned HTTP %d: %s", upstream.Status, snippet([]byte(upstream.Body))), relayErrorSoft
			}
			return fmt.Sprintf("Apps Script relay upstream returned HTTP %d", upstream.Status), relayErrorSoft
		}
	}

	lower := strings.ToLower(string(trimmed))
	if strings.Contains(lower, "relay_loop_detected") {
		return "Apps Script relay loop detected - RELAY_URLS must point to the VPS /tunnel endpoint, not another Apps Script URL", relayErrorHard
	}
	if status, ok := parseUpstreamStatusSentinel(lower); ok {
		switch status {
		case http.StatusNoContent:
			return "VPS rejected the encrypted batch with HTTP 204 - most likely tunnel_key mismatch between client_config.json and server_config.json", relayErrorHard
		case http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout, http.StatusInternalServerError:
			return fmt.Sprintf("Apps Script reached the relay URL, but the VPS returned HTTP %d - check goose-server, firewall, and the RELAY_URLS /tunnel address", status), relayErrorSoft
		default:
			return fmt.Sprintf("Apps Script relay upstream returned HTTP %d", status), relayErrorSoft
		}
	}

	// ── Quota / rate-limit ─────────────────────────────────────────────────
	// "Service invoked too many times for one day: urlfetch."
	// "Bandwidth quota exceeded"
	dailyQuotaReason := "Apps Script quota exhausted (20k requests/day limit) - " +
		"wait up to 24h for the account quota window to reset, " +
		"or deploy Code.gs under a second Google account and add it to script_keys"
	if strings.Contains(lower, "urlfetch") &&
		(strings.Contains(lower, "\u062f\u0631 \u0637\u0648\u0644 \u06cc\u06a9 \u0631\u0648\u0632") ||
			strings.Contains(lower, "\u062f\u0641\u0639\u0627\u062a \u0632\u06cc\u0627\u062f")) {
		return dailyQuotaReason, relayErrorDailyQuota
	}
	dailyQuotaPatterns := []string{
		"service invoked too many times:",
		"service invoked too many times for one day",
		"invoked too many times for one day",
		"service using too much computer time for one day",
		"too much computer time for one day",
		"bandwidth quota exceeded",
		"too much upload bandwidth",
		"too much traffic",
		"daily quota",
		"quota exceeded",
		"daily limit",
	}
	for _, p := range dailyQuotaPatterns {
		if strings.Contains(lower, p) {
			return dailyQuotaReason, relayErrorDailyQuota
		}
	}
	rateLimitPatterns := []string{
		"service invoked too many times in a short time",
		"script invoked too many times per second",
		"too many scripts running simultaneously",
		"too many requests",
		"rate limit",
		"rate-limit",
		"rate limited",
		"rate-limited",
	}
	for _, p := range rateLimitPatterns {
		if strings.Contains(lower, p) {
			return "Apps Script temporarily rate-limited this deployment - backing off briefly and rotating to another script", relayErrorRateLimit
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
			return "Apps Script auth error - check: (1) AES key matches on both sides, " +
				"(2) deployment is set to 'Execute as: Me / Anyone can access', " +
				"(3) script_keys uses the Deployment ID (not the Script ID), " +
				"(4) the owning Google account has authorised the script by running it manually", relayErrorHard
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
			return "Apps Script deployment not found - verify script_keys is the Deployment ID " +
				"(not the Script ID), the deployment is active, and you re-deployed after editing Code.gs", relayErrorHard
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
			return "Apps Script blocked by a Google Workspace admin policy - " +
				"either the target URL is not on the admin's UrlFetch allowlist " +
				"or a required Google service has been disabled by the domain admin", relayErrorHard
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
			return "Google Apps Script server temporarily unavailable - will retry", relayErrorSoft
		}
	}
	if strings.Contains(lower, "upstream fetch error:") || strings.Contains(lower, "exception:") {
		return "Code.gs could not reach your VPS - check goose-server is running, server_port matches RELAY_URLS, and the VPS firewall allows Google's egress IPs", relayErrorSoft
	}

	return "", relayErrorSoft
}

func parseUpstreamStatusSentinel(lower string) (int, bool) {
	const prefix = "upstream status "
	start := strings.Index(lower, prefix)
	if start < 0 {
		return 0, false
	}
	rest := strings.TrimSpace(lower[start+len(prefix):])
	if rest == "" {
		return 0, false
	}
	end := 0
	for end < len(rest) && rest[end] >= '0' && rest[end] <= '9' {
		end++
	}
	if end == 0 {
		return 0, false
	}
	status, err := strconv.Atoi(rest[:end])
	if err != nil {
		return 0, false
	}
	return status, true
}

func safeLogError(err error) string {
	if err == nil {
		return ""
	}
	var urlErr *neturl.Error
	if errors.As(err, &urlErr) {
		op := strings.TrimSpace(urlErr.Op)
		if op == "" {
			op = "request"
		}
		if urlErr.Err == nil {
			return op
		}
		return fmt.Sprintf("%s: %s", op, safeLogError(urlErr.Err))
	}
	return err.Error()
}

type redactedWrappedError struct {
	msg string
	err error
}

func (e redactedWrappedError) Error() string { return e.msg }
func (e redactedWrappedError) Unwrap() error { return e.err }

func safeWrappedError(err error) error {
	if err == nil {
		return nil
	}
	return redactedWrappedError{msg: safeLogError(err), err: err}
}

func shortScriptKey(scriptURL string) string {
	if u, err := neturl.Parse(scriptURL); err == nil && u.Host != "" {
		if strings.EqualFold(u.Hostname(), "script.google.com") {
			parts := strings.Split(strings.Trim(u.EscapedPath(), "/"), "/")
			for i := 0; i < len(parts)-1; i++ {
				if parts[i] == "s" {
					id := parts[i+1]
					if len(id) > 14 {
						return id[:6] + "..." + id[len(id)-6:]
					}
					return id
				}
			}
		}
		return u.Host
	}
	label := strings.TrimSpace(scriptURL)
	if len(label) > 48 {
		return label[:21] + "..." + label[len(label)-21:]
	}
	if label != "" {
		return label
	}
	return "(unknown)"
}
