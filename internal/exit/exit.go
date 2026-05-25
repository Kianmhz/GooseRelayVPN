// Package exit implements the VPS-side HTTP handler. Apps Script POSTs
// AES-encrypted frame batches here; we decrypt, demux by session_id, dial real
// upstream targets on SYN, pump bytes between net.Conn and session, and
// long-poll the response so downstream bytes get delivered with low latency.
package exit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
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
	"golang.org/x/net/proxy"
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
	ActiveDrainWindow = time.Duration(protocol.DefaultActiveDrainWindowMs) * time.Millisecond

	// LongPollWindow is how long the handler holds open a request waiting for
	// downstream bytes. Keep this comfortably below the UrlFetchApp
	// timeoutSeconds used by apps_script/Code.gs.
	LongPollWindow = time.Duration(protocol.DefaultLongPollWindowMs) * time.Millisecond

	// MaxFramePayload caps the bytes per downstream frame (matches carrier).
	// Raised from 128KB: single-seal means no per-frame crypto cost, so fewer
	// larger frames are strictly better (less length-prefix overhead, fewer
	// Unmarshal calls). Must match the value in internal/carrier/client.go.
	MaxFramePayload = protocol.MaxFramePayload

	// upstreamReadBuf is the chunk size for reading from real net.Conn before
	// pushing to session.EnqueueTx (which then chunks into frames). Matches
	// MaxFramePayload so a single TCP read fills exactly one max-sized frame:
	// halves the frames-per-MB count on bulk downloads vs. 128KB, which cuts
	// length-prefix and Unmarshal overhead on the receiving carrier.
	upstreamReadBuf = 256 * 1024

	// coalesceWindow lets us gather a few more frames before responding, which
	// improves throughput for video streams under higher RTT links.
	coalesceWindow = time.Duration(protocol.DefaultCoalesceWindowMs) * time.Millisecond

	// coalesceWindowBusy is used when many sessions are active concurrently:
	// under high fan-out the next batch fills within a few ms, so 25ms of
	// extra accumulation is pure tail latency. Only applied when a) the
	// session count is above busySessionThreshold and b) the current batch
	// is not already large (>= maxDrainFramesPerBatch/2) — large batches
	// are bulk-dominant and benefit more from full coalesce.
	coalesceWindowBusy = time.Duration(protocol.DefaultCoalesceWindowBusyMs) * time.Millisecond

	// coalesceMinFrames is the minimum number of frames in a drain before we
	// bother waiting coalesceWindow. Batches at or below this threshold are
	// almost certainly interactive (TLS handshake, HTTP control frames) and
	// adding 25ms per hop compounds visibly across round-trips.
	coalesceMinFrames = 4

	// maxDrainFramesPerBatch bounds total frames emitted in one HTTP response so
	// one poll does not become a very large base64 body under high concurrency.
	maxDrainFramesPerBatch = protocol.MaxDrainFramesPerBatch

	// Under high fan-out (mobile apps opening many parallel connections), allow
	// a larger but still bounded batch to reduce queueing delay.
	busySessionThreshold       = protocol.BusySessionThreshold
	maxDrainFramesPerBatchBusy = protocol.MaxDrainFramesPerBatchBusy

	// maxResponseBytesPreEncode bounds payload bytes packed into one HTTP
	// response before AES-GCM seal and base64. The default is intentionally
	// below the replay per-session cap so mobile/Apps Script responses are fast
	// to deliver and replay-safe. protocol.MaxResponseBytesPreEncode remains
	// the explicit expert ceiling for stable links with replay disabled.
	maxResponseBytesPreEncode = protocol.DefaultMaxResponseBytesPreEncode

	// dialFailureBackoffBase is the first cooldown after a structural target
	// dial failure. Repeated failures double up to dialFailureBackoffMax, which
	// quiets dead app/proxy targets without broad session caps.
	dialFailureBackoffBase   = 2 * time.Second
	dialFailureBackoffMax    = 60 * time.Second
	dialFailureSuppressAfter = 2
	dialFailureHistoryRetain = 10 * time.Minute
	dialFailureMaxEntries    = 4096
	dialFailurePruneInterval = time.Minute

	// pendingControlMaxFramesPerOwner bounds queued RST/version control frames
	// for one client owner. Normal operation drains these immediately; the cap
	// prevents a valid-key client with many failed sessions from growing memory
	// while offline or never polling again.
	pendingControlMaxFramesPerOwner = maxDrainFramesPerBatchBusy * 4
	pendingControlInactiveTTL       = 2 * time.Minute

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

	// streamDisconnectGrace gives direct-stream clients time to reconnect or
	// fall back to POST polling before stream-owned sessions are aborted. Apps
	// Script/fronted POSTs can take several seconds on mobile networks, so this
	// must be longer than a single slow fallback poll.
	streamDisconnectGrace = 30 * time.Second

	// maxConcurrentSYNDials bounds authenticated upstream dial fan-out per
	// batch. Established DATA/FIN/RST frames are still routed immediately when
	// unrelated SYN dials are slow.
	maxConcurrentSYNDials = 32

	// maxUnauthTunnelReads bounds concurrent body reads/decrypt attempts before
	// a request proves it knows tunnel_key. This keeps public /tunnel endpoints
	// from allocating max_request_body_bytes per attacker connection.
	maxUnauthTunnelReads = 32

	// maxUnauthStreamHandshakes bounds accepted WebSockets that have not yet
	// sent a valid encrypted hello.
	maxUnauthStreamHandshakes = 16

	tunnelReadChunkSize = 32 * 1024
)

var (
	errSessionLimit     = errors.New("exit: session limit reached")
	errSessionCollision = errors.New("exit: session id collision")
	errSessionCanceled  = errors.New("exit: session open canceled")
)
var errRequestTooLarge = errors.New("tunnel request too large")

func readTunnelRequestBody(r io.Reader, contentLength int64, limit int) ([]byte, error) {
	if contentLength > int64(limit) {
		return nil, fmt.Errorf("%w (%d bytes > %d)", errRequestTooLarge, contentLength, limit)
	}
	readLimit := int64(limit)
	if contentLength >= 0 {
		readLimit = contentLength
	}
	lr := &io.LimitedReader{R: r, N: readLimit + 1}
	var body []byte
	if contentLength > 0 {
		body = make([]byte, 0, int(contentLength))
	}
	buf := make([]byte, tunnelReadChunkSize)
	for {
		n, err := lr.Read(buf)
		if n > 0 {
			body = append(body, buf[:n]...)
			if len(body) > limit {
				return nil, fmt.Errorf("%w (%d bytes > %d)", errRequestTooLarge, len(body), limit)
			}
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		if lr.N == 0 {
			if contentLength >= 0 && int64(len(body)) < contentLength {
				return nil, io.ErrUnexpectedEOF
			}
			break
		}
	}
	if contentLength >= 0 && int64(len(body)) != contentLength {
		return nil, io.ErrUnexpectedEOF
	}
	if len(body) > limit {
		return nil, fmt.Errorf("%w (%d bytes > %d)", errRequestTooLarge, len(body), limit)
	}
	return body, nil
}

func acquireSlot(ch chan struct{}) (func(), bool) {
	if ch == nil {
		return func() {}, true
	}
	select {
	case ch <- struct{}{}:
		return func() { <-ch }, true
	default:
		return nil, false
	}
}

// Config is the VPS server's configuration.
type Config struct {
	ListenAddr                    string // "0.0.0.0:8443"
	AESKeyHex                     string // 64-char hex
	DebugTiming                   bool   // when true, log per-session dial breakdown and first-read latency
	AutoTune                      bool   // when true, tune latency windows within fixed safety caps
	StatsJSON                     bool   // when true, emit periodic stats as JSON log lines
	UpstreamProxy                 string // optional "host:port" of a local SOCKS5 proxy (e.g. WARP on 127.0.0.1:40000)
	UpstreamProxyUser             string
	UpstreamProxyPass             string
	Version                       string // build version string (exposed in /healthz and version probe)
	ActiveDrainWindow             time.Duration
	LongPollWindow                time.Duration
	UpstreamDialTimeout           time.Duration
	CoalesceWindow                time.Duration
	CoalesceWindowBusy            time.Duration
	DisableCoalesce               bool
	MaxSessions                   int
	MaxDrainFramesPerSession      int
	MaxRequestBodyBytes           int
	MaxResponseBytesPreEncode     int
	InitialResponseBytesPreEncode int
	SecondResponseBytesPreEncode  int
	DisableInitialResponseCap     bool
	DisableSecondResponseCap      bool
	DownstreamReplayEnabled       bool
}

// Server holds the per-process session state.
type Server struct {
	cfg                           Config
	aead                          *frame.Crypto
	dial                          func(network, address string, timeout time.Duration) (net.Conn, error)
	dialContext                   func(ctx context.Context, network, address string, timeout time.Duration) (net.Conn, error)
	dns                           *dnsCache
	debugTiming                   bool
	autoTune                      bool
	statsJSON                     bool
	version                       string
	timingMu                      sync.RWMutex
	activeDrainWindow             time.Duration
	longPollWindow                time.Duration
	upstreamDialTimeout           time.Duration
	coalesceWindow                time.Duration
	coalesceWindowBusy            time.Duration
	baseActiveDrainWindow         time.Duration
	baseCoalesceWindow            time.Duration
	baseCoalesceWindowBusy        time.Duration
	maxSessions                   int
	maxDrainFramesPerSession      int
	maxRequestBodyBytes           int
	maxResponseBytesPreEncode     int
	initialResponseBytesPreEncode int
	secondResponseBytesPreEncode  int
	downstreamReplayEnabled       bool
	replay                        *downstreamReplayManager
	sessionCount                  atomic.Int32

	mu             sync.Mutex
	sessions       map[[frame.SessionIDLen]byte]*session.Session
	opening        map[[frame.SessionIDLen]byte]*pendingOpenSession
	sessionOwners  map[[frame.SessionIDLen]byte][frame.ClientIDLen]byte // sessionID -> owning clientID
	txReady        map[[frame.SessionIDLen]byte]struct{}                // sessions with pending TX frames
	ownerReady     map[[frame.ClientIDLen]byte][][frame.SessionIDLen]byte
	streamInFlight map[[frame.SessionIDLen]byte]*session.Session // transactional direct-stream drains currently writing
	firstReply     map[[frame.SessionIDLen]byte]struct{}         // sessions whose first downstream batch hasn't been sent yet
	responseStage  map[[frame.SessionIDLen]byte]int              // successful downstream response count per session, capped after ramp-up
	upstreams      map[[frame.SessionIDLen]byte]net.Conn         // upstream conn per session, kept so GC can force-close
	lastActivity   map[[frame.SessionIDLen]byte]time.Time        // last time the client sent a frame for this session
	dialFail       map[string]dialFailureState
	pendingRSTs    map[[frame.ClientIDLen]byte][]*frame.Frame // RSTs queued per requesting client
	pendingCtrl    map[[frame.ClientIDLen]byte][]*frame.Frame // control responses queued per client
	streamGen      map[[frame.ClientIDLen]byte]uint64         // increments on each direct stream reconnect
	activeStreams  map[[frame.ClientIDLen]byte]uint64         // currently connected direct stream generation per client
	streamStopOnce sync.Once
	streamStopCh   chan struct{}
	postActivity   map[[frame.ClientIDLen]byte]time.Time // last successful POST poll per client
	dialFailPruned time.Time
	// clientInstances tracks stable client instance labels announced by
	// version probes. A fresh process run can use this to close stale sessions
	// from older random clientIDs without resetting unrelated clients that
	// share the same tunnel key.
	clientInstances       map[string]map[[frame.ClientIDLen]byte]struct{}
	clientInstanceByOwner map[[frame.ClientIDLen]byte]string

	unauthTunnelReads      chan struct{}
	unauthStreamHandshakes chan struct{}

	// activity is a per-client wake channel. handleTunnel waits on the
	// channel for its own clientID; openSession's TX callback kicks the
	// owning client's channel. This stops one client's traffic from
	// repeatedly waking another client's idle long-poll, which would
	// otherwise return empty and burn through HTTP requests.
	activity map[[frame.ClientIDLen]byte]chan struct{}
	stats    serverStats

	// upstreamReadPool is a sync.Pool of upstreamReadBuf (256KiB) buffers
	// reused across upstream pump goroutines.
	upstreamReadPool sync.Pool
}

type pendingOpenSession struct {
	owner    [frame.ClientIDLen]byte
	done     chan struct{}
	cancel   context.CancelFunc
	sess     *session.Session
	err      error
	canceled bool
}

type dialFailureState struct {
	until    time.Time
	updated  time.Time
	failures uint8
}

// serverStats holds atomic counters surfaced periodically by runStatsLoop.
type serverStats struct {
	requests             atomic.Uint64
	framesIn             atomic.Uint64
	framesOut            atomic.Uint64
	bytesIn              atomic.Uint64
	bytesOut             atomic.Uint64
	sessionsOpen         atomic.Uint64
	sessionsClose        atomic.Uint64
	dialsOK              atomic.Uint64
	dialsFail            atomic.Uint64
	dialsSuppressed      atomic.Uint64
	dialAttempts         atomic.Uint64
	dialRaceWins         atomic.Uint64
	dialIPv4             atomic.Uint64
	dialIPv6             atomic.Uint64
	dialProxy            atomic.Uint64
	rstSent              atomic.Uint64
	decodeFailures       atomic.Uint64
	ackReceived          atomic.Uint64
	replayFrames         atomic.Uint64
	replayBytes          atomic.Uint64
	replayPruned         atomic.Uint64
	replayDropped        atomic.Uint64
	replayDroppedCap     atomic.Uint64
	replayDroppedExpired atomic.Uint64
	compressAttempted    atomic.Uint64
	compressUsed         atomic.Uint64
	compressSkipped      atomic.Uint64
	compressRaw          atomic.Uint64
	compressZstd         atomic.Uint64
	compressRawBytes     atomic.Uint64
	compressBodyBytes    atomic.Uint64
	compressWireBytes    atomic.Uint64
	compressSaved        atomic.Uint64
	compressLost         atomic.Uint64

	queueWait metrics.DurationWindow
	encode    metrics.DurationWindow
	decode    metrics.DurationWindow
	reqSize   metrics.SizeBuckets
	respSize  metrics.SizeBuckets
	wireRatio metrics.RatioBuckets
}

// New constructs an exit Server.
func New(cfg Config) (*Server, error) {
	aead, err := frame.NewCryptoFromHexKey(cfg.AESKeyHex)
	if err != nil {
		return nil, err
	}
	dialFn, dialCtxFn := dialFuncs(cfg.UpstreamProxy, cfg.UpstreamProxyUser, cfg.UpstreamProxyPass)
	activeDrainWindow := cfg.ActiveDrainWindow
	if activeDrainWindow <= 0 {
		activeDrainWindow = ActiveDrainWindow
	}
	longPollWindow := cfg.LongPollWindow
	if longPollWindow <= 0 {
		longPollWindow = LongPollWindow
	}
	upstreamDialTimeout := cfg.UpstreamDialTimeout
	if upstreamDialTimeout <= 0 {
		upstreamDialTimeout = time.Duration(protocol.DefaultUpstreamDialTimeoutMs) * time.Millisecond
	}
	resolvedCoalesceWindow := cfg.CoalesceWindow
	if resolvedCoalesceWindow < 0 {
		resolvedCoalesceWindow = 0
	}
	if resolvedCoalesceWindow == 0 && cfg.CoalesceWindowBusy == 0 && !cfg.DisableCoalesce {
		resolvedCoalesceWindow = coalesceWindow
	}
	resolvedCoalesceWindowBusy := cfg.CoalesceWindowBusy
	if resolvedCoalesceWindowBusy < 0 {
		resolvedCoalesceWindowBusy = 0
	}
	if resolvedCoalesceWindowBusy == 0 && resolvedCoalesceWindow > 0 {
		resolvedCoalesceWindowBusy = coalesceWindowBusy
	}
	resolvedMaxResponseBytesPreEncode := cfg.MaxResponseBytesPreEncode
	if resolvedMaxResponseBytesPreEncode <= 0 {
		resolvedMaxResponseBytesPreEncode = maxResponseBytesPreEncode
	}
	resolvedInitialResponseBytesPreEncode := cfg.InitialResponseBytesPreEncode
	if cfg.DisableInitialResponseCap {
		resolvedInitialResponseBytesPreEncode = 0
	} else if resolvedInitialResponseBytesPreEncode <= 0 {
		resolvedInitialResponseBytesPreEncode = protocol.InitialResponseBytesPreEncode
	}
	if resolvedInitialResponseBytesPreEncode > resolvedMaxResponseBytesPreEncode {
		resolvedInitialResponseBytesPreEncode = resolvedMaxResponseBytesPreEncode
	}
	resolvedSecondResponseBytesPreEncode := cfg.SecondResponseBytesPreEncode
	if cfg.DisableSecondResponseCap {
		resolvedSecondResponseBytesPreEncode = 0
	} else if resolvedSecondResponseBytesPreEncode <= 0 {
		resolvedSecondResponseBytesPreEncode = protocol.SecondResponseBytesPreEncode
	}
	if resolvedSecondResponseBytesPreEncode > resolvedMaxResponseBytesPreEncode {
		resolvedSecondResponseBytesPreEncode = resolvedMaxResponseBytesPreEncode
	}
	resolvedMaxRequestBodyBytes := cfg.MaxRequestBodyBytes
	if resolvedMaxRequestBodyBytes <= 0 {
		resolvedMaxRequestBodyBytes = protocol.MaxRequestBodyBytes
	}
	resolvedMaxSessions := cfg.MaxSessions
	if resolvedMaxSessions <= 0 {
		resolvedMaxSessions = protocol.DefaultMaxServerSessions
	}
	resolvedMaxDrainFramesPerSession := cfg.MaxDrainFramesPerSession
	if resolvedMaxDrainFramesPerSession <= 0 {
		resolvedMaxDrainFramesPerSession = protocol.DefaultMaxDrainFramesPerSession
	}
	var replay *downstreamReplayManager
	if cfg.DownstreamReplayEnabled {
		replay = newDownstreamReplayManager(0, 0, 0, 0, 0)
	}
	s := &Server{
		cfg:                           cfg,
		aead:                          aead,
		dial:                          dialFn,
		dialContext:                   dialCtxFn,
		dns:                           newDNSCache(),
		debugTiming:                   cfg.DebugTiming,
		autoTune:                      cfg.AutoTune,
		statsJSON:                     cfg.StatsJSON,
		version:                       cfg.Version,
		activeDrainWindow:             activeDrainWindow,
		longPollWindow:                longPollWindow,
		upstreamDialTimeout:           upstreamDialTimeout,
		coalesceWindow:                resolvedCoalesceWindow,
		coalesceWindowBusy:            resolvedCoalesceWindowBusy,
		baseActiveDrainWindow:         activeDrainWindow,
		baseCoalesceWindow:            resolvedCoalesceWindow,
		baseCoalesceWindowBusy:        resolvedCoalesceWindowBusy,
		maxSessions:                   resolvedMaxSessions,
		maxDrainFramesPerSession:      resolvedMaxDrainFramesPerSession,
		maxRequestBodyBytes:           resolvedMaxRequestBodyBytes,
		maxResponseBytesPreEncode:     resolvedMaxResponseBytesPreEncode,
		initialResponseBytesPreEncode: resolvedInitialResponseBytesPreEncode,
		secondResponseBytesPreEncode:  resolvedSecondResponseBytesPreEncode,
		downstreamReplayEnabled:       cfg.DownstreamReplayEnabled,
		replay:                        replay,
		sessions:                      make(map[[frame.SessionIDLen]byte]*session.Session),
		opening:                       make(map[[frame.SessionIDLen]byte]*pendingOpenSession),
		sessionOwners:                 make(map[[frame.SessionIDLen]byte][frame.ClientIDLen]byte),
		txReady:                       make(map[[frame.SessionIDLen]byte]struct{}),
		ownerReady:                    make(map[[frame.ClientIDLen]byte][][frame.SessionIDLen]byte),
		streamInFlight:                make(map[[frame.SessionIDLen]byte]*session.Session),
		firstReply:                    make(map[[frame.SessionIDLen]byte]struct{}),
		responseStage:                 make(map[[frame.SessionIDLen]byte]int),
		upstreams:                     make(map[[frame.SessionIDLen]byte]net.Conn),
		lastActivity:                  make(map[[frame.SessionIDLen]byte]time.Time),
		dialFail:                      make(map[string]dialFailureState),
		pendingRSTs:                   make(map[[frame.ClientIDLen]byte][]*frame.Frame),
		pendingCtrl:                   make(map[[frame.ClientIDLen]byte][]*frame.Frame),
		streamGen:                     make(map[[frame.ClientIDLen]byte]uint64),
		activeStreams:                 make(map[[frame.ClientIDLen]byte]uint64),
		streamStopCh:                  make(chan struct{}),
		postActivity:                  make(map[[frame.ClientIDLen]byte]time.Time),
		clientInstances:               make(map[string]map[[frame.ClientIDLen]byte]struct{}),
		clientInstanceByOwner:         make(map[[frame.ClientIDLen]byte]string),
		unauthTunnelReads:             make(chan struct{}, maxUnauthTunnelReads),
		unauthStreamHandshakes:        make(chan struct{}, maxUnauthStreamHandshakes),
		activity:                      make(map[[frame.ClientIDLen]byte]chan struct{}),
	}
	s.upstreamReadPool.New = func() interface{} {
		buf := make([]byte, upstreamReadBuf)
		return &buf
	}
	return s, nil
}

// dialFuncs returns timeout- and context-aware dial functions. When proxyAddr
// is non-empty it routes all outbound connections through the SOCKS5 proxy at
// that address; otherwise it falls back to direct TCP dials.
func dialFuncs(proxyAddr, proxyUser, proxyPass string) (
	func(network, address string, timeout time.Duration) (net.Conn, error),
	func(ctx context.Context, network, address string, timeout time.Duration) (net.Conn, error),
) {
	if proxyAddr == "" {
		ctxDial := func(ctx context.Context, network, address string, timeout time.Duration) (net.Conn, error) {
			ctx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			d := net.Dialer{Timeout: timeout}
			return d.DialContext(ctx, network, address)
		}
		return net.DialTimeout, ctxDial
	}
	forward := &net.Dialer{Timeout: 15 * time.Second}
	var auth *proxy.Auth
	if proxyUser != "" || proxyPass != "" {
		auth = &proxy.Auth{User: proxyUser, Password: proxyPass}
	}
	d, err := proxy.SOCKS5("tcp", proxyAddr, auth, forward)
	if err != nil {
		log.Printf("[exit] upstream_proxy: failed to build SOCKS5 dialer: %v - falling back to direct", err)
		ctxDial := func(ctx context.Context, network, address string, timeout time.Duration) (net.Conn, error) {
			ctx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			d := net.Dialer{Timeout: timeout}
			return d.DialContext(ctx, network, address)
		}
		return net.DialTimeout, ctxDial
	}
	cd, ok := d.(proxy.ContextDialer)
	if !ok {
		ctxDial := func(ctx context.Context, _ string, address string, timeout time.Duration) (net.Conn, error) {
			ctx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			type dialOutcome struct {
				conn net.Conn
				err  error
			}
			done := make(chan dialOutcome, 1)
			go func() {
				conn, err := d.Dial("tcp", address)
				if ctx.Err() != nil {
					if conn != nil {
						_ = conn.Close()
					}
					return
				}
				select {
				case done <- dialOutcome{conn: conn, err: err}:
				case <-ctx.Done():
					if conn != nil {
						_ = conn.Close()
					}
				}
			}()
			select {
			case out := <-done:
				return out.conn, out.err
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		timeoutDial := func(network, address string, timeout time.Duration) (net.Conn, error) {
			return ctxDial(context.Background(), network, address, timeout)
		}
		return timeoutDial, ctxDial
	}
	ctxDial := func(ctx context.Context, _ string, address string, timeout time.Duration) (net.Conn, error) {
		ctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		return cd.DialContext(ctx, "tcp", address)
	}
	timeoutDial := func(network, address string, timeout time.Duration) (net.Conn, error) {
		return ctxDial(context.Background(), network, address, timeout)
	}
	return timeoutDial, ctxDial
}

// ListenAndServe blocks. It binds an HTTP listener on cfg.ListenAddr with one
// route, POST /tunnel, that handles batched encrypted frames.
func (s *Server) ListenAndServe() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/tunnel", s.handleTunnel)
	mux.HandleFunc("/stream", s.handleStream)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		payload, err := json.Marshal(map[string]interface{}{
			"ok":       true,
			"version":  s.version,
			"protocol": protocol.ProtocolVersion,
		})
		if err != nil {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(payload)
	})
	httpSrv := &http.Server{
		Addr:              s.cfg.ListenAddr,
		Handler:           mux,
		ReadTimeout:       30 * time.Second,
		ReadHeaderTimeout: 3 * time.Second,
		MaxHeaderBytes:    4096,
		// WriteTimeout intentionally generous — long-poll responses can take
		// up to LongPollWindow to start writing.
		WriteTimeout: s.longPollWindow + 10*time.Second,
	}

	// Background loops that share the lifetime of the HTTP server.
	bgCtx, cancelBg := context.WithCancel(context.Background())
	defer cancelBg()
	go s.runStatsLoop(bgCtx)
	go s.runIdleGCLoop(bgCtx)
	if s.autoTune {
		go s.runAutoTuneLoop(bgCtx)
	}

	log.Printf("[exit] listening on %s", s.cfg.ListenAddr)
	return httpSrv.ListenAndServe()
}

func (s *Server) ListenAndServeContext(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/tunnel", s.handleTunnel)
	mux.HandleFunc("/stream", s.handleStream)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		payload, err := json.Marshal(map[string]interface{}{
			"ok":       true,
			"version":  s.version,
			"protocol": protocol.ProtocolVersion,
		})
		if err != nil {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(payload)
	})
	httpSrv := s.httpServer(mux)

	bgCtx, cancelBg := context.WithCancel(ctx)
	defer cancelBg()
	go s.runStatsLoop(bgCtx)
	go s.runIdleGCLoop(bgCtx)
	if s.autoTune {
		go s.runAutoTuneLoop(bgCtx)
	}

	log.Printf("[exit] listening on %s", s.cfg.ListenAddr)
	errCh := make(chan error, 1)
	go func() { errCh <- httpSrv.ListenAndServe() }()

	select {
	case err := <-errCh:
		cancelBg()
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		s.shutdownStreams()
		cancelBg()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		shutdownErr := httpSrv.Shutdown(shutdownCtx)
		s.abortAllSessions("server shutting down")
		err := <-errCh
		if shutdownErr != nil {
			return shutdownErr
		}
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

func (s *Server) httpServer(handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              s.cfg.ListenAddr,
		Handler:           handler,
		ReadTimeout:       30 * time.Second,
		ReadHeaderTimeout: 3 * time.Second,
		MaxHeaderBytes:    4096,
		WriteTimeout:      s.longPollWindow + 10*time.Second,
	}
}

func (s *Server) handleTunnel(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	s.stats.requests.Add(1)
	releaseRead, ok := acquireSlot(s.unauthTunnelReads)
	if !ok {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	defer func() {
		if releaseRead != nil {
			releaseRead()
		}
	}()
	body, err := readTunnelRequestBody(r.Body, r.ContentLength, s.maxRequestBodyBytes)
	if err != nil {
		log.Printf("[exit] read body: %v", err)
		if errors.Is(err, errRequestTooLarge) {
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	binaryResponse := isBinaryTunnelRequest(r)
	clientID, rxFrames, err := s.decodeRequestBatch(body, binaryResponse)
	if err != nil {
		s.stats.decodeFailures.Add(1)
		// Decode failure on the very first batch from a client almost always
		// means the AES key on the client does not match this server's key.
		log.Printf("[exit] decode batch failed: %v (likely tunnel_key mismatch - confirm client config matches this server's tunnel_key)", err)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	releaseRead()
	releaseRead = nil
	s.markPostActivity(clientID, time.Now())

	if len(rxFrames) > 0 {
		var bytesIn uint64
		for _, f := range rxFrames {
			bytesIn += uint64(len(f.Payload))
		}
		s.stats.framesIn.Add(uint64(len(rxFrames)))
		s.stats.bytesIn.Add(bytesIn)
	}

	// Route incoming frames asynchronously. SYN frames may spend the whole
	// upstream dial timeout on a dead target; waiting here would hold the HTTP
	// response hostage and delay unrelated downstream bytes already queued for
	// this client. The drain loop below is woken by session OnTx/queued control
	// frames, so fast handshakes still return in this response while slow dials
	// finish in the background.
	hasSYN := false
	for _, f := range rxFrames {
		if f != nil && f.HasFlag(frame.FlagSYN) {
			hasSYN = true
			break
		}
	}
	if len(rxFrames) > 0 && hasSYN {
		routeTimeout := s.upstreamDialTimeout + time.Second
		if routeTimeout <= time.Second {
			routeTimeout = time.Duration(protocol.DefaultUpstreamDialTimeoutMs)*time.Millisecond + time.Second
		}
		routeCtx, cancelRoute := context.WithTimeout(context.WithoutCancel(r.Context()), routeTimeout)
		done := s.routeIncomingBatchContextAsync(routeCtx, rxFrames, clientID)
		go func() {
			select {
			case <-done:
			case <-s.streamStopCh:
			}
			cancelRoute()
		}()
	} else if len(rxFrames) > 0 {
		s.routeIncomingBatchContext(r.Context(), rxFrames, clientID)
	}

	// Capture the per-client wake channel before entering the wait loop so a
	// kick that fires between drainAll() returning empty and us blocking on
	// the channel is not lost.
	wakeCh := s.activityFor(clientID)

	// Active batches use a shorter wait to avoid stalling unrelated sessions,
	// while empty polls keep long-poll behavior for push responsiveness.
	deadline := time.Now().Add(s.drainWindow(rxFrames))
	waitTimer := time.NewTimer(time.Hour)
	if !waitTimer.Stop() {
		<-waitTimer.C
	}
	defer waitTimer.Stop()
	for {
		txFrames, urgent := s.drainReplay(clientID, s.maxResponseBytesPreEncode)
		replayed := len(txFrames) > 0
		if replayed {
			controlFrameBudget := maxDrainFramesPerBatch - len(txFrames)
			if len(s.sessions) >= busySessionThreshold {
				controlFrameBudget = maxDrainFramesPerBatchBusy - len(txFrames)
			}
			controlByteBudget := s.maxResponseBytesPreEncode - framePayloadBytes(txFrames)
			control, controlUrgent := s.drainPendingControlLimited(clientID, controlFrameBudget, controlByteBudget)
			if len(control) > 0 {
				txFrames = append(txFrames, control...)
				urgent = urgent || controlUrgent
			}
		}
		if len(txFrames) == 0 {
			txFrames, urgent = s.drainAll(clientID, s.maxResponseBytesPreEncode)
		}
		if len(txFrames) > 0 {
			// Track running payload bytes so the coalesce loop respects the
			// same response-size budget across multiple drainAll calls.
			var totalBytes int
			for _, f := range txFrames {
				totalBytes += len(f.Payload)
			}
			// Coalesce bursts into one response to reduce per-request overhead,
			// but only when the batch is large enough to be bulk/video traffic.
			// Small batches (≤ coalesceMinFrames) are interactive; adding a
			// 25ms wait there compounds latency across every TLS round-trip.
			// Urgent batches (RSTs, first downstream after SYN) skip coalesce
			// unconditionally so connection setup is not delayed.
			if !replayed && !urgent && len(txFrames) > coalesceMinFrames && totalBytes < s.maxResponseBytesPreEncode {
				coalesceDeadline := time.Now().Add(s.coalesceDuration(len(txFrames)))
				coalesceTimer := time.NewTimer(time.Hour)
				if !coalesceTimer.Stop() {
					<-coalesceTimer.C
				}
			coalesceLoop:
				for {
					if time.Now().After(coalesceDeadline) || totalBytes >= s.maxResponseBytesPreEncode {
						break coalesceLoop
					}
					remainingCoalesce := time.Until(coalesceDeadline)
					resetExitTimer(coalesceTimer, remainingCoalesce)
					select {
					case <-r.Context().Done():
						stopExitTimer(coalesceTimer)
						break coalesceLoop
					case <-wakeCh:
						stopExitTimer(coalesceTimer)
						more, moreUrgent := s.drainAll(clientID, s.maxResponseBytesPreEncode-totalBytes)
						for _, f := range more {
							totalBytes += len(f.Payload)
						}
						txFrames = append(txFrames, more...)
						if moreUrgent {
							break coalesceLoop
						}
					case <-coalesceTimer.C:
						break coalesceLoop
					}
				}
				stopExitTimer(coalesceTimer)
			}

			if s.replay != nil && !replayed {
				dropped := s.replay.track(clientID, txFrames, time.Now())
				if len(dropped) > 0 {
					n := s.abortDownstreamSessions(clientID, dropped, "downstream replay buffer cap exceeded")
					if n > 0 {
						s.stats.replayDropped.Add(uint64(n))
						s.stats.replayDroppedCap.Add(uint64(n))
					}
					txFrames = filterFramesExcludingSessions(txFrames, dropped)
					controlFrameBudget := maxDrainFramesPerBatch - len(txFrames)
					if len(s.sessions) >= busySessionThreshold {
						controlFrameBudget = maxDrainFramesPerBatchBusy - len(txFrames)
					}
					controlByteBudget := s.maxResponseBytesPreEncode - framePayloadBytes(txFrames)
					control, _ := s.drainPendingControlLimited(clientID, controlFrameBudget, controlByteBudget)
					if len(control) > 0 {
						txFrames = append(txFrames, control...)
					}
				}
			}

			respBody, err := s.encodeResponseBatch(clientID, txFrames, binaryResponse)
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
			w.Header().Set("Content-Type", responseContentType(binaryResponse))
			w.Header().Set("Content-Length", strconv.Itoa(len(respBody)))
			if _, err := w.Write(respBody); err != nil {
				if s.replay != nil {
					log.Printf("[exit] HTTP response write failed after draining frames; retaining replay buffer for owner=%x: %v", clientID[:4], err)
					s.replay.forceReady(clientID)
					s.requeueControlFrames(clientID, txFrames)
					s.kick(clientID)
					return
				}
				s.abortDownstreamSessions(clientID, frameSessionIDs(txFrames), "HTTP response write failed after draining frames")
				return
			}
			return
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			// Empty response (still a valid base64-encoded zero-frame batch).
			respBody, _ := s.encodeResponseBatch(clientID, nil, binaryResponse)
			w.Header().Set("Content-Type", responseContentType(binaryResponse))
			w.Header().Set("Content-Length", strconv.Itoa(len(respBody)))
			_, _ = w.Write(respBody)
			return
		}
		waitFor := remaining
		if s.replay != nil {
			if replayDelay, ok := s.replay.nextReadyDelay(clientID, time.Now()); ok && replayDelay < waitFor {
				waitFor = replayDelay
			}
		}
		resetExitTimer(waitTimer, waitFor)
		select {
		case <-r.Context().Done():
			stopExitTimer(waitTimer)
			return
		case <-wakeCh:
			stopExitTimer(waitTimer)
			// loop and drain
		case <-waitTimer.C:
			// loop one more time, then exit on next iteration
		}
	}
}

func stopExitTimer(t *time.Timer) {
	if !t.Stop() {
		select {
		case <-t.C:
		default:
		}
	}
}

func resetExitTimer(t *time.Timer, d time.Duration) {
	stopExitTimer(t)
	t.Reset(d)
}

func (s *Server) routeIncomingBatchContext(ctx context.Context, rxFrames []*frame.Frame, owner [frame.ClientIDLen]byte) {
	s.routeIncomingBatchContextMode(ctx, rxFrames, owner, true)
}

func (s *Server) routeIncomingBatchContextAsync(ctx context.Context, rxFrames []*frame.Frame, owner [frame.ClientIDLen]byte) <-chan struct{} {
	return s.routeIncomingBatchContextMode(ctx, rxFrames, owner, false)
}

func (s *Server) routeIncomingBatchContextMode(ctx context.Context, rxFrames []*frame.Frame, owner [frame.ClientIDLen]byte, wait bool) <-chan struct{} {
	done := make(chan struct{})
	// Process SYN frames through a bounded worker pool: routeIncoming on a SYN
	// may dial upstream synchronously, and one dead target should not block
	// unrelated sessions. Non-SYN frames for already-established sessions are
	// routed immediately; non-SYN frames sharing a session ID with a SYN in this
	// batch wait until that SYN has registered the session.
	type synGate struct {
		done chan struct{}
		once sync.Once
	}
	var synFrames []*frame.Frame
	synGates := make(map[[frame.SessionIDLen]byte]*synGate)
	for _, f := range rxFrames {
		if f == nil || !f.HasFlag(frame.FlagSYN) {
			continue
		}
		synFrames = append(synFrames, f)
		if _, ok := synGates[f.SessionID]; !ok {
			synGates[f.SessionID] = &synGate{done: make(chan struct{})}
		}
	}

	var synWG sync.WaitGroup
	if len(synFrames) > 0 {
		workers := maxConcurrentSYNDials
		if len(synFrames) < workers {
			workers = len(synFrames)
		}
		jobs := make(chan *frame.Frame, len(synFrames))
		for _, f := range synFrames {
			jobs <- f
		}
		close(jobs)
		for i := 0; i < workers; i++ {
			synWG.Add(1)
			go func() {
				defer synWG.Done()
				for f := range jobs {
					s.routeIncomingContext(ctx, f, owner)
					if gate := synGates[f.SessionID]; gate != nil {
						gate.once.Do(func() { close(gate.done) })
					}
				}
			}()
		}
	}

	followByGate := make(map[[frame.SessionIDLen]byte][]*frame.Frame)
	for _, f := range rxFrames {
		if f == nil || f.HasFlag(frame.FlagSYN) {
			continue
		}
		if gate, waitsForSyn := synGates[f.SessionID]; waitsForSyn {
			_ = gate
			followByGate[f.SessionID] = append(followByGate[f.SessionID], f)
			continue
		}
		s.routeIncomingContext(ctx, f, owner)
	}

	var followWG sync.WaitGroup
	for id, frames := range followByGate {
		gate := synGates[id]
		if gate == nil {
			continue
		}
		frames := append([]*frame.Frame(nil), frames...)
		followWG.Add(1)
		go func() {
			defer followWG.Done()
			select {
			case <-gate.done:
				for _, f := range frames {
					if ctx.Err() != nil {
						return
					}
					s.routeIncomingContext(ctx, f, owner)
				}
			case <-ctx.Done():
			}
		}()
	}

	if wait {
		synWG.Wait()
		followWG.Wait()
		close(done)
		return done
	}
	go func() {
		synWG.Wait()
		followWG.Wait()
		close(done)
	}()
	return done
}

func frameSessionIDs(frames []*frame.Frame) [][frame.SessionIDLen]byte {
	ids := make([][frame.SessionIDLen]byte, 0, len(frames))
	seen := make(map[[frame.SessionIDLen]byte]struct{}, len(frames))
	for _, f := range frames {
		if _, ok := seen[f.SessionID]; ok {
			continue
		}
		seen[f.SessionID] = struct{}{}
		ids = append(ids, f.SessionID)
	}
	return ids
}

func filterFramesExcludingSessions(frames []*frame.Frame, excluded [][frame.SessionIDLen]byte) []*frame.Frame {
	if len(frames) == 0 || len(excluded) == 0 {
		return frames
	}
	excludedSet := make(map[[frame.SessionIDLen]byte]struct{}, len(excluded))
	for _, id := range excluded {
		excludedSet[id] = struct{}{}
	}
	out := frames[:0]
	for _, f := range frames {
		if f == nil {
			continue
		}
		if _, drop := excludedSet[f.SessionID]; drop {
			continue
		}
		out = append(out, f)
	}
	for i := len(out); i < len(frames); i++ {
		frames[i] = nil
	}
	return out
}

func isBinaryTunnelRequest(r *http.Request) bool {
	return hasASCIIPrefixFold(r.Header.Get("Content-Type"), "application/octet-stream")
}

func hasASCIIPrefixFold(s, prefix string) bool {
	return len(s) >= len(prefix) && strings.EqualFold(s[:len(prefix)], prefix)
}

func (s *Server) decodeRequestBatch(body []byte, binary bool) ([frame.ClientIDLen]byte, []*frame.Frame, error) {
	start := time.Now()
	defer func() {
		s.stats.decode.Add(time.Since(start))
		s.stats.reqSize.Add(len(body))
	}()
	if binary {
		return frame.DecodeBatchBinary(s.aead, body)
	}
	return frame.DecodeBatch(s.aead, body)
}

func (s *Server) encodeResponseBatch(clientID [frame.ClientIDLen]byte, frames []*frame.Frame, binary bool) ([]byte, error) {
	start := time.Now()
	plainSize := serverEncodedBatchPlainSize(frames)
	var (
		body []byte
		err  error
	)
	if binary {
		var encStats frame.BatchEncodeStats
		body, encStats, err = frame.EncodeBatchBinaryWithStats(s.aead, clientID, frames)
		if err == nil {
			s.recordCompressionStats(encStats)
		}
	} else {
		var encStats frame.BatchEncodeStats
		body, encStats, err = frame.EncodeBatchWithStats(s.aead, clientID, frames)
		if err == nil {
			s.recordCompressionStats(encStats)
		}
	}
	s.stats.encode.Add(time.Since(start))
	if err == nil {
		s.stats.respSize.Add(len(body))
		s.stats.wireRatio.Add(len(body), plainSize)
	}
	return body, err
}

func (s *Server) recordCompressionStats(stats frame.BatchEncodeStats) {
	if stats.CompressionAttempted {
		s.stats.compressAttempted.Add(1)
	}
	if stats.CompressionUsed {
		s.stats.compressUsed.Add(1)
	}
	if stats.CompressionSkipped {
		s.stats.compressSkipped.Add(1)
	}
	switch stats.Mode {
	case "zstd":
		s.stats.compressZstd.Add(1)
	default:
		s.stats.compressRaw.Add(1)
	}
	if stats.RawBytes > 0 {
		s.stats.compressRawBytes.Add(uint64(stats.RawBytes))
	}
	if stats.EncodedBytes > 0 {
		s.stats.compressBodyBytes.Add(uint64(stats.EncodedBytes))
	}
	if stats.WireBytes > 0 {
		s.stats.compressWireBytes.Add(uint64(stats.WireBytes))
	}
	if stats.SavedBytes > 0 {
		s.stats.compressSaved.Add(uint64(stats.SavedBytes))
	}
	if stats.LostBytes > 0 {
		s.stats.compressLost.Add(uint64(stats.LostBytes))
	}
}

func serverEncodedBatchPlainSize(frames []*frame.Frame) int {
	size := 1 + frame.ClientIDLen + 2
	for _, f := range frames {
		size += 4 + f.EncodedLen()
	}
	return size
}

func responseContentType(binary bool) string {
	if binary {
		return "application/octet-stream"
	}
	return "text/plain"
}

func (s *Server) drainWindow(rxFrames []*frame.Frame) time.Duration {
	s.timingMu.RLock()
	activeWindow := s.activeDrainWindow
	longWindow := s.longPollWindow
	s.timingMu.RUnlock()
	// Any non-empty client batch was a directed action (SYN, data, FIN, RST):
	// the worker that posted it is blocked waiting for our response and has
	// nothing else to do until we return. Use the short ActiveDrainWindow so
	// these workers come back into the pool quickly and back-to-back
	// connection setup/teardown cycles aren't gated on LongPollWindow (8s).
	// Only truly empty polls (idle long-polls) keep the long window so the
	// server can push downstream data without forcing constant repolling.
	if len(rxFrames) > 0 {
		return activeWindow
	}
	return longWindow
}

// coalesceDuration picks the coalesce window for the current drain. Under
// high session fan-out we shrink the window: the next batch fills within
// a few ms anyway, and 25ms of extra accumulation per response just adds
// tail latency. Large batches (already half-full or more) keep the full
// 25ms because they are bulk-dominant and benefit from extra throughput.
func (s *Server) coalesceDuration(currentFrames int) time.Duration {
	s.timingMu.RLock()
	window := s.coalesceWindow
	busyWindow := s.coalesceWindowBusy
	s.timingMu.RUnlock()
	if int(s.sessionCount.Load()) >= busySessionThreshold && currentFrames < maxDrainFramesPerBatch/2 {
		return busyWindow
	}
	return window
}

func (s *Server) decrementSessionCount() {
	for {
		n := s.sessionCount.Load()
		if n <= 0 {
			return
		}
		if s.sessionCount.CompareAndSwap(n, n-1) {
			return
		}
	}
}

func (s *Server) reserveSessionSlot() bool {
	limit := s.maxSessions
	if limit <= 0 {
		limit = protocol.DefaultMaxServerSessions
	}
	for {
		n := s.sessionCount.Load()
		if int(n) >= limit {
			return false
		}
		if s.sessionCount.CompareAndSwap(n, n+1) {
			return true
		}
	}
}

// routeIncoming routes one incoming frame to its session, creating the session
// (and dialing upstream) if this is a SYN. owner is the clientID of the
// requesting client; non-SYN frames for an existing session are rejected when
// they come from a different client (collision or spoof).
func (s *Server) routeIncoming(f *frame.Frame, owner [frame.ClientIDLen]byte) {
	s.routeIncomingContext(context.Background(), f, owner)
}

func (s *Server) waitForPendingOpen(ctx context.Context, owner [frame.ClientIDLen]byte, sessionID [frame.SessionIDLen]byte) (*session.Session, bool) {
	s.mu.Lock()
	pending, exists := s.opening[sessionID]
	if !exists {
		s.mu.Unlock()
		return nil, false
	}
	if pending.owner != owner {
		s.mu.Unlock()
		log.Printf("[exit] cross-client session collision on pending open %x; sending RST to %x",
			sessionID[:4], owner[:4])
		s.queueRST(owner, sessionID)
		s.stats.rstSent.Add(1)
		return nil, true
	}
	done := pending.done
	s.mu.Unlock()

	select {
	case <-done:
	case <-ctx.Done():
		return nil, true
	}

	s.mu.Lock()
	sess, exists := s.sessions[sessionID]
	currentOwner, ownerOK := s.sessionOwners[sessionID]
	s.mu.Unlock()
	if exists && ownerOK && currentOwner == owner {
		return sess, true
	}
	return nil, true
}

func (s *Server) routeIncomingContext(ctx context.Context, f *frame.Frame, owner [frame.ClientIDLen]byte) {
	if f.HasFlag(frame.FlagRST) {
		s.closeOwnedSession(owner, f.SessionID, "client reset")
		return
	}
	if f.HasFlag(frame.FlagACK) {
		if ackNextSeq, ok := protocol.DecodeDownstreamACK(f.Payload); ok {
			s.mu.Lock()
			_, exists := s.sessions[f.SessionID]
			currentOwner, ownerOK := s.sessionOwners[f.SessionID]
			validACK := exists && ownerOK && currentOwner == owner
			if validACK {
				s.lastActivity[f.SessionID] = time.Now()
			}
			s.mu.Unlock()
			if validACK && s.replay != nil {
				pruned := s.replay.ack(owner, f.SessionID, ackNextSeq)
				s.stats.ackReceived.Add(1)
				if pruned > 0 {
					s.stats.replayPruned.Add(uint64(pruned))
				}
			}
			return
		}
		if probe, ok := protocol.DecodeProbePayload(f.Payload); ok {
			s.handleVersionProbe(owner, f.SessionID, probe)
		}
		return
	}

	s.mu.Lock()
	sess, exists := s.sessions[f.SessionID]
	existingOwner, hasOwner := s.sessionOwners[f.SessionID]
	s.mu.Unlock()

	if exists && hasOwner && existingOwner != owner {
		// Different client claiming an active session ID — astronomically
		// unlikely with random 16-byte IDs, but possible if a client reused an
		// ID from a previous process. Reject to keep clients isolated.
		log.Printf("[exit] cross-client session collision on %x; sending RST to %x",
			f.SessionID[:4], owner[:4])
		s.queueRST(owner, f.SessionID)
		s.stats.rstSent.Add(1)
		return
	}

	if !exists {
		if !f.HasFlag(frame.FlagSYN) {
			if pendingSess, waited := s.waitForPendingOpen(ctx, owner, f.SessionID); waited {
				if pendingSess != nil {
					sess = pendingSess
					exists = true
				} else {
					return
				}
			} else {
				log.Printf("[exit] frame for unknown session (no SYN), sending RST")
				s.queueRST(owner, f.SessionID)
				s.stats.rstSent.Add(1)
				return
			}
		}
	}

	if !exists {
		if s.isDialSuppressed(f.Target) {
			log.Printf("[exit] dial suppressed for %s (recent failure backoff); sending RST", f.Target)
			s.stats.dialsSuppressed.Add(1)
			s.queueRST(owner, f.SessionID)
			s.stats.rstSent.Add(1)
			return
		}
		var err error
		sess, err = s.openSessionContext(ctx, f.SessionID, f.Target, owner)
		if err != nil {
			if errors.Is(err, errSessionCanceled) {
				return
			}
			if errors.Is(err, errSessionLimit) {
				log.Printf("[exit] session limit reached (%d), sending RST", s.maxSessions)
				s.queueRST(owner, f.SessionID)
				s.stats.rstSent.Add(1)
				return
			}
			if errors.Is(err, errSessionCollision) {
				log.Printf("[exit] session collision on %x while dialing; sending RST", f.SessionID[:4])
				s.queueRST(owner, f.SessionID)
				s.stats.rstSent.Add(1)
				return
			}
			s.recordDialFailure(f.Target, err)
			s.stats.dialsFail.Add(1)
			log.Printf("[exit] dial %s: %v", f.Target, err)
			s.queueRST(owner, f.SessionID)
			s.stats.rstSent.Add(1)
			return
		}
		s.stats.dialsOK.Add(1)
		s.clearDialFailure(f.Target)
	}
	s.mu.Lock()
	currentSess, stillExists := s.sessions[f.SessionID]
	currentOwner, ownerOK := s.sessionOwners[f.SessionID]
	s.mu.Unlock()
	if !stillExists || currentSess != sess || !ownerOK || currentOwner != owner {
		return
	}
	sess.ProcessRx(f)
	// Touch activity AFTER ProcessRx so a successful client→server frame
	// resets the idle timer for this session.
	s.mu.Lock()
	if _, stillExists := s.sessions[f.SessionID]; stillExists {
		s.lastActivity[f.SessionID] = time.Now()
	}
	s.mu.Unlock()
}

// queueRST enqueues a RST frame for the given session to be delivered to
// owner on its next poll. Also wakes that client's long-poll so the RST is
// flushed immediately rather than after the long-poll deadline.
func (s *Server) queueRST(owner [frame.ClientIDLen]byte, sessionID [frame.SessionIDLen]byte) {
	s.mu.Lock()
	s.enqueuePendingRSTLocked(owner, sessionID)
	s.mu.Unlock()
	s.kick(owner)
}

func (s *Server) enqueuePendingRSTLocked(owner [frame.ClientIDLen]byte, sessionID [frame.SessionIDLen]byte) bool {
	for _, queued := range s.pendingRSTs[owner] {
		if queued != nil && queued.SessionID == sessionID {
			return false
		}
	}
	s.pendingRSTs[owner] = append(s.pendingRSTs[owner], &frame.Frame{SessionID: sessionID, Flags: frame.FlagRST})
	s.trimPendingControlLocked(owner)
	return true
}

func (s *Server) enqueuePendingControlLocked(owner [frame.ClientIDLen]byte, f *frame.Frame) bool {
	if f == nil {
		return false
	}
	s.pendingCtrl[owner] = append(s.pendingCtrl[owner], f)
	s.trimPendingControlLocked(owner)
	return true
}

func (s *Server) trimPendingControlLocked(owner [frame.ClientIDLen]byte) int {
	total := len(s.pendingCtrl[owner]) + len(s.pendingRSTs[owner])
	if total <= pendingControlMaxFramesPerOwner {
		return 0
	}
	drop := total - pendingControlMaxFramesPerOwner
	dropped := 0
	if rsts := s.pendingRSTs[owner]; len(rsts) > 0 && drop > 0 {
		n := drop
		if n > len(rsts) {
			n = len(rsts)
		}
		for i := 0; i < n; i++ {
			rsts[i] = nil
		}
		rsts = append([]*frame.Frame(nil), rsts[n:]...)
		if len(rsts) > 0 {
			s.pendingRSTs[owner] = rsts
		} else {
			delete(s.pendingRSTs, owner)
		}
		drop -= n
		dropped += n
	}
	if ctrl := s.pendingCtrl[owner]; len(ctrl) > 0 && drop > 0 {
		n := drop
		if n > len(ctrl) {
			n = len(ctrl)
		}
		for i := 0; i < n; i++ {
			ctrl[i] = nil
		}
		ctrl = append([]*frame.Frame(nil), ctrl[n:]...)
		if len(ctrl) > 0 {
			s.pendingCtrl[owner] = ctrl
		} else {
			delete(s.pendingCtrl, owner)
		}
		dropped += n
	}
	return dropped
}

func (s *Server) pruneInactivePendingControlLocked(now time.Time, activeOwners map[[frame.ClientIDLen]byte]struct{}) int {
	owners := make(map[[frame.ClientIDLen]byte]struct{}, len(s.pendingCtrl)+len(s.pendingRSTs))
	for owner := range s.pendingCtrl {
		owners[owner] = struct{}{}
	}
	for owner := range s.pendingRSTs {
		owners[owner] = struct{}{}
	}
	pruned := 0
	for owner := range owners {
		if _, active := activeOwners[owner]; active {
			continue
		}
		if _, streamActive := s.activeStreams[owner]; streamActive {
			continue
		}
		lastPOST := s.postActivity[owner]
		if !lastPOST.IsZero() && now.Sub(lastPOST) <= pendingControlInactiveTTL {
			continue
		}
		pruned += len(s.pendingCtrl[owner]) + len(s.pendingRSTs[owner])
		delete(s.pendingCtrl, owner)
		delete(s.pendingRSTs, owner)
	}
	return pruned
}

func normalizeClientInstanceID(id string) string {
	id = strings.TrimSpace(id)
	if id == "" || len(id) > 128 {
		return ""
	}
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '-' || r == '_' || r == '.' || r == ':':
		default:
			return ""
		}
	}
	return id
}

func (s *Server) handleVersionProbe(owner [frame.ClientIDLen]byte, sessionID [frame.SessionIDLen]byte, probe *protocol.VersionProbe) {
	if probe != nil {
		if aborted := s.registerClientRun(owner, probe); aborted > 0 {
			log.Printf("[exit] client run reset closed %d stale session(s) for owner=%x", aborted, owner[:4])
		}
	}
	s.queueVersionResponse(owner, sessionID)
}

func (s *Server) registerClientRun(owner [frame.ClientIDLen]byte, probe *protocol.VersionProbe) int {
	instanceID := normalizeClientInstanceID(probe.ClientInstanceID)
	if instanceID == "" {
		return 0
	}

	var staleOwners [][frame.ClientIDLen]byte
	s.mu.Lock()
	if s.clientInstances == nil {
		s.clientInstances = make(map[string]map[[frame.ClientIDLen]byte]struct{})
	}
	if s.clientInstanceByOwner == nil {
		s.clientInstanceByOwner = make(map[[frame.ClientIDLen]byte]string)
	}
	if prevInstance := s.clientInstanceByOwner[owner]; prevInstance != "" && prevInstance != instanceID {
		if owners := s.clientInstances[prevInstance]; owners != nil {
			delete(owners, owner)
			if len(owners) == 0 {
				delete(s.clientInstances, prevInstance)
			}
		}
	}
	owners := s.clientInstances[instanceID]
	if owners == nil {
		owners = make(map[[frame.ClientIDLen]byte]struct{})
		s.clientInstances[instanceID] = owners
	}
	if probe.ResetPrevious {
		for staleOwner := range owners {
			if staleOwner == owner {
				continue
			}
			staleOwners = append(staleOwners, staleOwner)
			delete(owners, staleOwner)
			delete(s.clientInstanceByOwner, staleOwner)
			delete(s.activeStreams, staleOwner)
			delete(s.streamGen, staleOwner)
			delete(s.postActivity, staleOwner)
		}
	}
	owners[owner] = struct{}{}
	s.clientInstanceByOwner[owner] = instanceID
	s.mu.Unlock()

	aborted := 0
	for _, staleOwner := range staleOwners {
		aborted += s.abortOwnerSessions(staleOwner, "client run reset")
		s.kick(staleOwner)
		s.dropInactiveOwnerState(staleOwner)
	}
	return aborted
}

func (s *Server) forgetClientInstanceOwnerLocked(owner [frame.ClientIDLen]byte) {
	instanceID := s.clientInstanceByOwner[owner]
	if instanceID != "" {
		if owners := s.clientInstances[instanceID]; owners != nil {
			delete(owners, owner)
			if len(owners) == 0 {
				delete(s.clientInstances, instanceID)
			}
		}
	}
	delete(s.clientInstanceByOwner, owner)
}

func (s *Server) dropInactiveOwnerState(owner [frame.ClientIDLen]byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dropInactiveOwnerStateLocked(owner)
}

func (s *Server) dropInactiveOwnerStateLocked(owner [frame.ClientIDLen]byte) {
	delete(s.pendingRSTs, owner)
	delete(s.pendingCtrl, owner)
	delete(s.ownerReady, owner)
	delete(s.activity, owner)
	delete(s.postActivity, owner)
	delete(s.activeStreams, owner)
	delete(s.streamGen, owner)
	s.forgetClientInstanceOwnerLocked(owner)
}

func (s *Server) dropInactiveOwnerMetadataLocked(owner [frame.ClientIDLen]byte) {
	delete(s.activity, owner)
	delete(s.postActivity, owner)
	s.forgetClientInstanceOwnerLocked(owner)
}

func (s *Server) queueVersionResponse(owner [frame.ClientIDLen]byte, sessionID [frame.SessionIDLen]byte) {
	features := []string{"zstd", "raw_base64", protocol.FeatureBinaryBatchV1, protocol.FeatureClientRunResetV1}
	if s.downstreamReplayEnabled {
		features = append(features, protocol.FeatureDownstreamReplayV1)
	}
	payload, err := protocol.EncodeVersionInfo(s.version, MaxFramePayload, features)
	if err != nil {
		payload = []byte("{\"ok\":false}")
	}
	rst := &frame.Frame{SessionID: sessionID, Flags: frame.FlagRST, Payload: payload}
	s.mu.Lock()
	s.enqueuePendingControlLocked(owner, rst)
	s.mu.Unlock()
	s.kick(owner)
}

func (s *Server) registerStream(owner [frame.ClientIDLen]byte) uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.streamGen[owner]++
	s.activeStreams[owner] = s.streamGen[owner]
	if ch := s.activity[owner]; ch != nil {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
	return s.streamGen[owner]
}

func (s *Server) unregisterStream(owner [frame.ClientIDLen]byte, gen uint64) {
	s.mu.Lock()
	if s.activeStreams[owner] == gen {
		delete(s.activeStreams, owner)
	}
	s.mu.Unlock()
}

func (s *Server) isCurrentStream(owner [frame.ClientIDLen]byte, gen uint64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.activeStreams[owner] == gen
}

func (s *Server) markPostActivity(owner [frame.ClientIDLen]byte, at time.Time) {
	s.mu.Lock()
	if prev, ok := s.postActivity[owner]; !ok || at.After(prev) {
		s.postActivity[owner] = at
	}
	s.mu.Unlock()
}

func (s *Server) shouldAbortDisconnectedStream(owner [frame.ClientIDLen]byte, gen uint64, closedAt time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.streamGen[owner] != gen {
		return false
	}
	if lastPOST, ok := s.postActivity[owner]; ok && lastPOST.After(closedAt) {
		return false
	}
	return true
}

func (s *Server) cleanupDisconnectedStream(owner [frame.ClientIDLen]byte, gen uint64, closedAt time.Time) int {
	if !s.shouldAbortDisconnectedStream(owner, gen, closedAt) {
		return 0
	}
	return s.abortOwnerSessions(owner, "direct stream disconnected")
}

func (s *Server) dialProxyContext(ctx context.Context, target string) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if s.dialContext != nil {
		return s.dialContext(ctx, "tcp", target, s.upstreamDialTimeout)
	}
	type dialOutcome struct {
		conn net.Conn
		err  error
	}
	done := make(chan dialOutcome, 1)
	go func() {
		conn, err := s.dial("tcp", target, s.upstreamDialTimeout)
		if ctx.Err() != nil {
			if conn != nil {
				_ = conn.Close()
			}
			return
		}
		out := dialOutcome{conn: conn, err: err}
		select {
		case done <- out:
		case <-ctx.Done():
			if conn != nil {
				_ = conn.Close()
			}
		}
	}()
	select {
	case out := <-done:
		return out.conn, out.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (s *Server) pendingOpenError(pending *pendingOpenSession, err error) error {
	s.mu.Lock()
	if pending.canceled {
		pending.err = errSessionCanceled
		s.mu.Unlock()
		return errSessionCanceled
	}
	pending.err = err
	s.mu.Unlock()
	return err
}

// openSession dials the upstream target, creates a Session for the given ID,
// registers it under the given owner, and spawns the bidirectional pump
// goroutines.
func (s *Server) openSession(id [frame.SessionIDLen]byte, target string, owner [frame.ClientIDLen]byte) (*session.Session, error) {
	return s.openSessionContext(context.Background(), id, target, owner)
}

func (s *Server) openSessionContext(ctx context.Context, id [frame.SessionIDLen]byte, target string, owner [frame.ClientIDLen]byte) (*session.Session, error) {
	s.mu.Lock()
	if existing, exists := s.sessions[id]; exists {
		existingOwner := s.sessionOwners[id]
		s.mu.Unlock()
		if existingOwner != owner {
			return nil, errSessionCollision
		}
		return existing, nil
	}
	if pending, exists := s.opening[id]; exists {
		if pending.owner != owner {
			s.mu.Unlock()
			return nil, errSessionCollision
		}
		if pending.canceled {
			s.mu.Unlock()
			return nil, errSessionCanceled
		}
		done := pending.done
		s.mu.Unlock()
		select {
		case <-done:
			if pending.err != nil {
				return nil, pending.err
			}
			if pending.sess == nil {
				return nil, errSessionLimit
			}
			return pending.sess, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if !s.reserveSessionSlot() {
		s.mu.Unlock()
		return nil, errSessionLimit
	}
	dialCtx, cancelDial := context.WithCancel(ctx)
	defer cancelDial()
	pending := &pendingOpenSession{owner: owner, done: make(chan struct{}), cancel: cancelDial}
	s.opening[id] = pending
	s.mu.Unlock()

	slotReserved := true
	defer func() {
		if slotReserved {
			s.decrementSessionCount()
		}
		s.mu.Lock()
		if s.opening[id] == pending {
			delete(s.opening, id)
		}
		close(pending.done)
		s.mu.Unlock()
	}()

	var upstream net.Conn
	var res *dialResult
	var proxyDialElapsed time.Duration
	if s.cfg.UpstreamProxy != "" {
		// Let the SOCKS5 proxy handle DNS so the target hostname is resolved
		// on the proxy side (e.g. through WARP), not locally on the VPS.
		proxyDialStart := time.Now()
		conn, err := s.dialProxyContext(dialCtx, target)
		proxyDialElapsed = time.Since(proxyDialStart)
		if err != nil {
			return nil, s.pendingOpenError(pending, err)
		}
		upstream = conn
		s.stats.dialAttempts.Add(1)
		s.stats.dialProxy.Add(1)
	} else {
		var err error
		dialer := s.dial
		if s.dialContext != nil {
			dialer = func(network, address string, timeout time.Duration) (net.Conn, error) {
				return s.dialContext(dialCtx, network, address, timeout)
			}
		}
		res, err = dialWithDNSCacheContext(dialCtx, s.dns, dialer, "tcp", target, s.upstreamDialTimeout)
		if err != nil {
			return nil, s.pendingOpenError(pending, err)
		}
		upstream = res.Conn
		s.recordDialResult(res)
	}
	// Disable Nagle's algorithm so small writes (TLS handshake records, HTTP
	// request lines) hit the wire immediately instead of waiting up to 40 ms
	// to coalesce. Interactive workloads dominate this tunnel; throughput-bound
	// flows already buffer at the kernel level. Keepalives protect long-idle
	// terminal/database-style sessions from silent NAT expiry on cloud paths.
	if tcpConn, ok := upstream.(*net.TCPConn); ok {
		_ = tcpConn.SetNoDelay(true)
		_ = tcpConn.SetKeepAlive(true)
		_ = tcpConn.SetKeepAlivePeriod(60 * time.Second)
	}
	if s.debugTiming {
		if res != nil {
			log.Printf("[timing] %x dial dns=%dms cached=%v tcp=%dms ip=%s family=%s attempts=%d target=%s",
				id[:4], res.DNS.Milliseconds(), res.DNSCached, res.TCP.Milliseconds(),
				res.IP, ipFamily(res.IP), res.Attempts, target)
		} else {
			log.Printf("[timing] %x dial via proxy tcp=%dms target=%s", id[:4], proxyDialElapsed.Milliseconds(), target)
		}
	}
	dialedAt := time.Now()
	sess := session.New(id, target, false)
	wakeCh := s.activityFor(owner)
	sess.OnTx = func() {
		s.mu.Lock()
		s.markTxReadyLocked(owner, id)
		s.mu.Unlock()
		select {
		case wakeCh <- struct{}{}:
		default:
		}
	}
	sess.OnAbort = func(reason string) {
		log.Printf("[exit] session %x target=%s receive aborted: %s", id[:4], target, reason)
	}

	s.mu.Lock()
	if pending.canceled {
		pending.err = errSessionCanceled
		s.mu.Unlock()
		_ = upstream.Close()
		sess.Abort()
		return nil, errSessionCanceled
	}
	if existing, exists := s.sessions[id]; exists {
		existingOwner := s.sessionOwners[id]
		if existingOwner != owner {
			pending.err = errSessionCollision
		} else {
			pending.sess = existing
		}
		s.mu.Unlock()
		_ = upstream.Close()
		sess.Stop()
		if existingOwner != owner {
			return nil, errSessionCollision
		}
		return existing, nil
	}
	s.sessions[id] = sess
	s.sessionOwners[id] = owner
	s.upstreams[id] = upstream
	s.firstReply[id] = struct{}{}
	s.responseStage[id] = 0
	s.lastActivity[id] = time.Now()
	pending.sess = sess
	s.mu.Unlock()
	slotReserved = false
	s.stats.sessionsOpen.Add(1)

	log.Printf("[exit] new session %x owner=%x -> %s", id[:4], owner[:4], target)

	// Upstream → session.EnqueueTx (downstream direction).
	go func() {
		defer upstream.Close()
		bufP := s.upstreamReadPool.Get().(*[]byte)
		buf := *bufP
		defer func() {
			// Zero the pointer so we don't accidentally hold a reference;
			// the pool returns the slice header so future Reads get a fresh
			// buffer view but back the same allocation.
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
				// Stop the session so rxLoop exits and its defer closes RxChan,
				// which unblocks the write goroutine below and lets both pump
				// goroutines exit cleanly. Using Stop() here (rather than
				// CloseRx() directly) avoids racing with an in-flight deliverRx
				// that has released the session mutex but not yet sent on
				// RxChan — closing RxChan out from under it would panic.
				sess.Stop()
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

func (s *Server) recordDialResult(res *dialResult) {
	if res == nil {
		return
	}
	attempts := res.Attempts
	if attempts <= 0 {
		attempts = 1
	}
	s.stats.dialAttempts.Add(uint64(attempts))
	if attempts > 1 {
		s.stats.dialRaceWins.Add(1)
	}
	switch ipFamily(res.IP) {
	case "ipv4":
		s.stats.dialIPv4.Add(1)
	case "ipv6":
		s.stats.dialIPv6.Add(1)
	}
}

func ipFamily(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return "unknown"
	}
	if parsed.To4() != nil {
		return "ipv4"
	}
	return "ipv6"
}

func (s *Server) streamInFlightLocked(id [frame.SessionIDLen]byte) bool {
	inFlight := s.streamInFlight[id]
	if inFlight == nil {
		return false
	}
	if s.sessions[id] == inFlight {
		return true
	}
	delete(s.streamInFlight, id)
	return false
}

func (s *Server) markTxReadyLocked(owner [frame.ClientIDLen]byte, id [frame.SessionIDLen]byte) {
	if s.streamInFlightLocked(id) {
		return
	}
	if _, ok := s.txReady[id]; !ok {
		s.ownerReady[owner] = append(s.ownerReady[owner], id)
	}
	s.txReady[id] = struct{}{}
}

func (s *Server) readyOrderSnapshotLocked(owner [frame.ClientIDLen]byte) [][frame.SessionIDLen]byte {
	if len(s.txReady) == 0 {
		return nil
	}
	ids := make([][frame.SessionIDLen]byte, 0, len(s.ownerReady[owner]))
	seen := make(map[[frame.SessionIDLen]byte]struct{}, len(s.ownerReady[owner]))
	for _, id := range s.ownerReady[owner] {
		if _, ready := s.txReady[id]; !ready {
			continue
		}
		if s.streamInFlightLocked(id) {
			continue
		}
		if _, ok := s.sessions[id]; !ok {
			delete(s.txReady, id)
			continue
		}
		if s.sessionOwners[id] != owner {
			continue
		}
		ids = append(ids, id)
		seen[id] = struct{}{}
	}
	// Compatibility fallback for tests or future code paths that populate
	// txReady directly. Production paths use markTxReadyLocked above.
	for id := range s.txReady {
		if _, ok := seen[id]; ok {
			continue
		}
		if s.streamInFlightLocked(id) {
			continue
		}
		if _, ok := s.sessions[id]; !ok {
			delete(s.txReady, id)
			continue
		}
		if s.sessionOwners[id] != owner {
			continue
		}
		ids = append(ids, id)
		s.ownerReady[owner] = append(s.ownerReady[owner], id)
	}
	return ids
}

func (s *Server) compactReadyOrderLocked(owner [frame.ClientIDLen]byte) {
	queue := s.ownerReady[owner]
	if len(queue) == 0 {
		return
	}
	out := queue[:0]
	for _, id := range queue {
		if _, ok := s.txReady[id]; !ok {
			continue
		}
		if s.streamInFlightLocked(id) {
			continue
		}
		if s.sessionOwners[id] != owner {
			continue
		}
		out = append(out, id)
	}
	if len(out) == 0 {
		delete(s.ownerReady, owner)
		return
	}
	s.ownerReady[owner] = out
}

func (s *Server) drainPendingControl(owner [frame.ClientIDLen]byte) ([]*frame.Frame, bool) {
	return s.drainPendingControlLimited(owner, maxDrainFramesPerBatchBusy, s.maxResponseBytesPreEncode)
}

func (s *Server) drainPendingControlLimited(owner [frame.ClientIDLen]byte, frameBudget, byteBudget int) ([]*frame.Frame, bool) {
	if frameBudget <= 0 {
		return nil, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.drainPendingControlLocked(owner, frameBudget, byteBudget)
}

func framePayloadBytes(frames []*frame.Frame) int {
	total := 0
	for _, f := range frames {
		if f != nil {
			total += len(f.Payload)
		}
	}
	return total
}

func splitFramesByBudget(frames []*frame.Frame, frameBudget, byteBudget int) ([]*frame.Frame, []*frame.Frame) {
	if len(frames) == 0 {
		return nil, nil
	}
	if frameBudget <= 0 {
		return nil, append([]*frame.Frame(nil), frames...)
	}
	kept := make([]*frame.Frame, 0, min(len(frames), frameBudget))
	for i, f := range frames {
		payloadBytes := 0
		if f != nil {
			payloadBytes = len(f.Payload)
		}
		if len(kept) >= frameBudget || (payloadBytes > 0 && payloadBytes > byteBudget) {
			return kept, append([]*frame.Frame(nil), frames[i:]...)
		}
		kept = append(kept, f)
		byteBudget -= payloadBytes
	}
	return kept, nil
}

func (s *Server) drainPendingControlLocked(owner [frame.ClientIDLen]byte, frameBudget, byteBudget int) ([]*frame.Frame, bool) {
	if frameBudget <= 0 {
		return nil, false
	}
	var out []*frame.Frame
	drain := func(queue []*frame.Frame) (drained []*frame.Frame, rest []*frame.Frame) {
		if len(queue) == 0 || frameBudget <= 0 {
			return nil, queue
		}
		for len(queue) > 0 && frameBudget > 0 {
			f := queue[0]
			payloadBytes := 0
			if f != nil {
				payloadBytes = len(f.Payload)
			}
			if payloadBytes > 0 && payloadBytes > byteBudget {
				break
			}
			drained = append(drained, f)
			queue = queue[1:]
			frameBudget--
			byteBudget -= payloadBytes
		}
		if len(queue) == 0 {
			return drained, nil
		}
		rest = append([]*frame.Frame(nil), queue...)
		return drained, rest
	}
	if ctrl, rest := drain(s.pendingCtrl[owner]); len(ctrl) > 0 || len(rest) != len(s.pendingCtrl[owner]) {
		out = append(out, ctrl...)
		if len(rest) > 0 {
			s.pendingCtrl[owner] = rest
		} else {
			delete(s.pendingCtrl, owner)
		}
	}
	if rsts, rest := drain(s.pendingRSTs[owner]); len(rsts) > 0 || len(rest) != len(s.pendingRSTs[owner]) {
		out = append(out, rsts...)
		if len(rest) > 0 {
			s.pendingRSTs[owner] = rest
		} else {
			delete(s.pendingRSTs, owner)
		}
	}
	return out, len(out) > 0
}

func (s *Server) requeueControlFrames(owner [frame.ClientIDLen]byte, frames []*frame.Frame) int {
	if len(frames) == 0 {
		return 0
	}
	ctrl, rsts := cloneRSTControlFrames(frames)
	if len(ctrl) == 0 && len(rsts) == 0 {
		return 0
	}
	s.mu.Lock()
	count := s.prependControlFramesLocked(owner, ctrl, rsts)
	s.mu.Unlock()
	s.kick(owner)
	return count
}

func cloneRSTControlFrames(frames []*frame.Frame) ([]*frame.Frame, []*frame.Frame) {
	var ctrl []*frame.Frame
	var rsts []*frame.Frame
	for _, f := range frames {
		if f == nil || !f.HasFlag(frame.FlagRST) {
			continue
		}
		cp := *f
		if len(f.Payload) > 0 {
			cp.Payload = append([]byte(nil), f.Payload...)
			ctrl = append(ctrl, &cp)
			continue
		}
		rsts = append(rsts, &cp)
	}
	return ctrl, rsts
}

func (s *Server) prependControlFramesLocked(owner [frame.ClientIDLen]byte, ctrl, rsts []*frame.Frame) int {
	if len(ctrl) > 0 {
		s.pendingCtrl[owner] = append(ctrl, s.pendingCtrl[owner]...)
	}
	if len(rsts) > 0 {
		s.pendingRSTs[owner] = append(rsts, s.pendingRSTs[owner]...)
	}
	return len(ctrl) + len(rsts)
}

func (s *Server) drainReplay(owner [frame.ClientIDLen]byte, byteBudget int) ([]*frame.Frame, bool) {
	if s.replay == nil {
		return nil, false
	}
	now := time.Now()
	s.expireReplayForOwner(owner, now)
	frames := s.replay.ready(owner, byteBudget, now)
	if len(frames) == 0 {
		return nil, false
	}
	s.recordReplayDrain(frames)
	return frames, true
}

func (s *Server) drainReplayForStream(owner [frame.ClientIDLen]byte, byteBudget int) ([]*frame.Frame, bool) {
	if s.replay == nil {
		return nil, false
	}
	s.expireReplayForOwner(owner, time.Now())
	frames := s.replay.readyForStream(owner, byteBudget)
	if len(frames) == 0 {
		return nil, false
	}
	s.recordReplayDrain(frames)
	return frames, true
}

func (s *Server) recordReplayDrain(frames []*frame.Frame) {
	var bytes uint64
	for _, f := range frames {
		bytes += uint64(len(f.Payload))
	}
	s.stats.replayFrames.Add(uint64(len(frames)))
	s.stats.replayBytes.Add(bytes)
}

func (s *Server) markStreamReplayDelivered(owner [frame.ClientIDLen]byte, frames []*frame.Frame) {
	if s.replay == nil {
		return
	}
	for _, f := range frames {
		if f == nil || f.HasFlag(frame.FlagACK) || f.HasFlag(frame.FlagRST) {
			continue
		}
		s.replay.ack(owner, f.SessionID, f.Seq+1)
	}
}

func (s *Server) expireReplayForOwner(owner [frame.ClientIDLen]byte, now time.Time) int {
	if s.replay == nil {
		return 0
	}
	expired := s.replay.expireOwner(owner, now)
	if len(expired) == 0 {
		return 0
	}
	dropped := s.abortDownstreamSessions(owner, expired, "downstream replay buffer expired")
	if dropped > 0 {
		s.stats.replayDropped.Add(uint64(dropped))
		s.stats.replayDroppedExpired.Add(uint64(dropped))
	}
	return dropped
}

// drainAll returns all currently-buffered TX frames belonging to owner, plus
// an `urgent` flag signalling that at least one drained session is delivering
// its first downstream batch (e.g. TLS server hello after SYN). The caller
// skips the normal coalesce wait when urgent is set so connection setup isn't
// delayed by 25 ms on every new TLS handshake.
//
// Filtering by owner is what keeps multiple clients on the same server
// isolated: without it, whichever client's HTTP request reaches drainAll
// first would receive every other client's downstream frames and silently
// drop them, breaking every TLS stream in flight.
func (s *Server) drainAll(owner [frame.ClientIDLen]byte, byteBudget int) ([]*frame.Frame, bool) {
	return s.drainAllWithReplayHold(owner, byteBudget, true)
}

func (s *Server) drainAllForStream(owner [frame.ClientIDLen]byte, byteBudget int) ([]*frame.Frame, bool) {
	// Stream callers must flush pending POST replay first. Once the replayed
	// frames are written successfully to the reliable WebSocket, fresh frames no
	// longer need the POST replay hold and can flow immediately.
	return s.drainAllWithReplayHold(owner, byteBudget, false)
}

type streamResponseStageSnapshot struct {
	stage int
	ok    bool
}

type streamDrainRollback struct {
	owner         [frame.ClientIDLen]byte
	sessions      map[[frame.SessionIDLen]byte]*session.Session
	snapshots     map[[frame.SessionIDLen]byte]*session.DrainSnapshot
	firstReply    map[[frame.SessionIDLen]byte]bool
	responseStage map[[frame.SessionIDLen]byte]streamResponseStageSnapshot
}

func (s *Server) drainAllForStreamTxn(owner [frame.ClientIDLen]byte, byteBudget int) ([]*frame.Frame, bool, streamDrainRollback) {
	return s.drainAllWithReplayHoldTxn(owner, byteBudget, false, true)
}

func (s *Server) rollbackStreamDrainWithControl(rb streamDrainRollback, ctrl, rsts []*frame.Frame) {
	if len(rb.snapshots) == 0 && len(ctrl) == 0 && len(rsts) == 0 {
		return
	}
	s.mu.Lock()
	for id := range rb.snapshots {
		drainedSession := rb.sessions[id]
		if s.streamInFlight[id] == drainedSession {
			delete(s.streamInFlight, id)
		}
		current, alive := s.sessions[id]
		if !alive || current != drainedSession {
			continue
		}
		delete(s.txReady, id)
		if rb.firstReply[id] {
			s.firstReply[id] = struct{}{}
		} else {
			delete(s.firstReply, id)
		}
		if stage, ok := rb.responseStage[id]; ok && stage.ok {
			s.responseStage[id] = stage.stage
		} else {
			delete(s.responseStage, id)
		}
	}
	s.compactReadyOrderLocked(rb.owner)
	for id, snap := range rb.snapshots {
		if sess := rb.sessions[id]; sess != nil {
			sess.RollbackDrainNoNotify(snap)
		}
	}
	s.prependControlFramesLocked(rb.owner, ctrl, rsts)
	for id := range rb.snapshots {
		if current, alive := s.sessions[id]; !alive || current != rb.sessions[id] {
			continue
		}
		s.markTxReadyLocked(rb.owner, id)
	}
	s.mu.Unlock()
	s.kick(rb.owner)
}

func (s *Server) commitStreamDrain(rb streamDrainRollback) {
	if len(rb.snapshots) == 0 {
		return
	}
	needsWake := false
	s.mu.Lock()
	for id, drainedSession := range rb.sessions {
		if s.streamInFlight[id] == drainedSession {
			delete(s.streamInFlight, id)
		}
		current, alive := s.sessions[id]
		if !alive || current != drainedSession || drainedSession == nil {
			continue
		}
		if drainedSession.HasPendingTx() {
			s.markTxReadyLocked(rb.owner, id)
			needsWake = true
		}
	}
	s.mu.Unlock()
	if needsWake {
		s.kick(rb.owner)
	}
}

func (s *Server) drainAllWithReplayHold(owner [frame.ClientIDLen]byte, byteBudget int, holdFreshForReplay bool) ([]*frame.Frame, bool) {
	frames, urgent, _ := s.drainAllWithReplayHoldTxn(owner, byteBudget, holdFreshForReplay, false)
	return frames, urgent
}

func (s *Server) drainAllWithReplayHoldTxn(owner [frame.ClientIDLen]byte, byteBudget int, holdFreshForReplay bool, transactional bool) ([]*frame.Frame, bool, streamDrainRollback) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*frame.Frame
	var urgent bool
	rollback := streamDrainRollback{owner: owner}
	if ctrl := s.pendingCtrl[owner]; len(ctrl) > 0 {
		out = append(out, ctrl...)
		delete(s.pendingCtrl, owner)
		urgent = true
	}
	if rsts := s.pendingRSTs[owner]; len(rsts) > 0 {
		out = append(out, rsts...)
		delete(s.pendingRSTs, owner)
		urgent = true // RSTs are always urgent — client should know immediately
	}
	batchCap := maxDrainFramesPerBatch
	if len(s.sessions) >= busySessionThreshold {
		batchCap = maxDrainFramesPerBatchBusy
	}
	remaining := batchCap
	remainingBytes := byteBudget
	if len(out) > 0 {
		var overflow []*frame.Frame
		out, overflow = splitFramesByBudget(out, batchCap, byteBudget)
		if len(overflow) > 0 {
			ctrl, rsts := cloneRSTControlFrames(overflow)
			s.prependControlFramesLocked(owner, ctrl, rsts)
		}
		remaining -= len(out)
		if remaining < 0 {
			remaining = 0
		}
		remainingBytes -= framePayloadBytes(out)
		if remainingBytes < 0 {
			remainingBytes = 0
		}
	}

	refs := s.readyOrderSnapshotLocked(owner)
	defer s.compactReadyOrderLocked(owner)

	drained := make(map[[frame.SessionIDLen]byte]struct{})
	drainOne := func(id [frame.SessionIDLen]byte, sessionByteBudget int) {
		if remaining <= 0 || remainingBytes <= 0 {
			return
		}
		if holdFreshForReplay && s.replay != nil && s.replay.hasPending(owner, id) {
			return
		}
		sess, ok := s.sessions[id]
		if !ok {
			delete(s.txReady, id)
			drained[id] = struct{}{}
			return
		}
		perSessionCap := s.maxDrainFramesPerSession
		if remaining < perSessionCap {
			perSessionCap = remaining
		}
		if queuedAt := sess.FirstQueuedAt(); !queuedAt.IsZero() {
			s.stats.queueWait.Add(time.Since(queuedAt))
		}
		drainBytes := remainingBytes
		if sessionByteBudget > 0 && sessionByteBudget < drainBytes {
			drainBytes = sessionByteBudget
		} else if sessionByteBudget == 0 && s.responseStage[id] == 1 && s.secondResponseBytesPreEncode > 0 && s.secondResponseBytesPreEncode < drainBytes {
			drainBytes = s.secondResponseBytesPreEncode
		}
		var (
			frames []*frame.Frame
			snap   *session.DrainSnapshot
		)
		if transactional {
			frames, snap = sess.DrainTxLimitedByBudgetTxn(MaxFramePayload, perSessionCap, drainBytes)
		} else {
			frames = sess.DrainTxLimitedByBudget(MaxFramePayload, perSessionCap, drainBytes)
		}
		// Only clear from txReady when fully drained. A partial drain (cap
		// hit before all data + a trailing FIN could be emitted) needs to
		// stay queued, otherwise the session is stranded with no path back
		// into drainAll — OnTx only fires on new EnqueueTx/RequestClose, not
		// on leftover bytes — and the FIN never reaches the client until the
		// 10-minute idle GC reaps it. That's why ~270 closed sessions linger
		// in s.sessions as zombies under sustained load.
		if transactional && len(frames) > 0 {
			delete(s.txReady, id)
			s.streamInFlight[id] = sess
		} else if !sess.HasPendingTx() {
			delete(s.txReady, id)
		}
		if len(frames) > 0 {
			if transactional && snap != nil {
				if rollback.sessions == nil {
					rollback.sessions = make(map[[frame.SessionIDLen]byte]*session.Session)
					rollback.snapshots = make(map[[frame.SessionIDLen]byte]*session.DrainSnapshot)
					rollback.firstReply = make(map[[frame.SessionIDLen]byte]bool)
					rollback.responseStage = make(map[[frame.SessionIDLen]byte]streamResponseStageSnapshot)
				}
				rollback.sessions[id] = sess
				rollback.snapshots[id] = snap
				_, rollback.firstReply[id] = s.firstReply[id]
				stage, ok := s.responseStage[id]
				rollback.responseStage[id] = streamResponseStageSnapshot{stage: stage, ok: ok}
			}
			if _, isFirst := s.firstReply[id]; isFirst {
				urgent = true
				delete(s.firstReply, id)
				s.responseStage[id] = 1
			} else if s.responseStage[id] == 1 {
				// Treat the second response as urgent too. Otherwise response
				// coalescing could drain this session again into the same HTTP
				// response and effectively skip the ramp.
				urgent = true
				s.responseStage[id] = 2
			}
			// Outbound traffic also counts as session liveness; without this
			// a long pure-download session (large file, video stream) with no
			// client→server frames would be force-closed by the idle GC after
			// idleSessionTimeout even though it is actively delivering data.
			s.lastActivity[id] = time.Now()
			for _, f := range frames {
				remainingBytes -= len(f.Payload)
			}
		}
		out = append(out, frames...)
		remaining -= len(frames)
		drained[id] = struct{}{}
	}

	// First downstream bytes unblock handshakes and short interactive flows, so
	// drain them before older bulk sessions owned by the same client.
	for _, id := range refs {
		if remaining <= 0 || remainingBytes <= 0 {
			break
		}
		if _, ok := s.firstReply[id]; !ok {
			continue
		}
		drainOne(id, s.initialResponseBytesPreEncode)
	}
	if urgent && len(out) > 0 {
		return out, true, rollback
	}
	for _, id := range refs {
		if remaining <= 0 || remainingBytes <= 0 {
			break
		}
		if _, ok := drained[id]; ok {
			continue
		}
		if s.responseStage[id] != 1 {
			continue
		}
		drainOne(id, 0)
	}
	if urgent && len(out) > 0 {
		return out, true, rollback
	}
	for _, id := range refs {
		if remaining <= 0 || remainingBytes <= 0 {
			break
		}
		if _, ok := drained[id]; ok {
			continue
		}
		drainOne(id, 0)
	}
	return out, urgent, rollback
}

func (s *Server) gcDoneSessions() {
	type victim struct {
		id       [frame.SessionIDLen]byte
		sess     *session.Session
		upstream net.Conn
	}
	var victims []victim
	now := time.Now()
	if s.dns != nil {
		s.dns.pruneExpired(now)
	}

	if s.replay != nil {
		owners := make(map[[frame.ClientIDLen]byte]struct{})
		s.mu.Lock()
		for _, owner := range s.sessionOwners {
			owners[owner] = struct{}{}
		}
		s.mu.Unlock()
		for owner := range owners {
			s.expireReplayForOwner(owner, now)
		}
	}

	s.mu.Lock()
	for id, sess := range s.sessions {
		if sess.IsDone() {
			if s.streamInFlightLocked(id) {
				continue
			}
			owner := s.sessionOwners[id]
			if s.replay != nil && s.replay.hasPending(owner, id) {
				continue
			}
			victims = append(victims, victim{id: id, sess: sess, upstream: s.upstreams[id]})
			delete(s.sessions, id)
			delete(s.sessionOwners, id)
			delete(s.txReady, id)
			delete(s.streamInFlight, id)
			delete(s.firstReply, id)
			delete(s.responseStage, id)
			delete(s.upstreams, id)
			delete(s.lastActivity, id)
			if s.replay != nil {
				s.replay.remove(owner, id)
			}
			s.decrementSessionCount()
		}
	}
	// Clean up metadata for clients that have no active sessions. Keep pending
	// control/RST queues here: a probe response or RST can be queued for an
	// owner with no active sessions and still needs to be drained by the
	// currently waiting POST/stream.
	activeOwners := make(map[[frame.ClientIDLen]byte]struct{}, len(s.sessions))
	for _, owner := range s.sessionOwners {
		activeOwners[owner] = struct{}{}
	}
	s.pruneInactivePendingControlLocked(now, activeOwners)
	for owner := range s.activity {
		if _, stillActive := activeOwners[owner]; !stillActive {
			if _, streamActive := s.activeStreams[owner]; streamActive {
				continue
			}
			s.dropInactiveOwnerMetadataLocked(owner)
		}
	}
	for owner := range s.clientInstanceByOwner {
		if _, stillActive := activeOwners[owner]; !stillActive {
			if _, streamActive := s.activeStreams[owner]; streamActive {
				continue
			}
			s.dropInactiveOwnerMetadataLocked(owner)
		}
	}
	s.pruneDialFailuresLocked(now)
	s.mu.Unlock()

	for _, v := range victims {
		if v.upstream != nil {
			_ = v.upstream.Close()
		}
		if v.sess != nil {
			v.sess.Abort()
		}
		s.stats.sessionsClose.Add(1)
	}
}

func (s *Server) abortDownstreamSessions(owner [frame.ClientIDLen]byte, ids [][frame.SessionIDLen]byte, reason string) int {
	if len(ids) == 0 {
		return 0
	}
	type victim struct {
		id       [frame.SessionIDLen]byte
		sess     *session.Session
		upstream net.Conn
	}
	victims := make([]victim, 0, len(ids))
	seen := make(map[[frame.SessionIDLen]byte]struct{}, len(ids))

	s.mu.Lock()
	for _, id := range ids {
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		if s.sessionOwners[id] != owner {
			continue
		}
		sess, ok := s.sessions[id]
		if !ok {
			continue
		}
		victims = append(victims, victim{id: id, sess: sess, upstream: s.upstreams[id]})
		s.enqueuePendingRSTLocked(owner, id)
		delete(s.sessions, id)
		delete(s.sessionOwners, id)
		delete(s.txReady, id)
		delete(s.streamInFlight, id)
		delete(s.firstReply, id)
		delete(s.responseStage, id)
		delete(s.upstreams, id)
		delete(s.lastActivity, id)
		if s.replay != nil {
			s.replay.remove(owner, id)
		}
		s.decrementSessionCount()
	}
	s.compactReadyOrderLocked(owner)
	s.mu.Unlock()

	if len(victims) == 0 {
		return 0
	}
	log.Printf("[exit] %s; reset %d affected session(s) for owner=%x", reason, len(victims), owner[:4])
	for _, v := range victims {
		if v.upstream != nil {
			_ = v.upstream.Close()
		}
		if v.sess != nil {
			v.sess.Abort()
		}
		s.stats.sessionsClose.Add(1)
		s.stats.rstSent.Add(1)
	}
	s.kick(owner)
	return len(victims)
}

func cancelOpeningLocked(pending *pendingOpenSession) bool {
	if pending == nil || pending.canceled {
		return false
	}
	pending.canceled = true
	if pending.cancel != nil {
		pending.cancel()
	}
	return true
}

func (s *Server) closeOwnedSession(owner [frame.ClientIDLen]byte, id [frame.SessionIDLen]byte, reason string) bool {
	type victim struct {
		sess     *session.Session
		upstream net.Conn
		target   string
	}
	var v victim

	s.mu.Lock()
	if s.sessionOwners[id] != owner {
		if pending, ok := s.opening[id]; ok && pending.owner == owner {
			cancelOpeningLocked(pending)
			s.mu.Unlock()
			log.Printf("[exit] %s for pending session %x", reason, id[:4])
			return true
		}
		s.mu.Unlock()
		return false
	}
	sess, ok := s.sessions[id]
	if !ok {
		s.mu.Unlock()
		return false
	}
	v = victim{sess: sess, upstream: s.upstreams[id], target: sess.Target}
	delete(s.sessions, id)
	delete(s.sessionOwners, id)
	delete(s.txReady, id)
	delete(s.streamInFlight, id)
	delete(s.firstReply, id)
	delete(s.responseStage, id)
	delete(s.upstreams, id)
	delete(s.lastActivity, id)
	if s.replay != nil {
		s.replay.remove(owner, id)
	}
	s.decrementSessionCount()
	s.compactReadyOrderLocked(owner)
	s.mu.Unlock()

	log.Printf("[exit] %s for session %x target=%s", reason, id[:4], v.target)
	if v.upstream != nil {
		_ = v.upstream.Close()
	}
	if v.sess != nil {
		v.sess.Abort()
	}
	s.stats.sessionsClose.Add(1)
	return true
}

func (s *Server) abortOwnerSessions(owner [frame.ClientIDLen]byte, reason string) int {
	s.mu.Lock()
	ids := make([][frame.SessionIDLen]byte, 0, len(s.sessionOwners))
	for id, sessionOwner := range s.sessionOwners {
		if sessionOwner == owner {
			ids = append(ids, id)
		}
	}
	pendingIDs := make([][frame.SessionIDLen]byte, 0)
	for id, pending := range s.opening {
		if pending.owner != owner {
			continue
		}
		if cancelOpeningLocked(pending) {
			pendingIDs = append(pendingIDs, id)
			s.enqueuePendingRSTLocked(owner, id)
		}
	}
	s.mu.Unlock()
	n := s.abortDownstreamSessions(owner, ids, reason)
	if len(pendingIDs) > 0 {
		log.Printf("[exit] %s; canceled %d pending open(s) for owner=%x", reason, len(pendingIDs), owner[:4])
		s.stats.rstSent.Add(uint64(len(pendingIDs)))
		s.kick(owner)
	}
	return n + len(pendingIDs)
}

func (s *Server) abortAllSessions(reason string) int {
	s.mu.Lock()
	owners := make(map[[frame.ClientIDLen]byte][][frame.SessionIDLen]byte)
	for id, owner := range s.sessionOwners {
		owners[owner] = append(owners[owner], id)
	}
	pendingByOwner := make(map[[frame.ClientIDLen]byte]int)
	for _, pending := range s.opening {
		if cancelOpeningLocked(pending) {
			pendingByOwner[pending.owner]++
		}
	}
	s.mu.Unlock()

	total := 0
	for owner, ids := range owners {
		total += s.abortDownstreamSessions(owner, ids, reason)
	}
	for owner, count := range pendingByOwner {
		log.Printf("[exit] %s; canceled %d pending open(s) for owner=%x", reason, count, owner[:4])
		total += count
	}
	return total
}

func (s *Server) shutdownStreams() {
	if s.streamStopCh == nil {
		return
	}
	s.streamStopOnce.Do(func() {
		close(s.streamStopCh)
	})
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
		owner := s.sessionOwners[id]
		victims = append(victims, victim{
			id:       id,
			sess:     sess,
			upstream: s.upstreams[id],
			target:   sess.Target,
			idleFor:  time.Since(last),
		})
		delete(s.sessions, id)
		delete(s.sessionOwners, id)
		delete(s.txReady, id)
		delete(s.streamInFlight, id)
		delete(s.firstReply, id)
		delete(s.responseStage, id)
		delete(s.upstreams, id)
		delete(s.lastActivity, id)
		if s.replay != nil {
			s.replay.remove(owner, id)
		}
		s.decrementSessionCount()
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
			v.sess.Abort()
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
			s.gcDoneSessions()
			s.gcIdleSessions()
		}
	}
}

// kick wakes the long-poll handler currently serving owner so it drains
// pending TX frames immediately. A non-blocking send keeps repeated kicks
// from blocking the upstream-read goroutine when the owner is not currently
// polling — the buffered len-1 channel collapses bursts into a single wake.
func (s *Server) kick(owner [frame.ClientIDLen]byte) {
	ch := s.activityFor(owner)
	select {
	case ch <- struct{}{}:
	default:
	}
}

// activityFor returns owner's wake channel, lazily allocating it on first
// use. Idle owner channels are garbage-collected after their sessions and
// active direct streams are gone.
func (s *Server) activityFor(owner [frame.ClientIDLen]byte) chan struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	ch, ok := s.activity[owner]
	if !ok {
		ch = make(chan struct{}, 1)
		s.activity[owner] = ch
	}
	return ch
}

func (s *Server) isDialSuppressed(target string) bool {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	state, ok := s.dialFail[target]
	if !ok {
		return false
	}
	if now.After(state.until) {
		if now.After(state.until.Add(dialFailureHistoryRetain)) {
			delete(s.dialFail, target)
		}
		return false
	}
	return state.failures >= dialFailureSuppressAfter
}

func (s *Server) recordDialFailure(target string, err error) {
	if !isBackoffEligibleDialErr(err) {
		return
	}
	now := time.Now()
	s.mu.Lock()
	state := s.dialFail[target]
	if now.After(state.until.Add(dialFailureHistoryRetain)) {
		state.failures = 0
	}
	if state.failures < 32 {
		state.failures++
	}
	backoff := dialFailureBackoffFor(state.failures)
	state.until = now.Add(backoff)
	state.updated = now
	s.dialFail[target] = state
	if len(s.dialFail) > dialFailureMaxEntries || now.Sub(s.dialFailPruned) >= dialFailurePruneInterval {
		s.pruneDialFailuresLocked(now)
	}
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

func (s *Server) pruneDialFailuresLocked(now time.Time) {
	s.dialFailPruned = now
	for target, state := range s.dialFail {
		if now.After(state.until.Add(dialFailureHistoryRetain)) {
			delete(s.dialFail, target)
		}
	}
	for len(s.dialFail) > dialFailureMaxEntries {
		var oldestTarget string
		var oldest time.Time
		first := true
		for target, state := range s.dialFail {
			when := state.updated
			if when.IsZero() {
				when = state.until
			}
			if first || when.Before(oldest) {
				oldestTarget = target
				oldest = when
				first = false
			}
		}
		if oldestTarget == "" {
			return
		}
		delete(s.dialFail, oldestTarget)
	}
}

func dialFailureBackoffFor(failures uint8) time.Duration {
	if failures == 0 {
		failures = 1
	}
	backoff := dialFailureBackoffBase
	for i := uint8(1); i < failures; i++ {
		if backoff >= dialFailureBackoffMax/2 {
			return dialFailureBackoffMax
		}
		backoff *= 2
	}
	if backoff > dialFailureBackoffMax {
		return dialFailureBackoffMax
	}
	return backoff
}
