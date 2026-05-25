package exit

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/kianmhz/GooseRelayVPN/internal/frame"
	"github.com/kianmhz/GooseRelayVPN/internal/protocol"
	"github.com/kianmhz/GooseRelayVPN/internal/session"
)

const exitTimingTestKeyHex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func mustExitTimingServer(tb testing.TB) *Server {
	tb.Helper()
	s, err := New(Config{ListenAddr: "127.0.0.1:0", AESKeyHex: exitTimingTestKeyHex})
	if err != nil {
		tb.Fatalf("new server: %v", err)
	}
	return s
}

func mustExitTimingCrypto(tb testing.TB) *frame.Crypto {
	tb.Helper()
	c, err := frame.NewCryptoFromHexKey(exitTimingTestKeyHex)
	if err != nil {
		tb.Fatalf("new crypto: %v", err)
	}
	return c
}

func setExitTimingDial(s *Server, dial func(network, address string, timeout time.Duration) (net.Conn, error)) {
	s.dial = dial
	s.dialContext = func(ctx context.Context, network, address string, timeout time.Duration) (net.Conn, error) {
		type dialOutcome struct {
			conn net.Conn
			err  error
		}
		done := make(chan dialOutcome, 1)
		go func() {
			conn, err := dial(network, address, timeout)
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
}

func TestExitStatsHandlesDisabledReplay(t *testing.T) {
	s := mustExitTimingServer(t)
	if s.replay != nil {
		t.Fatal("test server unexpectedly initialized downstream replay")
	}

	s.logStats()
	s.statsJSON = true
	s.logStats()
}

func TestExitEncodeResponseBatchRecordsCompressionStats(t *testing.T) {
	s := mustExitTimingServer(t)
	frames := []*frame.Frame{{
		SessionID: [frame.SessionIDLen]byte{1},
		Payload:   bytes.Repeat([]byte("exit-compressible-"), 128),
	}}

	if _, err := s.encodeResponseBatch([frame.ClientIDLen]byte{1}, frames, false); err != nil {
		t.Fatalf("encodeResponseBatch: %v", err)
	}

	if got := s.stats.compressAttempted.Load(); got != 1 {
		t.Fatalf("compressAttempted = %d, want 1", got)
	}
	if got := s.stats.compressUsed.Load(); got != 1 {
		t.Fatalf("compressUsed = %d, want 1", got)
	}
	if got := s.stats.compressZstd.Load(); got != 1 {
		t.Fatalf("compressZstd = %d, want 1", got)
	}
	if s.stats.compressSaved.Load() == 0 {
		t.Fatal("compressSaved = 0, want saved bytes")
	}
	if s.stats.compressWireBytes.Load() == 0 || s.stats.compressRawBytes.Load() == 0 || s.stats.compressBodyBytes.Load() == 0 {
		t.Fatalf("compression byte counters missing: raw=%d body=%d wire=%d",
			s.stats.compressRawBytes.Load(), s.stats.compressBodyBytes.Load(), s.stats.compressWireBytes.Load())
	}
}

func TestExitCompressionStatsMap(t *testing.T) {
	s := mustExitTimingServer(t)
	s.stats.compressAttempted.Add(2)
	s.stats.compressUsed.Add(1)
	s.stats.compressSkipped.Add(1)
	s.stats.compressRaw.Add(1)
	s.stats.compressZstd.Add(1)
	s.stats.compressRawBytes.Add(1000)
	s.stats.compressBodyBytes.Add(700)
	s.stats.compressWireBytes.Add(940)
	s.stats.compressSaved.Add(300)
	s.stats.compressLost.Add(12)

	stats := s.compressionStatsMap()
	for key, want := range map[string]uint64{
		"attempted":   2,
		"used":        1,
		"skipped":     1,
		"raw":         1,
		"zstd":        1,
		"raw_bytes":   1000,
		"body_bytes":  700,
		"wire_bytes":  940,
		"saved_bytes": 300,
		"lost_bytes":  12,
	} {
		if got := stats[key]; got != want {
			t.Fatalf("compressionStatsMap[%s] = %d, want %d (map=%#v)", key, got, want, stats)
		}
	}
}

func payloadBytes(frames []*frame.Frame) int {
	var total int
	for _, f := range frames {
		if f != nil {
			total += len(f.Payload)
		}
	}
	return total
}

func TestExit_AdvancedPerformanceConfigResolvesRuntimeKnobs(t *testing.T) {
	s, err := New(Config{
		ListenAddr:                   "127.0.0.1:0",
		AESKeyHex:                    exitTimingTestKeyHex,
		MaxSessions:                  123,
		ActiveDrainWindow:            25 * time.Millisecond,
		LongPollWindow:               75 * time.Millisecond,
		UpstreamDialTimeout:          8 * time.Second,
		CoalesceWindow:               5 * time.Millisecond,
		CoalesceWindowBusy:           2 * time.Millisecond,
		MaxRequestBodyBytes:          2 * 1024 * 1024,
		MaxResponseBytesPreEncode:    512 * 1024,
		MaxDrainFramesPerSession:     16,
		SecondResponseBytesPreEncode: 512 * 1024,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if s.activeDrainWindow != 25*time.Millisecond {
		t.Fatalf("activeDrainWindow = %v, want 25ms", s.activeDrainWindow)
	}
	if s.longPollWindow != 75*time.Millisecond {
		t.Fatalf("longPollWindow = %v, want 75ms", s.longPollWindow)
	}
	if s.upstreamDialTimeout != 8*time.Second {
		t.Fatalf("upstreamDialTimeout = %v, want 8s", s.upstreamDialTimeout)
	}
	if s.coalesceWindow != 5*time.Millisecond {
		t.Fatalf("coalesceWindow = %v, want 5ms", s.coalesceWindow)
	}
	if s.coalesceWindowBusy != 2*time.Millisecond {
		t.Fatalf("coalesceWindowBusy = %v, want 2ms", s.coalesceWindowBusy)
	}
	if s.maxResponseBytesPreEncode != 512*1024 {
		t.Fatalf("maxResponseBytesPreEncode = %d, want 512KiB", s.maxResponseBytesPreEncode)
	}
	if s.secondResponseBytesPreEncode != 512*1024 {
		t.Fatalf("secondResponseBytesPreEncode = %d, want 512KiB", s.secondResponseBytesPreEncode)
	}
	if s.maxRequestBodyBytes != 2*1024*1024 {
		t.Fatalf("maxRequestBodyBytes = %d, want 2MiB", s.maxRequestBodyBytes)
	}
	if s.maxDrainFramesPerSession != 16 {
		t.Fatalf("maxDrainFramesPerSession = %d, want 16", s.maxDrainFramesPerSession)
	}
	if s.maxSessions != 123 {
		t.Fatalf("maxSessions = %d, want 123", s.maxSessions)
	}
}

func TestExit_DisableResponseRampCapsResolvesToZero(t *testing.T) {
	s, err := New(Config{
		ListenAddr:                "127.0.0.1:0",
		AESKeyHex:                 exitTimingTestKeyHex,
		DisableInitialResponseCap: true,
		DisableSecondResponseCap:  true,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if s.initialResponseBytesPreEncode != 0 {
		t.Fatalf("initialResponseBytesPreEncode = %d, want disabled 0", s.initialResponseBytesPreEncode)
	}
	if s.secondResponseBytesPreEncode != 0 {
		t.Fatalf("secondResponseBytesPreEncode = %d, want disabled 0", s.secondResponseBytesPreEncode)
	}
}

func TestExitHTTPServerUsesTightHeaderLimits(t *testing.T) {
	s := mustExitTimingServer(t)
	httpSrv := s.httpServer(http.NewServeMux())
	if httpSrv.ReadHeaderTimeout != 3*time.Second {
		t.Fatalf("ReadHeaderTimeout = %v, want 3s", httpSrv.ReadHeaderTimeout)
	}
	if httpSrv.MaxHeaderBytes != 4096 {
		t.Fatalf("MaxHeaderBytes = %d, want 4096", httpSrv.MaxHeaderBytes)
	}
}

func TestExit_DisableCoalesceAllowsZeroWindows(t *testing.T) {
	s, err := New(Config{
		ListenAddr:      "127.0.0.1:0",
		AESKeyHex:       exitTimingTestKeyHex,
		DisableCoalesce: true,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if s.coalesceWindow != 0 || s.coalesceWindowBusy != 0 {
		t.Fatalf("coalesce windows = %v/%v, want 0/0", s.coalesceWindow, s.coalesceWindowBusy)
	}
}

func TestExitOpenSessionEnforcesMaxSessions(t *testing.T) {
	s, err := New(Config{
		ListenAddr:      "127.0.0.1:0",
		AESKeyHex:       exitTimingTestKeyHex,
		UpstreamProxy:   "127.0.0.1:1",
		MaxSessions:     1,
		DisableCoalesce: true,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	setExitTimingDial(s, func(_, _ string, _ time.Duration) (net.Conn, error) {
		a, b := net.Pipe()
		t.Cleanup(func() {
			_ = a.Close()
			_ = b.Close()
		})
		return a, nil
	})

	var owner [frame.ClientIDLen]byte
	owner[0] = 0x51
	firstID := [frame.SessionIDLen]byte{0x01}
	if _, err := s.openSession(firstID, "example.com:443", owner); err != nil {
		t.Fatalf("first openSession: %v", err)
	}
	if got := s.sessionCount.Load(); got != 1 {
		t.Fatalf("sessionCount = %d, want 1", got)
	}

	secondID := [frame.SessionIDLen]byte{0x02}
	if _, err := s.openSession(secondID, "example.org:443", owner); !errors.Is(err, errSessionLimit) {
		t.Fatalf("second openSession err = %v, want errSessionLimit", err)
	}
	if got := s.sessionCount.Load(); got != 1 {
		t.Fatalf("sessionCount after rejected open = %d, want 1", got)
	}
}

func TestExitOpenSessionViaProxyRecordsDialAttemptStats(t *testing.T) {
	s, err := New(Config{
		ListenAddr:      "127.0.0.1:0",
		AESKeyHex:       exitTimingTestKeyHex,
		UpstreamProxy:   "127.0.0.1:1",
		DisableCoalesce: true,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	setExitTimingDial(s, func(_, _ string, _ time.Duration) (net.Conn, error) {
		a, b := net.Pipe()
		t.Cleanup(func() {
			_ = a.Close()
			_ = b.Close()
		})
		return a, nil
	})

	owner := [frame.ClientIDLen]byte{0x53}
	id := [frame.SessionIDLen]byte{0x04}
	if _, err := s.openSession(id, "example.com:443", owner); err != nil {
		t.Fatalf("openSession: %v", err)
	}
	if got := s.stats.dialProxy.Load(); got != 1 {
		t.Fatalf("dialProxy = %d, want 1", got)
	}
	if got := s.stats.dialAttempts.Load(); got != 1 {
		t.Fatalf("dialAttempts = %d, want 1", got)
	}
}

func TestExitOpenSessionViaProxyReturnsOnContextCancel(t *testing.T) {
	s, err := New(Config{
		ListenAddr:      "127.0.0.1:0",
		AESKeyHex:       exitTimingTestKeyHex,
		UpstreamProxy:   "127.0.0.1:1",
		DisableCoalesce: true,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	dialStarted := make(chan struct{})
	releaseDial := make(chan struct{})
	var once sync.Once
	setExitTimingDial(s, func(_, _ string, _ time.Duration) (net.Conn, error) {
		once.Do(func() { close(dialStarted) })
		<-releaseDial
		return nil, &net.OpError{Op: "dial", Net: "tcp", Err: errSimulatedDialFail{}}
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := s.openSessionContext(ctx, [frame.SessionIDLen]byte{0x64}, "example.com:443", [frame.ClientIDLen]byte{0x65})
		done <- err
	}()

	select {
	case <-dialStarted:
	case <-time.After(time.Second):
		close(releaseDial)
		t.Fatal("proxy dial did not start")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			close(releaseDial)
			t.Fatalf("openSessionContext err = %v, want context.Canceled", err)
		}
	case <-time.After(200 * time.Millisecond):
		close(releaseDial)
		t.Fatal("openSessionContext did not return when context was canceled")
	}
	if got := s.sessionCount.Load(); got != 0 {
		close(releaseDial)
		t.Fatalf("sessionCount after canceled proxy open = %d, want 0", got)
	}
	close(releaseDial)
}

func TestExitClientRSTCancelsPendingOpen(t *testing.T) {
	s, err := New(Config{
		ListenAddr:      "127.0.0.1:0",
		AESKeyHex:       exitTimingTestKeyHex,
		UpstreamProxy:   "127.0.0.1:1",
		DisableCoalesce: true,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	dialStarted := make(chan struct{})
	releaseDial := make(chan struct{})
	var once sync.Once
	setExitTimingDial(s, func(_, _ string, _ time.Duration) (net.Conn, error) {
		once.Do(func() { close(dialStarted) })
		<-releaseDial
		a, b := net.Pipe()
		t.Cleanup(func() {
			_ = a.Close()
			_ = b.Close()
		})
		return a, nil
	})

	owner := [frame.ClientIDLen]byte{0x66}
	id := [frame.SessionIDLen]byte{0x67}
	done := make(chan struct{})
	go func() {
		s.routeIncomingContext(context.Background(), &frame.Frame{
			SessionID: id,
			Flags:     frame.FlagSYN,
			Target:    "example.com:443",
		}, owner)
		close(done)
	}()

	select {
	case <-dialStarted:
	case <-time.After(time.Second):
		close(releaseDial)
		t.Fatal("pending dial did not start")
	}
	if !s.closeOwnedSession(owner, id, "client reset") {
		close(releaseDial)
		t.Fatal("closeOwnedSession did not cancel pending open")
	}
	select {
	case <-done:
	case <-time.After(200 * time.Millisecond):
		close(releaseDial)
		t.Fatal("pending open did not finish after RST cancellation")
	}

	s.mu.Lock()
	_, sessionExists := s.sessions[id]
	_, openingExists := s.opening[id]
	s.mu.Unlock()
	if sessionExists || openingExists {
		t.Fatalf("pending open registered after reset: sessionExists=%v openingExists=%v", sessionExists, openingExists)
	}
	if got := s.sessionCount.Load(); got != 0 {
		t.Fatalf("sessionCount = %d, want 0", got)
	}
	if got := s.stats.dialsFail.Load(); got != 0 {
		close(releaseDial)
		t.Fatalf("dialsFail = %d, want 0 for canceled pending open", got)
	}
	close(releaseDial)
}

func TestExitRouteIncomingWaitsForPendingOpenFromEarlierBatch(t *testing.T) {
	s, err := New(Config{
		ListenAddr:      "127.0.0.1:0",
		AESKeyHex:       exitTimingTestKeyHex,
		UpstreamProxy:   "127.0.0.1:1",
		DisableCoalesce: true,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	dialStarted := make(chan struct{})
	releaseDial := make(chan struct{})
	var (
		once         sync.Once
		upstreamPeer net.Conn
	)
	setExitTimingDial(s, func(_, _ string, _ time.Duration) (net.Conn, error) {
		once.Do(func() { close(dialStarted) })
		<-releaseDial
		a, b := net.Pipe()
		upstreamPeer = b
		t.Cleanup(func() {
			_ = a.Close()
			_ = b.Close()
		})
		return a, nil
	})

	owner := [frame.ClientIDLen]byte{0x6a}
	id := [frame.SessionIDLen]byte{0x6b}
	synDone := make(chan struct{})
	go func() {
		s.routeIncomingContext(context.Background(), &frame.Frame{
			SessionID: id,
			Flags:     frame.FlagSYN,
			Target:    "example.com:443",
		}, owner)
		close(synDone)
	}()

	select {
	case <-dialStarted:
	case <-time.After(time.Second):
		close(releaseDial)
		t.Fatal("pending dial did not start")
	}

	dataDone := make(chan struct{})
	go func() {
		s.routeIncomingContext(context.Background(), &frame.Frame{
			SessionID: id,
			Seq:       1,
			Payload:   []byte("early"),
		}, owner)
		close(dataDone)
	}()

	select {
	case <-dataDone:
		close(releaseDial)
		t.Fatal("non-SYN frame returned before pending open completed")
	case <-time.After(75 * time.Millisecond):
	}

	close(releaseDial)
	select {
	case <-synDone:
	case <-time.After(time.Second):
		t.Fatal("SYN route did not finish")
	}
	select {
	case <-dataDone:
	case <-time.After(time.Second):
		t.Fatal("DATA route did not finish after pending open completed")
	}
	if upstreamPeer == nil {
		t.Fatal("dial succeeded without exposing upstream peer")
	}
	_ = upstreamPeer.SetReadDeadline(time.Now().Add(time.Second))
	got := make([]byte, len("early"))
	if _, err := io.ReadFull(upstreamPeer, got); err != nil {
		t.Fatalf("read upstream payload: %v", err)
	}
	if string(got) != "early" {
		t.Fatalf("upstream payload = %q, want early", got)
	}

	s.mu.Lock()
	pendingRST := len(s.pendingRSTs[owner])
	s.mu.Unlock()
	if pendingRST != 0 {
		t.Fatalf("pending RST count = %d, want 0 for frame waited behind SYN", pendingRST)
	}
}

func TestExitAbortAllCancelsPendingOpen(t *testing.T) {
	s, err := New(Config{
		ListenAddr:      "127.0.0.1:0",
		AESKeyHex:       exitTimingTestKeyHex,
		UpstreamProxy:   "127.0.0.1:1",
		DisableCoalesce: true,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	dialStarted := make(chan struct{})
	releaseDial := make(chan struct{})
	var once sync.Once
	setExitTimingDial(s, func(_, _ string, _ time.Duration) (net.Conn, error) {
		once.Do(func() { close(dialStarted) })
		<-releaseDial
		a, b := net.Pipe()
		t.Cleanup(func() {
			_ = a.Close()
			_ = b.Close()
		})
		return a, nil
	})

	owner := [frame.ClientIDLen]byte{0x68}
	id := [frame.SessionIDLen]byte{0x69}
	done := make(chan struct{})
	go func() {
		s.routeIncomingContext(context.Background(), &frame.Frame{
			SessionID: id,
			Flags:     frame.FlagSYN,
			Target:    "example.com:443",
		}, owner)
		close(done)
	}()

	select {
	case <-dialStarted:
	case <-time.After(time.Second):
		close(releaseDial)
		t.Fatal("pending dial did not start")
	}
	if got := s.abortAllSessions("server shutting down"); got != 1 {
		close(releaseDial)
		t.Fatalf("abortAllSessions canceled %d session(s), want 1 pending open", got)
	}
	select {
	case <-done:
	case <-time.After(200 * time.Millisecond):
		close(releaseDial)
		t.Fatal("pending open did not finish after abortAllSessions")
	}

	s.mu.Lock()
	_, sessionExists := s.sessions[id]
	_, openingExists := s.opening[id]
	s.mu.Unlock()
	if sessionExists || openingExists {
		t.Fatalf("pending open registered after abortAllSessions: sessionExists=%v openingExists=%v", sessionExists, openingExists)
	}
	if got := s.sessionCount.Load(); got != 0 {
		t.Fatalf("sessionCount = %d, want 0", got)
	}
	close(releaseDial)
}

func TestExitOpenSessionDuplicateWaitsForInFlightDialAtSessionLimit(t *testing.T) {
	s, err := New(Config{
		ListenAddr:      "127.0.0.1:0",
		AESKeyHex:       exitTimingTestKeyHex,
		UpstreamProxy:   "127.0.0.1:1",
		MaxSessions:     1,
		DisableCoalesce: true,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	var (
		dialStarted = make(chan struct{})
		releaseDial = make(chan struct{})
		once        sync.Once
	)
	setExitTimingDial(s, func(_, _ string, _ time.Duration) (net.Conn, error) {
		once.Do(func() { close(dialStarted) })
		<-releaseDial
		a, b := net.Pipe()
		t.Cleanup(func() {
			_ = a.Close()
			_ = b.Close()
		})
		return a, nil
	})

	owner := [frame.ClientIDLen]byte{0x52}
	id := [frame.SessionIDLen]byte{0x03}
	firstDone := make(chan struct{})
	var firstSess *session.Session
	var firstErr error
	go func() {
		firstSess, firstErr = s.openSessionContext(context.Background(), id, "example.com:443", owner)
		close(firstDone)
	}()

	select {
	case <-dialStarted:
	case <-time.After(time.Second):
		t.Fatal("first dial did not start")
	}

	secondDone := make(chan struct{})
	var secondSess *session.Session
	var secondErr error
	go func() {
		secondSess, secondErr = s.openSessionContext(context.Background(), id, "example.com:443", owner)
		close(secondDone)
	}()

	select {
	case <-secondDone:
		t.Fatalf("duplicate open returned before in-flight dial finished: sess=%v err=%v", secondSess, secondErr)
	case <-time.After(30 * time.Millisecond):
	}

	close(releaseDial)
	select {
	case <-firstDone:
	case <-time.After(time.Second):
		t.Fatal("first open did not finish")
	}
	select {
	case <-secondDone:
	case <-time.After(time.Second):
		t.Fatal("duplicate open did not finish")
	}
	if firstErr != nil || secondErr != nil {
		t.Fatalf("open errors first=%v second=%v", firstErr, secondErr)
	}
	if firstSess == nil || secondSess != firstSess {
		t.Fatalf("duplicate open returned different session: first=%p second=%p", firstSess, secondSess)
	}
	if got := s.sessionCount.Load(); got != 1 {
		t.Fatalf("sessionCount = %d, want 1", got)
	}
}

func TestExit_DrainAllPrioritizesFirstReplyOverOlderBulk(t *testing.T) {
	s := mustExitTimingServer(t)
	owner := [frame.ClientIDLen]byte{1}
	bulkID := [frame.SessionIDLen]byte{0x0b}
	firstReplyID := [frame.SessionIDLen]byte{0x0f}

	bulk := session.New(bulkID, "bulk.example:443", false)
	bulk.EnqueueTx([]byte("bulk"))
	firstReply := session.New(firstReplyID, "first.example:443", false)
	firstReply.EnqueueTx([]byte("first"))

	s.mu.Lock()
	s.sessions[bulkID] = bulk
	s.sessionOwners[bulkID] = owner
	s.txReady[bulkID] = struct{}{}
	s.lastActivity[bulkID] = time.Now().Add(-1 * time.Second)

	s.sessions[firstReplyID] = firstReply
	s.sessionOwners[firstReplyID] = owner
	s.txReady[firstReplyID] = struct{}{}
	s.firstReply[firstReplyID] = struct{}{}
	s.lastActivity[firstReplyID] = time.Now()
	s.mu.Unlock()

	frames, urgent := s.drainAll(owner, 1024)
	if !urgent {
		t.Fatalf("drainAll urgent = false, want true for first reply")
	}
	if len(frames) == 0 {
		t.Fatal("drainAll returned no frames")
	}
	if frames[0].SessionID != firstReplyID {
		t.Fatalf("first drained session = %x, want first-reply session %x", frames[0].SessionID[:], firstReplyID[:])
	}
}

func TestExit_DrainAllCapsFirstReplyAndDoesNotMixBulk(t *testing.T) {
	s := mustExitTimingServer(t)
	s.initialResponseBytesPreEncode = 512 * 1024
	owner := [frame.ClientIDLen]byte{1}

	bulkID := [frame.SessionIDLen]byte{0x0b}
	firstReplyID := [frame.SessionIDLen]byte{0x0f}
	chunk := bytes.Repeat([]byte("x"), MaxFramePayload*4)

	bulk := session.New(bulkID, "bulk.example:443", false)
	if err := bulk.EnqueueTx(chunk); err != nil {
		t.Fatalf("bulk enqueue: %v", err)
	}
	firstReply := session.New(firstReplyID, "first.example:443", false)
	if err := firstReply.EnqueueTx(chunk); err != nil {
		t.Fatalf("first enqueue: %v", err)
	}

	s.mu.Lock()
	s.sessions[bulkID] = bulk
	s.sessionOwners[bulkID] = owner
	s.txReady[bulkID] = struct{}{}
	s.lastActivity[bulkID] = time.Now()
	s.markTxReadyLocked(owner, bulkID)

	s.sessions[firstReplyID] = firstReply
	s.sessionOwners[firstReplyID] = owner
	s.txReady[firstReplyID] = struct{}{}
	s.firstReply[firstReplyID] = struct{}{}
	s.lastActivity[firstReplyID] = time.Now()
	s.markTxReadyLocked(owner, firstReplyID)
	s.mu.Unlock()

	frames, urgent := s.drainAll(owner, maxResponseBytesPreEncode)
	if !urgent {
		t.Fatal("drainAll urgent = false, want first reply urgent")
	}
	if len(frames) == 0 {
		t.Fatal("drainAll returned no first-reply frames")
	}
	var total int
	for _, f := range frames {
		if f.SessionID != firstReplyID {
			t.Fatalf("drained non-first-reply session %x in first-reply batch", f.SessionID[:])
		}
		total += len(f.Payload)
	}
	if total > s.initialResponseBytesPreEncode {
		t.Fatalf("first reply bytes = %d, want <= %d", total, s.initialResponseBytesPreEncode)
	}
	if !bulk.HasPendingTx() {
		t.Fatal("bulk session was drained into the first-reply batch")
	}
}

func TestExit_DrainAllRampsDownstreamResponseBytes(t *testing.T) {
	s := mustExitTimingServer(t)
	s.initialResponseBytesPreEncode = 512 * 1024
	s.secondResponseBytesPreEncode = 1024 * 1024
	s.maxResponseBytesPreEncode = 4 * 1024 * 1024
	owner := [frame.ClientIDLen]byte{1}
	id := [frame.SessionIDLen]byte{0x77}

	sess := session.New(id, "video.example:443", false)
	if err := sess.EnqueueTx(bytes.Repeat([]byte("x"), 8*1024*1024)); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	s.mu.Lock()
	s.sessions[id] = sess
	s.sessionOwners[id] = owner
	s.txReady[id] = struct{}{}
	s.firstReply[id] = struct{}{}
	s.lastActivity[id] = time.Now()
	s.markTxReadyLocked(owner, id)
	s.mu.Unlock()

	first, urgent := s.drainAll(owner, s.maxResponseBytesPreEncode)
	if !urgent {
		t.Fatal("first drain urgent = false, want true")
	}
	if got := payloadBytes(first); got == 0 || got > 512*1024 {
		t.Fatalf("first drain payload bytes = %d, want 1..512KiB", got)
	}

	second, urgent := s.drainAll(owner, s.maxResponseBytesPreEncode)
	if !urgent {
		t.Fatal("second drain urgent = false, want true so coalescing does not skip the ramp")
	}
	if got := payloadBytes(second); got == 0 || got > 1024*1024 {
		t.Fatalf("second drain payload bytes = %d, want 1..1MiB", got)
	}

	third, urgent := s.drainAll(owner, s.maxResponseBytesPreEncode)
	if urgent {
		t.Fatal("third drain urgent = true, want false")
	}
	if got := payloadBytes(third); got == 0 || got > 4*1024*1024 {
		t.Fatalf("third drain payload bytes = %d, want 1..configured 4MiB", got)
	}
}

func TestExit_DrainAllPrioritizesSecondRampBeforeBulk(t *testing.T) {
	s := mustExitTimingServer(t)
	s.secondResponseBytesPreEncode = 2 * 1024 * 1024
	s.maxResponseBytesPreEncode = 4 * 1024 * 1024
	owner := [frame.ClientIDLen]byte{0x31}
	bulkID := [frame.SessionIDLen]byte{0x32}
	rampID := [frame.SessionIDLen]byte{0x33}

	bulk := session.New(bulkID, "bulk.example:443", false)
	defer bulk.Stop()
	if err := bulk.EnqueueTx(bytes.Repeat([]byte("b"), 6*1024*1024)); err != nil {
		t.Fatalf("enqueue bulk: %v", err)
	}
	ramp := session.New(rampID, "video.example:443", false)
	defer ramp.Stop()
	if err := ramp.EnqueueTx(bytes.Repeat([]byte("r"), 3*1024*1024)); err != nil {
		t.Fatalf("enqueue ramp: %v", err)
	}

	s.mu.Lock()
	s.sessions[bulkID] = bulk
	s.sessionOwners[bulkID] = owner
	s.txReady[bulkID] = struct{}{}
	s.responseStage[bulkID] = 2
	s.lastActivity[bulkID] = time.Now()
	s.markTxReadyLocked(owner, bulkID)
	s.sessions[rampID] = ramp
	s.sessionOwners[rampID] = owner
	s.txReady[rampID] = struct{}{}
	s.responseStage[rampID] = 1
	s.lastActivity[rampID] = time.Now()
	s.markTxReadyLocked(owner, rampID)
	s.mu.Unlock()

	frames, urgent := s.drainAll(owner, s.maxResponseBytesPreEncode)
	if !urgent {
		t.Fatal("drain urgent = false, want second-ramp response to stay urgent")
	}
	var rampBytes, bulkBytes int
	for _, f := range frames {
		switch f.SessionID {
		case rampID:
			rampBytes += len(f.Payload)
		case bulkID:
			bulkBytes += len(f.Payload)
		}
	}
	if rampBytes == 0 || rampBytes > s.secondResponseBytesPreEncode {
		t.Fatalf("ramp bytes = %d, want 1..%d", rampBytes, s.secondResponseBytesPreEncode)
	}
	if bulkBytes != 0 {
		t.Fatalf("bulk bytes = %d, want 0 while second-ramp session is pending", bulkBytes)
	}
}

func TestExit_CoalesceStopsWhenRampDrainBecomesUrgent(t *testing.T) {
	s, err := New(Config{
		ListenAddr:                "127.0.0.1:0",
		AESKeyHex:                 exitTimingTestKeyHex,
		CoalesceWindow:            500 * time.Millisecond,
		CoalesceWindowBusy:        500 * time.Millisecond,
		MaxResponseBytesPreEncode: 4 * 1024 * 1024,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	c := mustExitTimingCrypto(t)
	owner := [frame.ClientIDLen]byte{0x42}
	bulkID := [frame.SessionIDLen]byte{0x43}
	rampID := [frame.SessionIDLen]byte{0x44}

	bulk := session.New(bulkID, "bulk.example:443", false)
	defer bulk.Stop()
	if err := bulk.EnqueueTx(bytes.Repeat([]byte("b"), (coalesceMinFrames+1)*MaxFramePayload)); err != nil {
		t.Fatalf("enqueue bulk: %v", err)
	}
	ramp := session.New(rampID, "video.example:443", false)
	defer ramp.Stop()
	if err := ramp.EnqueueTx(bytes.Repeat([]byte("r"), 5*1024*1024)); err != nil {
		t.Fatalf("enqueue ramp: %v", err)
	}

	s.mu.Lock()
	s.sessions[bulkID] = bulk
	s.sessionOwners[bulkID] = owner
	s.txReady[bulkID] = struct{}{}
	s.responseStage[bulkID] = 2
	s.lastActivity[bulkID] = time.Now()
	s.markTxReadyLocked(owner, bulkID)
	s.sessions[rampID] = ramp
	s.sessionOwners[rampID] = owner
	s.responseStage[rampID] = 1
	s.lastActivity[rampID] = time.Now()
	s.mu.Unlock()

	body, err := frame.EncodeBatchBinary(c, owner, nil)
	if err != nil {
		t.Fatalf("encode request: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/tunnel", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/octet-stream")
	rec := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		s.handleTunnel(rec, req)
		close(done)
	}()

	deadline := time.Now().Add(time.Second)
	for bulk.HasPendingTx() {
		if time.Now().After(deadline) {
			t.Fatal("bulk session was not drained into initial coalesced response")
		}
		time.Sleep(time.Millisecond)
	}

	s.mu.Lock()
	s.txReady[rampID] = struct{}{}
	s.markTxReadyLocked(owner, rampID)
	s.mu.Unlock()
	s.kick(owner)

	deadline = time.Now().Add(time.Second)
	for {
		s.mu.Lock()
		stage := s.responseStage[rampID]
		s.mu.Unlock()
		if stage >= 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("ramp session did not advance to second response stage")
		}
		time.Sleep(time.Millisecond)
	}
	s.kick(owner)

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handleTunnel did not return")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	_, frames, err := frame.DecodeBatchBinary(c, rec.Body.Bytes())
	if err != nil {
		t.Fatalf("decode response: %v", err)
	}
	var rampBytes int
	for _, f := range frames {
		if f.SessionID == rampID {
			rampBytes += len(f.Payload)
		}
	}
	if rampBytes == 0 || rampBytes > s.secondResponseBytesPreEncode {
		t.Fatalf("ramp bytes in coalesced response = %d, want 1..%d", rampBytes, s.secondResponseBytesPreEncode)
	}
	if !ramp.HasPendingTx() {
		t.Fatal("ramp session fully drained; coalesce skipped past the second response stage")
	}
}

func TestExit_CanceledCoalesceStillAccountsForDrainedFrames(t *testing.T) {
	s, err := New(Config{
		ListenAddr:                "127.0.0.1:0",
		AESKeyHex:                 exitTimingTestKeyHex,
		CoalesceWindow:            500 * time.Millisecond,
		CoalesceWindowBusy:        500 * time.Millisecond,
		MaxResponseBytesPreEncode: 4 * 1024 * 1024,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	c := mustExitTimingCrypto(t)
	owner := [frame.ClientIDLen]byte{0x4a}
	sid := [frame.SessionIDLen]byte{0x4b}
	sess := session.New(sid, "bulk.example:443", false)
	defer sess.Stop()
	if err := sess.EnqueueTx(bytes.Repeat([]byte("x"), (coalesceMinFrames+1)*MaxFramePayload)); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	s.mu.Lock()
	s.sessions[sid] = sess
	s.sessionOwners[sid] = owner
	s.lastActivity[sid] = time.Now()
	s.markTxReadyLocked(owner, sid)
	s.mu.Unlock()

	body, err := frame.EncodeBatchBinary(c, owner, nil)
	if err != nil {
		t.Fatalf("encode empty poll: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req := httptest.NewRequest(http.MethodPost, "/tunnel", bytes.NewReader(body)).WithContext(ctx)
	req.Header.Set("Content-Type", "application/octet-stream")
	rec := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		s.handleTunnel(rec, req)
		close(done)
	}()

	deadline := time.Now().Add(time.Second)
	for sess.HasPendingTx() {
		if time.Now().After(deadline) {
			t.Fatal("session was not drained into coalesce batch")
		}
		time.Sleep(time.Millisecond)
	}
	cancel()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("handleTunnel did not return after coalesce context cancel")
	}
	if rec.Body.Len() == 0 {
		t.Fatal("coalesce context cancel returned without writing or accounting for drained frames")
	}
	_, frames, err := frame.DecodeBatchBinary(c, rec.Body.Bytes())
	if err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(frames) != coalesceMinFrames+1 {
		t.Fatalf("response frames = %d, want %d drained frames", len(frames), coalesceMinFrames+1)
	}
}

func TestExit_AbortDownstreamSessionsQueuesRSTForAffectedOwner(t *testing.T) {
	s := mustExitTimingServer(t)
	owner := [frame.ClientIDLen]byte{1}
	otherOwner := [frame.ClientIDLen]byte{2}
	affectedID := [frame.SessionIDLen]byte{0xaa}
	untouchedID := [frame.SessionIDLen]byte{0xbb}

	affected := session.New(affectedID, "affected.example:443", false)
	affected.EnqueueTx([]byte("affected"))
	untouched := session.New(untouchedID, "untouched.example:443", false)
	untouched.EnqueueTx([]byte("untouched"))

	s.mu.Lock()
	s.sessions[affectedID] = affected
	s.sessionOwners[affectedID] = owner
	s.txReady[affectedID] = struct{}{}
	s.lastActivity[affectedID] = time.Now()
	s.sessions[untouchedID] = untouched
	s.sessionOwners[untouchedID] = otherOwner
	s.txReady[untouchedID] = struct{}{}
	s.lastActivity[untouchedID] = time.Now()
	s.mu.Unlock()

	if n := s.abortDownstreamSessions(owner, [][frame.SessionIDLen]byte{affectedID, untouchedID}, "test abort"); n != 1 {
		t.Fatalf("abortDownstreamSessions reset %d sessions, want 1", n)
	}

	s.mu.Lock()
	_, affectedPresent := s.sessions[affectedID]
	_, affectedReady := s.txReady[affectedID]
	_, untouchedPresent := s.sessions[untouchedID]
	_, untouchedReady := s.txReady[untouchedID]
	rsts := append([]*frame.Frame(nil), s.pendingRSTs[owner]...)
	s.mu.Unlock()

	if affectedPresent || affectedReady {
		t.Fatal("affected session still present in server maps")
	}
	if !untouchedPresent || !untouchedReady {
		t.Fatal("session owned by another client was removed")
	}
	if len(rsts) != 1 || rsts[0].SessionID != affectedID || !rsts[0].HasFlag(frame.FlagRST) {
		t.Fatalf("pending RSTs = %#v, want one RST for affected session", rsts)
	}
}

type closeTrackingConn struct {
	net.Conn
	closed bool
}

func (c *closeTrackingConn) Close() error {
	c.closed = true
	return c.Conn.Close()
}

func closeRxAndWaitDone(t *testing.T, sess *session.Session) {
	t.Helper()
	sess.CloseRx()
	deadline := time.Now().Add(time.Second)
	for !sess.IsDone() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !sess.IsDone() {
		t.Fatal("test setup failed: session is not done")
	}
}

func TestExit_GCDoneSessionsClosesUpstream(t *testing.T) {
	s := mustExitTimingServer(t)
	owner := [frame.ClientIDLen]byte{1}
	id := [frame.SessionIDLen]byte{0xcc}
	sess := session.New(id, "done.example:443", false)
	sess.RequestClose()
	_ = sess.DrainTx(MaxFramePayload)
	closeRxAndWaitDone(t, sess)

	a, b := net.Pipe()
	defer b.Close()
	upstream := &closeTrackingConn{Conn: a}

	s.mu.Lock()
	s.sessions[id] = sess
	s.sessionOwners[id] = owner
	s.upstreams[id] = upstream
	s.lastActivity[id] = time.Now()
	s.sessionCount.Store(1)
	s.mu.Unlock()

	s.gcDoneSessions()

	if !upstream.closed {
		t.Fatal("gcDoneSessions removed done session without closing upstream")
	}
	if got := s.sessionCount.Load(); got != 0 {
		t.Fatalf("sessionCount = %d, want 0", got)
	}
}

func TestExit_GCDoneSessionsKeepsDoneSessionWithPendingReplay(t *testing.T) {
	s, err := New(Config{
		ListenAddr:              "127.0.0.1:0",
		AESKeyHex:               exitTimingTestKeyHex,
		DownstreamReplayEnabled: true,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	owner := [frame.ClientIDLen]byte{0x11}
	id := [frame.SessionIDLen]byte{0x12}
	sess := session.New(id, "done-replay.example:443", false)
	defer sess.Stop()
	sess.RequestClose()
	_ = sess.DrainTx(MaxFramePayload)
	closeRxAndWaitDone(t, sess)

	a, b := net.Pipe()
	defer b.Close()
	defer a.Close()
	upstream := &closeTrackingConn{Conn: a}

	s.mu.Lock()
	s.sessions[id] = sess
	s.sessionOwners[id] = owner
	s.upstreams[id] = upstream
	s.lastActivity[id] = time.Now()
	s.sessionCount.Store(1)
	s.mu.Unlock()
	s.replay.track(owner, []*frame.Frame{{
		SessionID: id,
		Seq:       0,
		Payload:   []byte("final-downstream"),
	}}, time.Now())

	s.gcDoneSessions()

	s.mu.Lock()
	_, alive := s.sessions[id]
	count := s.sessionCount.Load()
	s.mu.Unlock()
	if !alive {
		t.Fatal("gcDoneSessions removed a done session with unacked replay frames")
	}
	if upstream.closed {
		t.Fatal("gcDoneSessions closed upstream while replay was still pending")
	}
	if count != 1 {
		t.Fatalf("sessionCount = %d, want 1 while replay is pending", count)
	}
	if !s.replay.hasPending(owner, id) {
		t.Fatal("gcDoneSessions removed replay state before downstream ACK")
	}
}

func TestExit_InboundRSTClosesOwnedSessionAndUpstream(t *testing.T) {
	s := mustExitTimingServer(t)
	owner := [frame.ClientIDLen]byte{0x44}
	id := [frame.SessionIDLen]byte{0x55}
	sess := session.New(id, "rst.example:443", false)

	a, b := net.Pipe()
	defer b.Close()
	upstream := &closeTrackingConn{Conn: a}

	s.mu.Lock()
	s.sessions[id] = sess
	s.sessionOwners[id] = owner
	s.upstreams[id] = upstream
	s.lastActivity[id] = time.Now()
	s.sessionCount.Store(1)
	s.mu.Unlock()

	s.routeIncoming(&frame.Frame{SessionID: id, Flags: frame.FlagRST}, owner)

	s.mu.Lock()
	_, stillSession := s.sessions[id]
	_, stillOwner := s.sessionOwners[id]
	_, stillUpstream := s.upstreams[id]
	count := s.sessionCount.Load()
	s.mu.Unlock()

	if stillSession || stillOwner || stillUpstream {
		t.Fatal("inbound RST did not remove server session state")
	}
	if count != 0 {
		t.Fatalf("sessionCount = %d, want 0", count)
	}
	if !upstream.closed {
		t.Fatal("inbound RST did not close upstream connection")
	}
}

func TestExit_DialFailureQueuesRSTForOpeningSession(t *testing.T) {
	s := mustExitTimingServer(t)
	c := mustExitTimingCrypto(t)
	setExitTimingDial(s, func(_, _ string, _ time.Duration) (net.Conn, error) {
		return nil, &net.OpError{Op: "dial", Net: "tcp", Err: errSimulatedDialFail{}}
	})

	clientID := [frame.ClientIDLen]byte{0x66}
	sessionID := [frame.SessionIDLen]byte{0x77}
	frames := invokeAsClient(t, s, c, clientID, []*frame.Frame{{
		SessionID: sessionID,
		Flags:     frame.FlagSYN,
		Target:    "127.0.0.1:1",
	}})

	if len(frames) != 1 || frames[0].SessionID != sessionID || !frames[0].HasFlag(frame.FlagRST) {
		t.Fatalf("dial failure response = %#v, want one RST for opening session", frames)
	}
}

func TestExit_StreamRequiresHelloBeforeTimeout(t *testing.T) {
	oldTimeout := streamHelloTimeout
	streamHelloTimeout = 50 * time.Millisecond
	defer func() { streamHelloTimeout = oldTimeout }()

	s := mustExitTimingServer(t)
	srv := httptest.NewServer(http.HandlerFunc(s.handleStream))
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/stream"
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, _, err := websocket.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatalf("dial stream: %v", err)
	}
	defer conn.CloseNow()

	_, _, err = conn.Read(ctx)
	if err == nil {
		t.Fatal("stream stayed open without encrypted hello")
	}
}

func TestReadTunnelRequestBodyRejectsOverLimit(t *testing.T) {
	_, err := readTunnelRequestBody(bytes.NewReader([]byte("abcdef")), -1, 5)
	if err == nil {
		t.Fatal("readTunnelRequestBody succeeded for over-limit body")
	}
}

func TestReadTunnelRequestBodyRejectsLargeContentLengthBeforeReading(t *testing.T) {
	_, err := readTunnelRequestBody(errReader{}, 6, 5)
	if !errors.Is(err, errRequestTooLarge) {
		t.Fatalf("readTunnelRequestBody err = %v, want errRequestTooLarge", err)
	}
}

func TestReadTunnelRequestBodyAllowsLimitSizedBody(t *testing.T) {
	got, err := readTunnelRequestBody(bytes.NewReader([]byte("abcde")), int64(len("abcde")), 5)
	if err != nil {
		t.Fatalf("readTunnelRequestBody: %v", err)
	}
	if string(got) != "abcde" {
		t.Fatalf("got %q, want abcde", got)
	}
}

func TestReadTunnelRequestBodyReadsKnownContentLengthInSmallChunks(t *testing.T) {
	const bodySize = 64 * 1024
	r := &maxReadSizeReader{remaining: bodySize}
	got, err := readTunnelRequestBody(r, bodySize, bodySize)
	if err != nil {
		t.Fatalf("readTunnelRequestBody: %v", err)
	}
	if len(got) != bodySize {
		t.Fatalf("body length = %d, want %d", len(got), bodySize)
	}
	if r.maxReadSize > 32*1024 {
		t.Fatalf("reader saw buffer size %d, want at most 32KiB", r.maxReadSize)
	}
}

type maxReadSizeReader struct {
	remaining   int
	maxReadSize int
}

func (r *maxReadSizeReader) Read(p []byte) (int, error) {
	if len(p) > r.maxReadSize {
		r.maxReadSize = len(p)
	}
	if r.remaining == 0 {
		return 0, io.EOF
	}
	if len(p) > r.remaining {
		p = p[:r.remaining]
	}
	for i := range p {
		p[i] = 'x'
	}
	r.remaining -= len(p)
	return len(p), nil
}

type failingResponseWriter struct {
	header http.Header
	code   int
	err    error
}

func (w *failingResponseWriter) Header() http.Header {
	if w.header == nil {
		w.header = make(http.Header)
	}
	return w.header
}

func (w *failingResponseWriter) Write([]byte) (int, error) {
	if w.err != nil {
		return 0, w.err
	}
	return 0, errors.New("injected response write failure")
}

func (w *failingResponseWriter) WriteHeader(code int) {
	w.code = code
}

func TestHandleTunnelSetsContentLength(t *testing.T) {
	s, err := New(Config{
		ListenAddr:         "127.0.0.1:0",
		AESKeyHex:          exitTimingTestKeyHex,
		LongPollWindow:     time.Millisecond,
		CoalesceWindow:     -1,
		CoalesceWindowBusy: -1,
	})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	var clientID [frame.ClientIDLen]byte
	body, err := frame.EncodeBatch(s.aead, clientID, nil)
	if err != nil {
		t.Fatalf("encode request: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/tunnel", bytes.NewReader(body))
	rr := httptest.NewRecorder()

	s.handleTunnel(rr, req)

	resp := rr.Result()
	defer resp.Body.Close()
	got := resp.Header.Get("Content-Length")
	want := strconv.Itoa(rr.Body.Len())
	if got != want {
		t.Fatalf("Content-Length = %q, want %q", got, want)
	}
}

func TestHandleTunnelWriteFailureKeepsReplayAndWakesStream(t *testing.T) {
	s, err := New(Config{
		ListenAddr:              "127.0.0.1:0",
		AESKeyHex:               exitTimingTestKeyHex,
		DownstreamReplayEnabled: true,
	})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	c := mustExitTimingCrypto(t)
	owner := [frame.ClientIDLen]byte{0x86}
	sid := [frame.SessionIDLen]byte{0x87}
	sess := session.New(sid, "download.example:443", false)
	defer sess.Stop()
	if err := sess.EnqueueTx([]byte("fresh")); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	s.mu.Lock()
	s.sessions[sid] = sess
	s.sessionOwners[sid] = owner
	s.lastActivity[sid] = time.Now()
	s.markTxReadyLocked(owner, sid)
	s.mu.Unlock()

	wakeCh := s.activityFor(owner)
	select {
	case <-wakeCh:
	default:
	}
	body, err := frame.EncodeBatchBinary(c, owner, nil)
	if err != nil {
		t.Fatalf("encode empty poll: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/tunnel", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/octet-stream")
	s.handleTunnel(&failingResponseWriter{err: errors.New("write failed")}, req)

	if !s.streamBlockedByReplay(owner) {
		t.Fatal("failed POST write did not retain replay")
	}
	if ready := s.replay.ready(owner, 4096, time.Now()); len(ready) != 1 || ready[0].SessionID != sid {
		t.Fatalf("failed POST write replay ready = %#v, want immediate replay for %x", ready, sid[:4])
	}
	select {
	case <-wakeCh:
	case <-time.After(time.Second):
		t.Fatal("failed POST write did not wake active stream/replay waiter")
	}
}

func TestHandleTunnelWriteFailureRequeuesReplayControlFrames(t *testing.T) {
	s, err := New(Config{
		ListenAddr:              "127.0.0.1:0",
		AESKeyHex:               exitTimingTestKeyHex,
		DownstreamReplayEnabled: true,
	})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	c := mustExitTimingCrypto(t)
	owner := [frame.ClientIDLen]byte{0x88}
	replaySID := [frame.SessionIDLen]byte{0x89}
	rstSID := [frame.SessionIDLen]byte{0x8a}
	s.replay.retryDelay = time.Nanosecond
	s.replay.track(owner, []*frame.Frame{{
		SessionID: replaySID,
		Seq:       0,
		Payload:   []byte("pending-replay"),
	}}, time.Now().Add(-time.Millisecond))
	s.queueRST(owner, rstSID)

	body, err := frame.EncodeBatchBinary(c, owner, nil)
	if err != nil {
		t.Fatalf("encode empty poll: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/tunnel", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/octet-stream")
	s.handleTunnel(&failingResponseWriter{err: errors.New("write failed")}, req)

	if !s.streamBlockedByReplay(owner) {
		t.Fatal("failed replay POST write did not retain replay")
	}
	frames, _ := s.drainPendingControl(owner)
	if len(frames) != 1 || frames[0].SessionID != rstSID || !frames[0].HasFlag(frame.FlagRST) {
		t.Fatalf("requeued control frames = %#v, want RST for %x", frames, rstSID[:4])
	}
}

func TestHandleTunnelRejectsWhenUnauthenticatedReadSlotsFull(t *testing.T) {
	s := mustExitTimingServer(t)
	s.unauthTunnelReads = make(chan struct{}, 1)
	s.unauthTunnelReads <- struct{}{}

	req := httptest.NewRequest(http.MethodPost, "/tunnel", errReader{})
	req.ContentLength = 1
	rec := httptest.NewRecorder()

	s.handleTunnel(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}
}

func TestHandleTunnelReleasesUnauthenticatedReadSlotAfterDecode(t *testing.T) {
	s := mustExitTimingServer(t)
	s.unauthTunnelReads = make(chan struct{}, 1)
	s.longPollWindow = 2 * time.Second
	c := mustExitTimingCrypto(t)
	owner := [frame.ClientIDLen]byte{0x91}

	body, err := frame.EncodeBatchBinary(c, owner, nil)
	if err != nil {
		t.Fatalf("encode first request: %v", err)
	}
	readStarted := make(chan struct{})
	firstCtx, cancelFirst := context.WithCancel(context.Background())
	defer cancelFirst()
	firstReq := httptest.NewRequest(http.MethodPost, "/tunnel", &signalReadStartReader{
		r:       bytes.NewReader(body),
		started: readStarted,
	}).WithContext(firstCtx)
	firstReq.ContentLength = int64(len(body))
	firstReq.Header.Set("Content-Type", "application/octet-stream")
	firstRec := httptest.NewRecorder()
	firstDone := make(chan struct{})
	go func() {
		s.handleTunnel(firstRec, firstReq)
		close(firstDone)
	}()

	select {
	case <-readStarted:
	case <-time.After(time.Second):
		t.Fatal("first request body was not read")
	}

	deadline := time.After(time.Second)
	for {
		select {
		case <-firstDone:
			t.Fatal("first long-poll returned before slot-release check")
		case <-deadline:
			t.Fatal("unauthenticated read slot stayed occupied after valid decode")
		default:
		}
		if len(s.unauthTunnelReads) == 0 {
			goto released
		}
		time.Sleep(time.Millisecond)
	}

released:
	secondReq := httptest.NewRequest(http.MethodPost, "/tunnel", errReader{})
	secondReq.ContentLength = 1
	secondRec := httptest.NewRecorder()
	s.handleTunnel(secondRec, secondReq)
	if secondRec.Code == http.StatusServiceUnavailable {
		t.Fatal("second request was rejected by pre-auth slot while first authenticated long-poll was active")
	}

	cancelFirst()
	select {
	case <-firstDone:
	case <-time.After(time.Second):
		t.Fatal("first long-poll did not finish")
	}
}

type signalReadStartReader struct {
	r       io.Reader
	started chan struct{}
	once    sync.Once
}

func (r *signalReadStartReader) Read(p []byte) (int, error) {
	r.once.Do(func() { close(r.started) })
	return r.r.Read(p)
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) {
	return 0, errors.New("reader should not be touched")
}

func TestExit_RequestBodyLimitIndependentFromResponseBudget(t *testing.T) {
	s, err := New(Config{
		ListenAddr:                "127.0.0.1:0",
		AESKeyHex:                 exitTimingTestKeyHex,
		MaxRequestBodyBytes:       protocol.MaxFramePayload + 1024,
		MaxResponseBytesPreEncode: protocol.MaxFramePayload,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	body := bytes.Repeat([]byte("x"), protocol.MaxFramePayload+1)
	req := httptest.NewRequest(http.MethodPost, "/tunnel", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	s.handleTunnel(rec, req)

	if rec.Code == http.StatusBadRequest {
		t.Fatalf("request was rejected by response budget; want body read to use maxRequestBodyBytes=%d", s.maxRequestBodyBytes)
	}
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want decode failure HTTP 204 after body read succeeds", rec.Code)
	}
}

func TestExit_DirectBinaryRequestGetsBinaryResponse(t *testing.T) {
	s := mustExitTimingServer(t)
	c := mustExitTimingCrypto(t)

	var clientID [frame.ClientIDLen]byte
	clientID[0] = 0x42
	body, err := frame.EncodeBatchBinary(c, clientID, nil)
	if err != nil {
		t.Fatalf("encode binary: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/tunnel", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/octet-stream")
	rec := httptest.NewRecorder()

	s.handleTunnel(rec, req)

	resp := rec.Result()
	defer resp.Body.Close()
	if got := resp.Header.Get("Content-Type"); got != "application/octet-stream" {
		t.Fatalf("Content-Type = %q, want application/octet-stream", got)
	}
	respBody, _ := io.ReadAll(resp.Body)
	gotClient, frames, err := frame.DecodeBatchBinary(c, respBody)
	if err != nil {
		t.Fatalf("decode binary response: %v", err)
	}
	if gotClient != clientID {
		t.Fatalf("clientID mismatch: got %x want %x", gotClient, clientID)
	}
	if len(frames) != 0 {
		t.Fatalf("frames = %d, want 0", len(frames))
	}
}

func TestStreamRejectsOversizedUnauthenticatedHello(t *testing.T) {
	s := mustExitTimingServer(t)
	c := mustExitTimingCrypto(t)
	srv := httptest.NewServer(http.HandlerFunc(s.handleStream))
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	conn, _, err := websocket.Dial(context.Background(), wsURL, nil)
	if err != nil {
		t.Fatalf("dial stream: %v", err)
	}
	defer conn.CloseNow()

	var clientID [frame.ClientIDLen]byte
	clientID[0] = 0x7a
	var sid [frame.SessionIDLen]byte
	sid[0] = 0x41
	body, err := frame.EncodeBatchBinary(c, clientID, []*frame.Frame{{
		SessionID: sid,
		Seq:       0,
		Payload:   bytes.Repeat([]byte("x"), 128*1024),
	}})
	if err != nil {
		t.Fatalf("encode oversized hello: %v", err)
	}
	if err := conn.Write(context.Background(), websocket.MessageBinary, body); err != nil {
		t.Fatalf("write oversized hello: %v", err)
	}

	deadline := time.Now().Add(300 * time.Millisecond)
	for time.Now().Before(deadline) {
		s.mu.Lock()
		active := len(s.activeStreams)
		s.mu.Unlock()
		if active == 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	s.mu.Lock()
	active := len(s.activeStreams)
	s.mu.Unlock()
	t.Fatalf("activeStreams = %d after oversized unauthenticated hello, want 0", active)
}

func TestStreamRejectsBrowserCrossOriginDial(t *testing.T) {
	s := mustExitTimingServer(t)
	srv := httptest.NewServer(http.HandlerFunc(s.handleStream))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(srv.URL, "http")+"/stream", &websocket.DialOptions{
		HTTPHeader: http.Header{"Origin": []string{"https://example.invalid"}},
	})
	if err == nil {
		t.Fatal("cross-origin browser-style stream dial succeeded")
	}
}

func TestExit_BinaryTunnelContentTypeIsCaseInsensitive(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/tunnel", nil)
	req.Header.Set("Content-Type", "Application/Octet-Stream; charset=binary")
	if !isBinaryTunnelRequest(req) {
		t.Fatal("mixed-case application/octet-stream content type was not detected as binary")
	}
	req.Header.Set("Content-Type", "text/plain")
	if isBinaryTunnelRequest(req) {
		t.Fatal("text/plain was incorrectly detected as binary")
	}
}

func TestExit_StreamVersionProbeReturnsBinaryBatch(t *testing.T) {
	s := mustExitTimingServer(t)
	c := mustExitTimingCrypto(t)
	mux := http.NewServeMux()
	mux.HandleFunc("/stream", s.handleStream)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(srv.URL, "http")+"/stream", nil)
	if err != nil {
		t.Fatalf("dial stream: %v", err)
	}
	defer conn.CloseNow()

	clientID := [frame.ClientIDLen]byte{0x55}
	sessionID := [frame.SessionIDLen]byte{0x77}
	body, err := frame.EncodeBatchBinary(c, clientID, []*frame.Frame{{
		SessionID: sessionID,
		Flags:     frame.FlagACK,
		Payload:   protocol.EncodeProbePayload("test-client"),
	}})
	if err != nil {
		t.Fatalf("encode probe: %v", err)
	}
	if err := conn.Write(ctx, websocket.MessageBinary, body); err != nil {
		t.Fatalf("write probe: %v", err)
	}

	typ, respBody, err := conn.Read(ctx)
	if err != nil {
		t.Fatalf("read stream response: %v", err)
	}
	if typ != websocket.MessageBinary {
		t.Fatalf("message type = %v, want binary", typ)
	}
	gotClient, frames, err := frame.DecodeBatchBinary(c, respBody)
	if err != nil {
		t.Fatalf("decode stream response: %v", err)
	}
	if gotClient != clientID {
		t.Fatalf("clientID = %x, want %x", gotClient, clientID)
	}
	if len(frames) != 1 || !frames[0].HasFlag(frame.FlagRST) {
		t.Fatalf("frames = %#v, want one RST version response", frames)
	}
	info, err := protocol.DecodeVersionInfo(frames[0].Payload)
	if err != nil || !info.OK {
		t.Fatalf("version payload decode = %#v, %v", info, err)
	}
}

func TestExit_VersionProbeAdvertisesDownstreamReplayWhenEnabled(t *testing.T) {
	s, err := New(Config{
		ListenAddr:              "127.0.0.1:0",
		AESKeyHex:               exitTimingTestKeyHex,
		DownstreamReplayEnabled: true,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	c := mustExitTimingCrypto(t)
	clientID := [frame.ClientIDLen]byte{0x57}
	sessionID := [frame.SessionIDLen]byte{0x79}

	body, err := frame.EncodeBatchBinary(c, clientID, []*frame.Frame{{
		SessionID: sessionID,
		Flags:     frame.FlagACK,
		Payload:   protocol.EncodeProbePayload("test-client"),
	}})
	if err != nil {
		t.Fatalf("encode probe: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/tunnel", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/octet-stream")
	rr := httptest.NewRecorder()
	s.handleTunnel(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	_, frames, err := frame.DecodeBatchBinary(c, rr.Body.Bytes())
	if err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(frames) != 1 || !frames[0].HasFlag(frame.FlagRST) {
		t.Fatalf("frames = %#v, want version RST", frames)
	}
	info, err := protocol.DecodeVersionInfo(frames[0].Payload)
	if err != nil {
		t.Fatalf("version payload decode: %v", err)
	}
	if !protocol.HasFeature(info.Features, protocol.FeatureDownstreamReplayV1) {
		t.Fatalf("features = %v, want %s", info.Features, protocol.FeatureDownstreamReplayV1)
	}
}

func TestExit_ClientRunResetAbortsPreviousOwnerSessionsOnly(t *testing.T) {
	s := mustExitTimingServer(t)
	c := mustExitTimingCrypto(t)

	oldOwner := [frame.ClientIDLen]byte{0x61}
	newOwner := [frame.ClientIDLen]byte{0x62}
	instanceID := "phone-main"

	oldProbeID := [frame.SessionIDLen]byte{0x71}
	invokeAsClient(t, s, c, oldOwner, []*frame.Frame{{
		SessionID: oldProbeID,
		Flags:     frame.FlagACK,
		Payload: protocol.EncodeProbePayloadWithOptions("old-client", protocol.ProbeOptions{
			ClientInstanceID: instanceID,
			RunID:            "old-run",
		}),
	}})

	oldSessionID := [frame.SessionIDLen]byte{0x72}
	oldSess := session.New(oldSessionID, "example.com:443", false)
	t.Cleanup(oldSess.Stop)
	s.mu.Lock()
	s.sessions[oldSessionID] = oldSess
	s.sessionOwners[oldSessionID] = oldOwner
	s.lastActivity[oldSessionID] = time.Now()
	s.streamGen[oldOwner] = 1
	s.activeStreams[oldOwner] = 1
	s.mu.Unlock()

	newProbeID := [frame.SessionIDLen]byte{0x73}
	frames := invokeAsClient(t, s, c, newOwner, []*frame.Frame{{
		SessionID: newProbeID,
		Flags:     frame.FlagACK,
		Payload: protocol.EncodeProbePayloadWithOptions("new-client", protocol.ProbeOptions{
			ClientInstanceID: instanceID,
			RunID:            "new-run",
			ResetPrevious:    true,
		}),
	}})

	if len(frames) != 1 || !frames[0].HasFlag(frame.FlagRST) {
		t.Fatalf("frames = %#v, want one version response", frames)
	}
	s.mu.Lock()
	_, oldExists := s.sessions[oldSessionID]
	_, newRegistered := s.clientInstances[instanceID][newOwner]
	_, oldRegistered := s.clientInstances[instanceID][oldOwner]
	_, oldStreamActive := s.activeStreams[oldOwner]
	pendingOldRSTs := len(s.pendingRSTs[oldOwner])
	s.mu.Unlock()
	if oldExists {
		t.Fatal("old owner session still exists after client_run_reset_v1 probe")
	}
	if !newRegistered {
		t.Fatal("new owner was not registered for the client instance")
	}
	if oldRegistered {
		t.Fatal("old owner still registered after reset")
	}
	if oldStreamActive {
		t.Fatal("old owner stream still registered after reset")
	}
	if pendingOldRSTs != 0 {
		t.Fatalf("pending RSTs for stale owner = %d, want cleaned", pendingOldRSTs)
	}
}

func TestExit_GCDropsInactiveClientInstanceMetadata(t *testing.T) {
	s := mustExitTimingServer(t)
	c := mustExitTimingCrypto(t)

	owner := [frame.ClientIDLen]byte{0x64}
	instanceID := "gc-client"
	probeID := [frame.SessionIDLen]byte{0x74}
	invokeAsClient(t, s, c, owner, []*frame.Frame{{
		SessionID: probeID,
		Flags:     frame.FlagACK,
		Payload: protocol.EncodeProbePayloadWithOptions("client", protocol.ProbeOptions{
			ClientInstanceID: instanceID,
			RunID:            "run",
		}),
	}})

	s.gcDoneSessions()

	s.mu.Lock()
	_, byOwner := s.clientInstanceByOwner[owner]
	owners := s.clientInstances[instanceID]
	s.mu.Unlock()
	if byOwner {
		t.Fatal("inactive owner remained in clientInstanceByOwner")
	}
	if len(owners) != 0 {
		t.Fatalf("inactive instance owners = %d, want cleaned", len(owners))
	}
}

func TestExit_DownstreamACKDoesNotEnterSessionRx(t *testing.T) {
	s := mustExitTimingServer(t)
	owner := [frame.ClientIDLen]byte{0x58}
	sessionID := [frame.SessionIDLen]byte{0x7a}
	sess := session.New(sessionID, "example.com:443", false)
	defer sess.Stop()

	s.mu.Lock()
	s.sessions[sessionID] = sess
	s.sessionOwners[sessionID] = owner
	s.lastActivity[sessionID] = time.Now()
	s.mu.Unlock()

	s.routeIncomingContext(context.Background(), &frame.Frame{
		SessionID: sessionID,
		Flags:     frame.FlagACK,
		Payload:   protocol.EncodeDownstreamACK(7),
	}, owner)

	select {
	case got := <-sess.RxChan:
		t.Fatalf("ACK entered session RxChan as payload %q", got)
	case <-time.After(50 * time.Millisecond):
	}
}

func TestExit_MalformedDownstreamACKDoesNotEnterSessionRx(t *testing.T) {
	s := mustExitTimingServer(t)
	owner := [frame.ClientIDLen]byte{0x58}
	sessionID := [frame.SessionIDLen]byte{0x7f}
	sess := session.New(sessionID, "example.com:443", false)
	defer sess.Stop()

	s.mu.Lock()
	s.sessions[sessionID] = sess
	s.sessionOwners[sessionID] = owner
	s.lastActivity[sessionID] = time.Now()
	s.mu.Unlock()

	s.routeIncomingContext(context.Background(), &frame.Frame{
		SessionID: sessionID,
		Flags:     frame.FlagACK,
		Payload:   []byte("not-gack"),
	}, owner)

	select {
	case got := <-sess.RxChan:
		t.Fatalf("malformed ACK entered session RxChan as payload %q", got)
	case <-time.After(50 * time.Millisecond):
	}
}

func TestExit_DownstreamACKForUnknownSessionIsIgnored(t *testing.T) {
	s, err := New(Config{
		ListenAddr:              "127.0.0.1:0",
		AESKeyHex:               exitTimingTestKeyHex,
		DownstreamReplayEnabled: true,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	s.replay.retryDelay = time.Millisecond

	owner := [frame.ClientIDLen]byte{0x58}
	sessionID := [frame.SessionIDLen]byte{0x7d}
	now := time.Now()
	s.replay.track(owner, []*frame.Frame{{
		SessionID: sessionID,
		Seq:       0,
		Payload:   []byte("still-buffered"),
	}}, now)

	s.routeIncomingContext(context.Background(), &frame.Frame{
		SessionID: sessionID,
		Flags:     frame.FlagACK,
		Payload:   protocol.EncodeDownstreamACK(1),
	}, owner)

	if got := s.stats.ackReceived.Load(); got != 0 {
		t.Fatalf("ack_received = %d, want 0 for unknown-session ACK", got)
	}
	ready := s.replay.ready(owner, 1024, now.Add(2*time.Millisecond))
	if len(ready) != 1 || string(ready[0].Payload) != "still-buffered" {
		t.Fatalf("ready after unknown ACK = %#v, want replay frame preserved", ready)
	}
}

func TestExit_DownstreamReplayResendsLostResponse(t *testing.T) {
	s, err := New(Config{
		ListenAddr:                    "127.0.0.1:0",
		AESKeyHex:                     exitTimingTestKeyHex,
		LongPollWindow:                10 * time.Millisecond,
		MaxResponseBytesPreEncode:     protocol.MaxFramePayload,
		DownstreamReplayEnabled:       true,
		InitialResponseBytesPreEncode: protocol.MaxFramePayload,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	s.replay.retryDelay = 10 * time.Millisecond
	c := mustExitTimingCrypto(t)
	upstream, closeUpstream := startMarkerServer(t, []byte("lost-response"), 0)
	defer closeUpstream()

	clientID := [frame.ClientIDLen]byte{0x59}
	sessionID := [frame.SessionIDLen]byte{0x7b}
	body, err := frame.EncodeBatchBinary(c, clientID, []*frame.Frame{{
		SessionID: sessionID,
		Seq:       0,
		Flags:     frame.FlagSYN,
		Target:    upstream,
	}})
	if err != nil {
		t.Fatalf("encode SYN: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/tunnel", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/octet-stream")
	first := httptest.NewRecorder()
	s.handleTunnel(first, req)
	if first.Code != http.StatusOK {
		t.Fatalf("first status = %d, want 200", first.Code)
	}
	// Simulate losing the first HTTP response: do not deliver or ACK it.

	time.Sleep(15 * time.Millisecond)
	empty, err := frame.EncodeBatchBinary(c, clientID, nil)
	if err != nil {
		t.Fatalf("encode empty poll: %v", err)
	}
	req = httptest.NewRequest(http.MethodPost, "/tunnel", bytes.NewReader(empty))
	req.Header.Set("Content-Type", "application/octet-stream")
	second := httptest.NewRecorder()
	s.handleTunnel(second, req)
	if second.Code != http.StatusOK {
		t.Fatalf("second status = %d, want 200", second.Code)
	}
	_, frames, err := frame.DecodeBatchBinary(c, second.Body.Bytes())
	if err != nil {
		t.Fatalf("decode replay response: %v", err)
	}
	if len(frames) != 1 || frames[0].SessionID != sessionID || string(frames[0].Payload) != "lost-response" {
		t.Fatalf("replay frames = %#v, want lost-response for session %x", frames, sessionID[:4])
	}
}

func TestExit_DownstreamReplayWakesAtRetryDelay(t *testing.T) {
	s, err := New(Config{
		ListenAddr:                    "127.0.0.1:0",
		AESKeyHex:                     exitTimingTestKeyHex,
		LongPollWindow:                time.Second,
		MaxResponseBytesPreEncode:     protocol.MaxFramePayload,
		DownstreamReplayEnabled:       true,
		InitialResponseBytesPreEncode: protocol.MaxFramePayload,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	s.replay.retryDelay = 20 * time.Millisecond
	c := mustExitTimingCrypto(t)
	upstream, closeUpstream := startMarkerServer(t, []byte("retry-delay"), 0)
	defer closeUpstream()

	clientID := [frame.ClientIDLen]byte{0x59}
	sessionID := [frame.SessionIDLen]byte{0x7e}
	body, err := frame.EncodeBatchBinary(c, clientID, []*frame.Frame{{
		SessionID: sessionID,
		Seq:       0,
		Flags:     frame.FlagSYN,
		Target:    upstream,
	}})
	if err != nil {
		t.Fatalf("encode SYN: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/tunnel", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/octet-stream")
	first := httptest.NewRecorder()
	s.handleTunnel(first, req)
	if first.Code != http.StatusOK {
		t.Fatalf("first status = %d, want 200", first.Code)
	}

	empty, err := frame.EncodeBatchBinary(c, clientID, nil)
	if err != nil {
		t.Fatalf("encode empty poll: %v", err)
	}
	req = httptest.NewRequest(http.MethodPost, "/tunnel", bytes.NewReader(empty))
	req.Header.Set("Content-Type", "application/octet-stream")
	second := httptest.NewRecorder()
	start := time.Now()
	s.handleTunnel(second, req)
	elapsed := time.Since(start)
	if elapsed > 250*time.Millisecond {
		t.Fatalf("replay response took %s, want retry-delay wake well before long poll", elapsed)
	}
	_, frames, err := frame.DecodeBatchBinary(c, second.Body.Bytes())
	if err != nil {
		t.Fatalf("decode replay response: %v", err)
	}
	if len(frames) != 1 || frames[0].SessionID != sessionID || string(frames[0].Payload) != "retry-delay" {
		t.Fatalf("replay frames = %#v, want retry-delay for session %x", frames, sessionID[:4])
	}
}

func TestExit_DownstreamReplayAlsoFlushesPendingControl(t *testing.T) {
	s, err := New(Config{
		ListenAddr:              "127.0.0.1:0",
		AESKeyHex:               exitTimingTestKeyHex,
		DownstreamReplayEnabled: true,
		DisableCoalesce:         true,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	s.replay.retryDelay = 0
	c := mustExitTimingCrypto(t)
	owner := [frame.ClientIDLen]byte{0x64}
	replayID := [frame.SessionIDLen]byte{0x65}
	rstID := [frame.SessionIDLen]byte{0x66}

	s.replay.track(owner, []*frame.Frame{{
		SessionID: replayID,
		Seq:       0,
		Payload:   []byte("pending-replay"),
	}}, time.Now().Add(-time.Second))
	s.queueRST(owner, rstID)

	frames := invokeAsClient(t, s, c, owner, nil)
	if len(frames) != 2 {
		t.Fatalf("frames = %#v, want replay frame followed by pending RST", frames)
	}
	if frames[0].SessionID != replayID || string(frames[0].Payload) != "pending-replay" {
		t.Fatalf("first frame = %#v, want replay payload before control", frames[0])
	}
	if frames[1].SessionID != rstID || !frames[1].HasFlag(frame.FlagRST) {
		t.Fatalf("second frame = %#v, want pending RST control", frames[1])
	}
}

func TestExit_DownstreamACKPrunesReplayBuffer(t *testing.T) {
	s, err := New(Config{
		ListenAddr:                    "127.0.0.1:0",
		AESKeyHex:                     exitTimingTestKeyHex,
		LongPollWindow:                10 * time.Millisecond,
		MaxResponseBytesPreEncode:     protocol.MaxFramePayload,
		InitialResponseBytesPreEncode: protocol.MaxFramePayload,
		DownstreamReplayEnabled:       true,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	s.replay.retryDelay = 10 * time.Millisecond
	c := mustExitTimingCrypto(t)
	upstream, closeUpstream := startMarkerServer(t, []byte("ack-pruned"), 0)
	defer closeUpstream()

	clientID := [frame.ClientIDLen]byte{0x5a}
	sessionID := [frame.SessionIDLen]byte{0x7c}
	body, err := frame.EncodeBatchBinary(c, clientID, []*frame.Frame{{
		SessionID: sessionID,
		Seq:       0,
		Flags:     frame.FlagSYN,
		Target:    upstream,
	}})
	if err != nil {
		t.Fatalf("encode SYN: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/tunnel", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/octet-stream")
	first := httptest.NewRecorder()
	s.handleTunnel(first, req)
	if first.Code != http.StatusOK {
		t.Fatalf("first status = %d, want 200", first.Code)
	}

	ackBody, err := frame.EncodeBatchBinary(c, clientID, []*frame.Frame{{
		SessionID: sessionID,
		Flags:     frame.FlagACK,
		Payload:   protocol.EncodeDownstreamACK(1),
	}})
	if err != nil {
		t.Fatalf("encode ACK: %v", err)
	}
	req = httptest.NewRequest(http.MethodPost, "/tunnel", bytes.NewReader(ackBody))
	req.Header.Set("Content-Type", "application/octet-stream")
	ackResp := httptest.NewRecorder()
	s.handleTunnel(ackResp, req)

	time.Sleep(15 * time.Millisecond)
	empty, err := frame.EncodeBatchBinary(c, clientID, nil)
	if err != nil {
		t.Fatalf("encode empty poll: %v", err)
	}
	req = httptest.NewRequest(http.MethodPost, "/tunnel", bytes.NewReader(empty))
	req.Header.Set("Content-Type", "application/octet-stream")
	second := httptest.NewRecorder()
	s.handleTunnel(second, req)
	_, frames, err := frame.DecodeBatchBinary(c, second.Body.Bytes())
	if err != nil {
		t.Fatalf("decode second response: %v", err)
	}
	if len(frames) != 0 {
		t.Fatalf("frames after ACK = %#v, want none", frames)
	}
}

func TestExit_DownstreamReplayCapDropReturnsEncryptedRST(t *testing.T) {
	s, err := New(Config{
		ListenAddr:                "127.0.0.1:0",
		AESKeyHex:                 exitTimingTestKeyHex,
		DownstreamReplayEnabled:   true,
		MaxResponseBytesPreEncode: 1024,
		DisableCoalesce:           true,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	s.replay = newDownstreamReplayManager(1, 4096, 4096, time.Minute, time.Millisecond)
	c := mustExitTimingCrypto(t)

	owner := [frame.ClientIDLen]byte{0x72}
	sid := [frame.SessionIDLen]byte{0x73}
	sess := session.New(sid, "download.example:443", false)
	if err := sess.EnqueueTx([]byte("too-large")); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	s.mu.Lock()
	s.sessions[sid] = sess
	s.sessionOwners[sid] = owner
	s.lastActivity[sid] = time.Now()
	s.markTxReadyLocked(owner, sid)
	s.mu.Unlock()

	frames := invokeAsClient(t, s, c, owner, nil)
	if len(frames) != 1 || frames[0].SessionID != sid || !frames[0].HasFlag(frame.FlagRST) {
		t.Fatalf("frames = %#v, want one encrypted RST for capped session", frames)
	}
	if got := s.stats.replayDroppedCap.Load(); got != 1 {
		t.Fatalf("replayDroppedCap = %d, want 1", got)
	}
}

func TestExit_DownstreamReplayCapDropSendsUnaffectedFramesAndRST(t *testing.T) {
	s, err := New(Config{
		ListenAddr:                "127.0.0.1:0",
		AESKeyHex:                 exitTimingTestKeyHex,
		DownstreamReplayEnabled:   true,
		MaxResponseBytesPreEncode: 1024,
		DisableCoalesce:           true,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	s.replay = newDownstreamReplayManager(4, 4096, 4096, time.Minute, time.Millisecond)
	c := mustExitTimingCrypto(t)

	owner := [frame.ClientIDLen]byte{0x7a}
	oversizedID := [frame.SessionIDLen]byte{0x7b}
	validID := [frame.SessionIDLen]byte{0x7c}
	oversized := session.New(oversizedID, "large.example:443", false)
	valid := session.New(validID, "small.example:443", false)
	defer oversized.Stop()
	defer valid.Stop()
	if err := oversized.EnqueueTx([]byte("too-large")); err != nil {
		t.Fatalf("enqueue oversized: %v", err)
	}
	if err := valid.EnqueueTx([]byte("ok")); err != nil {
		t.Fatalf("enqueue valid: %v", err)
	}
	s.mu.Lock()
	s.sessions[oversizedID] = oversized
	s.sessions[validID] = valid
	s.sessionOwners[oversizedID] = owner
	s.sessionOwners[validID] = owner
	s.lastActivity[oversizedID] = time.Now()
	s.lastActivity[validID] = time.Now()
	s.markTxReadyLocked(owner, oversizedID)
	s.markTxReadyLocked(owner, validID)
	s.mu.Unlock()

	frames := invokeAsClient(t, s, c, owner, nil)
	var sawRST, sawValid bool
	for _, f := range frames {
		switch {
		case f.SessionID == oversizedID && f.HasFlag(frame.FlagRST):
			sawRST = true
		case f.SessionID == validID && string(f.Payload) == "ok":
			sawValid = true
		case f.SessionID == oversizedID && len(f.Payload) > 0:
			t.Fatalf("capped session payload leaked in response: %#v", f)
		}
	}
	if !sawRST || !sawValid {
		t.Fatalf("frames = %#v, want valid payload plus RST for capped session", frames)
	}
	if got := s.stats.replayDroppedCap.Load(); got != 1 {
		t.Fatalf("replayDroppedCap = %d, want 1", got)
	}
}

func TestExit_DrainAllForStreamAllowsFreshFramesWithPendingReplay(t *testing.T) {
	s, err := New(Config{
		ListenAddr:              "127.0.0.1:0",
		AESKeyHex:               exitTimingTestKeyHex,
		DownstreamReplayEnabled: true,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	owner := [frame.ClientIDLen]byte{0x74}
	sid := [frame.SessionIDLen]byte{0x75}
	sess := session.New(sid, "download.example:443", false)
	defer sess.Stop()
	if err := sess.EnqueueTx([]byte("fresh-after-lost-response")); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	s.mu.Lock()
	s.sessions[sid] = sess
	s.sessionOwners[sid] = owner
	s.lastActivity[sid] = time.Now()
	s.markTxReadyLocked(owner, sid)
	s.mu.Unlock()
	s.replay.track(owner, []*frame.Frame{{
		SessionID: sid,
		Seq:       0,
		Payload:   []byte("pending-replay"),
	}}, time.Now())

	frames, _ := s.drainAllForStream(owner, protocol.MaxFramePayload)
	if len(frames) != 1 || string(frames[0].Payload) != "fresh-after-lost-response" {
		t.Fatalf("stream drained frames = %#v, want fresh frame despite pending POST replay", frames)
	}
}

func TestExit_StreamConnectWithPendingReplayIsPromotedAndFlushed(t *testing.T) {
	s, err := New(Config{
		ListenAddr:              "127.0.0.1:0",
		AESKeyHex:               exitTimingTestKeyHex,
		DownstreamReplayEnabled: true,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	c := mustExitTimingCrypto(t)
	owner := [frame.ClientIDLen]byte{0x76}
	sid := [frame.SessionIDLen]byte{0x77}
	sess := session.New(sid, "download.example:443", false)
	defer sess.Stop()
	if err := sess.EnqueueTx([]byte("pending-replay")); err != nil {
		t.Fatalf("enqueue pending replay source: %v", err)
	}
	replayFrames := sess.DrainTx(protocol.MaxFramePayload)
	if len(replayFrames) != 1 || replayFrames[0].Seq != 0 {
		t.Fatalf("replay source frames = %#v, want one seq 0 frame", replayFrames)
	}
	if err := sess.EnqueueTx([]byte("fresh-after-replay")); err != nil {
		t.Fatalf("enqueue fresh frame: %v", err)
	}
	s.mu.Lock()
	s.sessions[sid] = sess
	s.sessionOwners[sid] = owner
	s.lastActivity[sid] = time.Now()
	s.markTxReadyLocked(owner, sid)
	s.mu.Unlock()
	s.replay.track(owner, replayFrames, time.Now())

	mux := http.NewServeMux()
	mux.HandleFunc("/stream", s.handleStream)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(srv.URL, "http")+"/stream", nil)
	if err != nil {
		t.Fatalf("dial stream: %v", err)
	}
	defer conn.CloseNow()
	hello, err := frame.EncodeBatchBinary(c, owner, nil)
	if err != nil {
		t.Fatalf("encode hello: %v", err)
	}
	if err := conn.Write(ctx, websocket.MessageBinary, hello); err != nil {
		t.Fatalf("write hello: %v", err)
	}
	typ, body, err := conn.Read(ctx)
	if err != nil {
		t.Fatalf("stream read replay: %v", err)
	}
	if typ != websocket.MessageBinary {
		t.Fatalf("stream message type = %v, want binary", typ)
	}
	gotOwner, frames, err := frame.DecodeBatchBinary(c, body)
	if err != nil {
		t.Fatalf("decode stream replay: %v", err)
	}
	if gotOwner != owner {
		t.Fatalf("stream replay owner = %x, want %x", gotOwner[:4], owner[:4])
	}
	if len(frames) != 1 || frames[0].SessionID != sid || string(frames[0].Payload) != "pending-replay" {
		t.Fatalf("stream replay frames = %#v, want pending replay for session %x", frames, sid[:4])
	}
	typ, body, err = conn.Read(ctx)
	if err != nil {
		t.Fatalf("stream read fresh after replay: %v", err)
	}
	if typ != websocket.MessageBinary {
		t.Fatalf("fresh stream message type = %v, want binary", typ)
	}
	gotOwner, frames, err = frame.DecodeBatchBinary(c, body)
	if err != nil {
		t.Fatalf("decode stream fresh frame: %v", err)
	}
	if gotOwner != owner {
		t.Fatalf("stream fresh owner = %x, want %x", gotOwner[:4], owner[:4])
	}
	if len(frames) != 1 || frames[0].SessionID != sid || frames[0].Seq != 1 || string(frames[0].Payload) != "fresh-after-replay" {
		t.Fatalf("fresh stream frames = %#v, want seq 1 fresh frame for session %x", frames, sid[:4])
	}

	s.mu.Lock()
	_, alive := s.sessions[sid]
	gen := s.streamGen[owner]
	s.mu.Unlock()
	if !alive {
		t.Fatal("pending-replay session was aborted by stream promotion")
	}
	if gen == 0 {
		t.Fatal("stream was not registered after replay promotion")
	}
	if s.streamBlockedByReplay(owner) {
		t.Fatal("replay remained pending after successful stream promotion flush")
	}
}

func TestExit_StreamConnectNotBlockedByRSTControlFrame(t *testing.T) {
	s, err := New(Config{
		ListenAddr:              "127.0.0.1:0",
		AESKeyHex:               exitTimingTestKeyHex,
		DownstreamReplayEnabled: true,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	c := mustExitTimingCrypto(t)
	owner := [frame.ClientIDLen]byte{0x7e}
	sid := [frame.SessionIDLen]byte{0x7f}
	s.queueRST(owner, sid)
	frames, urgent := s.drainAll(owner, 4096)
	if !urgent || len(frames) != 1 || !frames[0].HasFlag(frame.FlagRST) {
		t.Fatalf("drained frames = %#v urgent=%v, want one urgent RST", frames, urgent)
	}
	if dropped := s.replay.track(owner, frames, time.Now()); len(dropped) != 0 {
		t.Fatalf("track dropped %d session(s), want none", len(dropped))
	}
	if s.streamBlockedByReplay(owner) {
		t.Fatal("terminal RST control frame blocked direct stream")
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/stream", s.handleStream)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(srv.URL, "http")+"/stream", nil)
	if err != nil {
		t.Fatalf("dial stream: %v", err)
	}
	defer conn.CloseNow()
	hello, err := frame.EncodeBatchBinary(c, owner, nil)
	if err != nil {
		t.Fatalf("encode hello: %v", err)
	}
	if err := conn.Write(ctx, websocket.MessageBinary, hello); err != nil {
		t.Fatalf("write hello: %v", err)
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		s.mu.Lock()
		registered := s.streamGen[owner] > 0
		s.mu.Unlock()
		if registered {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("stream did not register; RST replay/control state may have blocked it")
}

func TestExit_StreamBlockedByReplayExpiresStaleReplayBeforeReportingBlocked(t *testing.T) {
	s, err := New(Config{
		ListenAddr:              "127.0.0.1:0",
		AESKeyHex:               exitTimingTestKeyHex,
		DownstreamReplayEnabled: true,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	s.replay.maxAge = time.Millisecond

	owner := [frame.ClientIDLen]byte{0x79}
	sid := [frame.SessionIDLen]byte{0x7a}
	sess := session.New(sid, "expired.example:443", false)
	defer sess.Stop()
	s.mu.Lock()
	s.sessions[sid] = sess
	s.sessionOwners[sid] = owner
	s.lastActivity[sid] = time.Now().Add(-time.Hour)
	s.sessionCount.Store(1)
	s.mu.Unlock()
	s.replay.track(owner, []*frame.Frame{{
		SessionID: sid,
		Seq:       0,
		Payload:   []byte("expired-replay"),
	}}, time.Now().Add(-time.Hour))

	if s.streamBlockedByReplay(owner) {
		t.Fatal("stream remained blocked by expired replay")
	}
	s.mu.Lock()
	_, alive := s.sessions[sid]
	count := s.sessionCount.Load()
	s.mu.Unlock()
	if alive {
		t.Fatal("expired replay session was not aborted")
	}
	if count != 0 {
		t.Fatalf("sessionCount = %d, want 0 after expired replay abort", count)
	}
	if got := s.stats.replayDropped.Load(); got != 1 {
		t.Fatalf("replayDropped = %d, want 1", got)
	}
	if got := s.stats.replayDroppedExpired.Load(); got != 1 {
		t.Fatalf("replayDroppedExpired = %d, want 1", got)
	}
	if got := s.stats.replayDroppedCap.Load(); got != 0 {
		t.Fatalf("replayDroppedCap = %d, want 0", got)
	}
}

func TestExit_StreamFlushesReplayThatBecomesPendingAfterConnect(t *testing.T) {
	s, err := New(Config{
		ListenAddr:              "127.0.0.1:0",
		AESKeyHex:               exitTimingTestKeyHex,
		DownstreamReplayEnabled: true,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	c := mustExitTimingCrypto(t)
	owner := [frame.ClientIDLen]byte{0x78}
	sid := [frame.SessionIDLen]byte{0x79}

	mux := http.NewServeMux()
	mux.HandleFunc("/stream", s.handleStream)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(srv.URL, "http")+"/stream", nil)
	if err != nil {
		t.Fatalf("dial stream: %v", err)
	}
	defer conn.CloseNow()
	hello, err := frame.EncodeBatchBinary(c, owner, nil)
	if err != nil {
		t.Fatalf("encode hello: %v", err)
	}
	if err := conn.Write(ctx, websocket.MessageBinary, hello); err != nil {
		t.Fatalf("write hello: %v", err)
	}
	deadline := time.Now().Add(time.Second)
	registered := false
	for time.Now().Before(deadline) {
		s.mu.Lock()
		registered = s.streamGen[owner] > 0
		s.mu.Unlock()
		if registered {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if !registered {
		t.Fatal("stream did not register before timeout")
	}

	sess := session.New(sid, "download.example:443", false)
	defer sess.Stop()
	s.mu.Lock()
	s.sessions[sid] = sess
	s.sessionOwners[sid] = owner
	s.lastActivity[sid] = time.Now()
	s.mu.Unlock()
	s.replay.track(owner, []*frame.Frame{{
		SessionID: sid,
		Seq:       0,
		Payload:   []byte("pending-replay"),
	}}, time.Now())
	s.kick(owner)

	typ, body, err := conn.Read(ctx)
	if err != nil {
		t.Fatalf("stream read pending replay: %v", err)
	}
	if typ != websocket.MessageBinary {
		t.Fatalf("stream message type = %v, want binary", typ)
	}
	gotOwner, frames, err := frame.DecodeBatchBinary(c, body)
	if err != nil {
		t.Fatalf("decode stream replay: %v", err)
	}
	if gotOwner != owner {
		t.Fatalf("stream replay owner = %x, want %x", gotOwner[:4], owner[:4])
	}
	if len(frames) != 1 || frames[0].SessionID != sid || string(frames[0].Payload) != "pending-replay" {
		t.Fatalf("stream replay frames = %#v, want pending replay for session %x", frames, sid[:4])
	}
	s.mu.Lock()
	_, alive := s.sessions[sid]
	s.mu.Unlock()
	if !alive {
		t.Fatal("pending-replay session was aborted after stream replay flush")
	}
	deadline = time.Now().Add(time.Second)
	for time.Now().Before(deadline) && s.streamBlockedByReplay(owner) {
		time.Sleep(time.Millisecond)
	}
	if s.streamBlockedByReplay(owner) {
		t.Fatal("replay remained pending after stream flushed replay created during the connection")
	}
}

func TestExit_StreamDoesNotPruneReplayWhenSupersededDuringWrite(t *testing.T) {
	s, err := New(Config{
		ListenAddr:              "127.0.0.1:0",
		AESKeyHex:               exitTimingTestKeyHex,
		DownstreamReplayEnabled: true,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	owner := [frame.ClientIDLen]byte{0x80}
	sid := [frame.SessionIDLen]byte{0x81}
	sess := session.New(sid, "download.example:443", false)
	defer sess.Stop()
	s.mu.Lock()
	s.sessions[sid] = sess
	s.sessionOwners[sid] = owner
	s.lastActivity[sid] = time.Now()
	s.mu.Unlock()
	s.replay.track(owner, []*frame.Frame{{
		SessionID: sid,
		Seq:       0,
		Payload:   []byte("pending-replay"),
	}}, time.Now())

	oldGen := s.registerStream(owner)
	writer := exitStreamWriterFunc(func(context.Context, websocket.MessageType, []byte) error {
		_ = s.registerStream(owner)
		return nil
	})

	if err := s.writeStream(context.Background(), writer, owner, oldGen); err != nil {
		t.Fatalf("writeStream: %v", err)
	}
	if !s.streamBlockedByReplay(owner) {
		t.Fatal("stale stream pruned replay after a newer stream became current")
	}
}

func TestExit_RegisterStreamWakesSupersededIdleWriter(t *testing.T) {
	s := mustExitTimingServer(t)
	owner := [frame.ClientIDLen]byte{0x82}
	oldGen := s.registerStream(owner)
	writer := exitStreamWriterFunc(func(context.Context, websocket.MessageType, []byte) error {
		t.Fatal("idle superseded stream unexpectedly wrote a frame")
		return nil
	})

	done := make(chan error, 1)
	go func() {
		done <- s.writeStream(context.Background(), writer, owner, oldGen)
	}()

	// Give writeStream time to enter its idle wait on the owner wake channel.
	time.Sleep(20 * time.Millisecond)
	_ = s.registerStream(owner)

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("writeStream: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("superseded idle stream writer did not wake and exit")
	}
}

func TestExit_UnregisteredStreamIsNotCurrent(t *testing.T) {
	s := mustExitTimingServer(t)
	owner := [frame.ClientIDLen]byte{0x8d}
	gen := s.registerStream(owner)
	if !s.isCurrentStream(owner, gen) {
		t.Fatal("registered stream was not current")
	}
	s.unregisterStream(owner, gen)
	if s.isCurrentStream(owner, gen) {
		t.Fatal("unregistered stream still reported current")
	}
	if !s.shouldAbortDisconnectedStream(owner, gen, time.Now()) {
		t.Fatal("disconnected stream cleanup no longer recognizes latest generation")
	}
}

func TestExit_StreamFreshWriteSupersededRollsBackFrames(t *testing.T) {
	s := mustExitTimingServer(t)
	owner := [frame.ClientIDLen]byte{0x8e}
	sid := [frame.SessionIDLen]byte{0x8f}
	sess := session.New(sid, "download.example:443", false)
	defer sess.Stop()
	sess.EnqueueTx([]byte("fresh-stream"))
	s.mu.Lock()
	s.sessions[sid] = sess
	s.sessionOwners[sid] = owner
	s.lastActivity[sid] = time.Now()
	s.firstReply[sid] = struct{}{}
	s.responseStage[sid] = 0
	s.markTxReadyLocked(owner, sid)
	s.mu.Unlock()

	oldGen := s.registerStream(owner)
	writer := exitStreamWriterFunc(func(context.Context, websocket.MessageType, []byte) error {
		_ = s.registerStream(owner)
		return nil
	})

	if err := s.writeStream(context.Background(), writer, owner, oldGen); err != nil {
		t.Fatalf("writeStream: %v", err)
	}
	s.mu.Lock()
	_, firstReplyRestored := s.firstReply[sid]
	stage := s.responseStage[sid]
	s.mu.Unlock()
	if !firstReplyRestored {
		t.Fatal("stale stream rollback did not restore first-reply ramp state")
	}
	if stage != 0 {
		t.Fatalf("responseStage = %d after stale stream rollback, want 0", stage)
	}
	frames, _ := s.drainAllForStream(owner, protocol.MaxFramePayload)
	if len(frames) != 1 || frames[0].SessionID != sid || string(frames[0].Payload) != "fresh-stream" {
		t.Fatalf("frames after stale stream rollback = %#v, want fresh-stream for %x", frames, sid[:4])
	}
}

func TestExit_StreamFreshPartialDrainHeldUntilWriteCompletes(t *testing.T) {
	s := mustExitTimingServer(t)
	s.maxResponseBytesPreEncode = 5
	owner := [frame.ClientIDLen]byte{0x92}
	sid := [frame.SessionIDLen]byte{0x93}
	sess := session.New(sid, "download.example:443", false)
	defer sess.Stop()
	sess.EnqueueTx([]byte("abcdefghij"))
	s.mu.Lock()
	s.sessions[sid] = sess
	s.sessionOwners[sid] = owner
	s.lastActivity[sid] = time.Now()
	s.markTxReadyLocked(owner, sid)
	s.mu.Unlock()

	oldGen := s.registerStream(owner)
	writeStarted := make(chan struct{})
	releaseWrite := make(chan struct{})
	var once sync.Once
	writer := exitStreamWriterFunc(func(context.Context, websocket.MessageType, []byte) error {
		once.Do(func() { close(writeStarted) })
		<-releaseWrite
		return nil
	})
	done := make(chan error, 1)
	go func() {
		done <- s.writeStream(context.Background(), writer, owner, oldGen)
	}()

	select {
	case <-writeStarted:
	case <-time.After(time.Second):
		t.Fatal("stream writer did not start first write")
	}
	if frames, _ := s.drainAllForStream(owner, protocol.MaxFramePayload); len(frames) != 0 {
		t.Fatalf("new stream could drain tail while stale stream write was in flight: %#v", frames)
	}
	_ = s.registerStream(owner)
	close(releaseWrite)
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("writeStream: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("stale stream writer did not exit")
	}
	frames, _ := s.drainAllForStream(owner, protocol.MaxFramePayload)
	if len(frames) != 1 || frames[0].SessionID != sid || string(frames[0].Payload) != "abcdefghij" {
		t.Fatalf("frames after stale partial rollback = %#v, want full payload for %x", frames, sid[:4])
	}
}

func TestExit_StreamFreshDrainIgnoresOnTxWhileWriteInFlight(t *testing.T) {
	s := mustExitTimingServer(t)
	s.maxResponseBytesPreEncode = 5
	owner := [frame.ClientIDLen]byte{0x94}
	sid := [frame.SessionIDLen]byte{0x95}
	sess := session.New(sid, "download.example:443", false)
	defer sess.Stop()
	sess.EnqueueTx([]byte("abcde"))
	s.mu.Lock()
	s.sessions[sid] = sess
	s.sessionOwners[sid] = owner
	s.lastActivity[sid] = time.Now()
	s.markTxReadyLocked(owner, sid)
	s.mu.Unlock()

	oldGen := s.registerStream(owner)
	writeStarted := make(chan struct{})
	releaseWrite := make(chan struct{})
	var once sync.Once
	writer := exitStreamWriterFunc(func(context.Context, websocket.MessageType, []byte) error {
		once.Do(func() { close(writeStarted) })
		<-releaseWrite
		return nil
	})
	done := make(chan error, 1)
	go func() {
		done <- s.writeStream(context.Background(), writer, owner, oldGen)
	}()

	select {
	case <-writeStarted:
	case <-time.After(time.Second):
		t.Fatal("stream writer did not start first write")
	}
	if err := sess.EnqueueTx([]byte("fghij")); err != nil {
		t.Fatalf("enqueue while stream write in-flight: %v", err)
	}
	if frames, _ := s.drainAllForStream(owner, protocol.MaxFramePayload); len(frames) != 0 {
		t.Fatalf("new stream drained OnTx data while stale stream write was in-flight: %#v", frames)
	}
	_ = s.registerStream(owner)
	close(releaseWrite)
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("writeStream: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("stale stream writer did not exit")
	}
	frames, _ := s.drainAllForStream(owner, protocol.MaxFramePayload)
	if len(frames) != 1 || frames[0].SessionID != sid || string(frames[0].Payload) != "abcdefghij" {
		t.Fatalf("frames after in-flight OnTx rollback = %#v, want full payload for %x", frames, sid[:4])
	}
}

func TestExit_StreamInFlightClearedWhenSessionRemovedBeforeRollback(t *testing.T) {
	s := mustExitTimingServer(t)
	owner := [frame.ClientIDLen]byte{0x96}
	sid := [frame.SessionIDLen]byte{0x97}
	sess := session.New(sid, "download.example:443", false)
	defer sess.Stop()
	sess.EnqueueTx([]byte("removed-before-rollback"))
	s.mu.Lock()
	s.sessions[sid] = sess
	s.sessionOwners[sid] = owner
	s.lastActivity[sid] = time.Now()
	s.markTxReadyLocked(owner, sid)
	s.mu.Unlock()

	gen := s.registerStream(owner)
	writeStarted := make(chan struct{})
	releaseWrite := make(chan struct{})
	writer := exitStreamWriterFunc(func(context.Context, websocket.MessageType, []byte) error {
		close(writeStarted)
		<-releaseWrite
		return errors.New("write failed after removal")
	})
	done := make(chan error, 1)
	go func() {
		done <- s.writeStream(context.Background(), writer, owner, gen)
	}()

	select {
	case <-writeStarted:
	case <-time.After(time.Second):
		t.Fatal("stream writer did not start first write")
	}
	if !s.closeOwnedSession(owner, sid, "test close") {
		t.Fatal("test setup failed: closeOwnedSession returned false")
	}
	close(releaseWrite)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("stream writer did not exit")
	}
	s.mu.Lock()
	_, inFlight := s.streamInFlight[sid]
	s.mu.Unlock()
	if inFlight {
		t.Fatal("streamInFlight marker survived session removal and rollback")
	}

	replacement := session.New(sid, "replacement.example:443", false)
	defer replacement.Stop()
	replacement.EnqueueTx([]byte("replacement"))
	s.mu.Lock()
	s.sessions[sid] = replacement
	s.sessionOwners[sid] = owner
	s.lastActivity[sid] = time.Now()
	s.markTxReadyLocked(owner, sid)
	s.mu.Unlock()
	frames, _ := s.drainAllForStream(owner, protocol.MaxFramePayload)
	if len(frames) != 1 || frames[0].SessionID != sid || string(frames[0].Payload) != "replacement" {
		t.Fatalf("replacement frames = %#v, want replacement for %x", frames, sid[:4])
	}
}

func TestExit_GCDoneSessionsKeepsStreamInFlightSession(t *testing.T) {
	s := mustExitTimingServer(t)
	owner := [frame.ClientIDLen]byte{0x9a}
	sid := [frame.SessionIDLen]byte{0x9b}
	sess := session.New(sid, "stream-finish.example:443", false)
	defer sess.Stop()
	sess.ProcessRx(&frame.Frame{SessionID: sid, Seq: 0, Flags: frame.FlagFIN})
	select {
	case _, ok := <-sess.RxChan:
		if ok {
			t.Fatal("test setup received payload from FIN-only frame")
		}
	case <-time.After(time.Second):
		t.Fatal("test setup timed out waiting for receive side to close")
	}
	if err := sess.EnqueueTx([]byte("tail")); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	sess.RequestClose()

	s.mu.Lock()
	s.sessions[sid] = sess
	s.sessionOwners[sid] = owner
	s.lastActivity[sid] = time.Now()
	s.markTxReadyLocked(owner, sid)
	s.sessionCount.Store(1)
	s.mu.Unlock()

	frames, _, rollback := s.drainAllForStreamTxn(owner, protocol.MaxFramePayload)
	if len(frames) != 2 || !frames[1].HasFlag(frame.FlagFIN) {
		t.Fatalf("stream drain frames = %#v, want payload plus FIN", frames)
	}
	if !sess.IsDone() {
		t.Fatal("test setup expected session done after draining FIN")
	}

	s.gcDoneSessions()

	s.mu.Lock()
	_, alive := s.sessions[sid]
	inFlight := s.streamInFlight[sid] == sess
	s.mu.Unlock()
	if !alive || !inFlight {
		t.Fatalf("gc removed stream in-flight session: alive=%v inFlight=%v", alive, inFlight)
	}

	s.rollbackStreamDrainWithControl(rollback, nil, nil)
}

func TestExit_OldStreamRollbackDoesNotTouchReusedSessionID(t *testing.T) {
	s := mustExitTimingServer(t)
	owner := [frame.ClientIDLen]byte{0x98}
	sid := [frame.SessionIDLen]byte{0x99}
	oldSession := session.New(sid, "old.example:443", false)
	defer oldSession.Stop()
	oldSession.EnqueueTx([]byte("old-session"))
	s.mu.Lock()
	s.sessions[sid] = oldSession
	s.sessionOwners[sid] = owner
	s.lastActivity[sid] = time.Now()
	s.markTxReadyLocked(owner, sid)
	s.mu.Unlock()

	oldGen := s.registerStream(owner)
	writeStarted := make(chan struct{})
	releaseWrite := make(chan struct{})
	writer := exitStreamWriterFunc(func(context.Context, websocket.MessageType, []byte) error {
		close(writeStarted)
		<-releaseWrite
		return errors.New("old write failed")
	})
	done := make(chan error, 1)
	go func() {
		done <- s.writeStream(context.Background(), writer, owner, oldGen)
	}()

	select {
	case <-writeStarted:
	case <-time.After(time.Second):
		t.Fatal("old stream writer did not start first write")
	}
	if !s.closeOwnedSession(owner, sid, "test close old") {
		t.Fatal("test setup failed: closeOwnedSession returned false")
	}

	replacement := session.New(sid, "replacement.example:443", false)
	defer replacement.Stop()
	replacement.EnqueueTx([]byte("replacement"))
	s.mu.Lock()
	s.sessions[sid] = replacement
	s.sessionOwners[sid] = owner
	s.lastActivity[sid] = time.Now()
	s.firstReply[sid] = struct{}{}
	s.responseStage[sid] = 0
	s.markTxReadyLocked(owner, sid)
	s.mu.Unlock()

	frames, _, replacementRollback := s.drainAllForStreamTxn(owner, protocol.MaxFramePayload)
	if len(frames) != 1 || frames[0].SessionID != sid || string(frames[0].Payload) != "replacement" {
		t.Fatalf("replacement transactional frames = %#v, want replacement for %x", frames, sid[:4])
	}
	close(releaseWrite)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("old stream writer did not exit")
	}
	s.mu.Lock()
	inFlight := s.streamInFlight[sid]
	_, firstReplyRestored := s.firstReply[sid]
	stage := s.responseStage[sid]
	s.mu.Unlock()
	if inFlight != replacement {
		t.Fatalf("streamInFlight = %p, want replacement session %p", inFlight, replacement)
	}
	if firstReplyRestored {
		t.Fatal("old rollback restored firstReply onto replacement session")
	}
	if stage != 1 {
		t.Fatalf("responseStage = %d after old rollback, want replacement stage 1", stage)
	}
	s.commitStreamDrain(replacementRollback)
	s.mu.Lock()
	_, inFlightStillSet := s.streamInFlight[sid]
	s.mu.Unlock()
	if inFlightStillSet {
		t.Fatal("replacement streamInFlight remained after commit")
	}
}

func TestExit_StreamFreshWriteFailureRollsBackFrames(t *testing.T) {
	s := mustExitTimingServer(t)
	owner := [frame.ClientIDLen]byte{0x90}
	sid := [frame.SessionIDLen]byte{0x91}
	sess := session.New(sid, "download.example:443", false)
	defer sess.Stop()
	sess.EnqueueTx([]byte("retry-after-failure"))
	s.mu.Lock()
	s.sessions[sid] = sess
	s.sessionOwners[sid] = owner
	s.lastActivity[sid] = time.Now()
	s.markTxReadyLocked(owner, sid)
	s.mu.Unlock()

	gen := s.registerStream(owner)
	errWriteFailed := errors.New("stream write failed")
	writer := exitStreamWriterFunc(func(context.Context, websocket.MessageType, []byte) error {
		return errWriteFailed
	})

	if err := s.writeStream(context.Background(), writer, owner, gen); !errors.Is(err, errWriteFailed) {
		t.Fatalf("writeStream err = %v, want %v", err, errWriteFailed)
	}
	frames, _ := s.drainAllForStream(owner, protocol.MaxFramePayload)
	if len(frames) != 1 || frames[0].SessionID != sid || string(frames[0].Payload) != "retry-after-failure" {
		t.Fatalf("frames after failed stream rollback = %#v, want retry-after-failure for %x", frames, sid[:4])
	}
}

func TestExit_StreamReplayWriteFailureKeepsReplayPending(t *testing.T) {
	s, err := New(Config{
		ListenAddr:              "127.0.0.1:0",
		AESKeyHex:               exitTimingTestKeyHex,
		DownstreamReplayEnabled: true,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	owner := [frame.ClientIDLen]byte{0x82}
	sid := [frame.SessionIDLen]byte{0x83}
	sess := session.New(sid, "download.example:443", false)
	defer sess.Stop()
	s.mu.Lock()
	s.sessions[sid] = sess
	s.sessionOwners[sid] = owner
	s.lastActivity[sid] = time.Now()
	s.mu.Unlock()
	s.replay.track(owner, []*frame.Frame{{
		SessionID: sid,
		Seq:       0,
		Payload:   []byte("pending-replay"),
	}}, time.Now())

	gen := s.registerStream(owner)
	errWriteFailed := errors.New("stream write failed")
	writer := exitStreamWriterFunc(func(context.Context, websocket.MessageType, []byte) error {
		return errWriteFailed
	})

	if err := s.writeStream(context.Background(), writer, owner, gen); !errors.Is(err, errWriteFailed) {
		t.Fatalf("writeStream err = %v, want %v", err, errWriteFailed)
	}
	if !s.streamBlockedByReplay(owner) {
		t.Fatal("failed stream write pruned replay")
	}
}

type exitStreamWriterFunc func(context.Context, websocket.MessageType, []byte) error

func (f exitStreamWriterFunc) Write(ctx context.Context, typ websocket.MessageType, body []byte) error {
	return f(ctx, typ, body)
}

func TestExit_StreamWriteFailureRequeuesControlFrames(t *testing.T) {
	s, err := New(Config{
		ListenAddr:              "127.0.0.1:0",
		AESKeyHex:               exitTimingTestKeyHex,
		DownstreamReplayEnabled: true,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	owner := [frame.ClientIDLen]byte{0x84}
	sid := [frame.SessionIDLen]byte{0x85}
	s.queueRST(owner, sid)

	gen := s.registerStream(owner)
	errWriteFailed := errors.New("stream write failed")
	writer := exitStreamWriterFunc(func(context.Context, websocket.MessageType, []byte) error {
		return errWriteFailed
	})

	if err := s.writeStream(context.Background(), writer, owner, gen); !errors.Is(err, errWriteFailed) {
		t.Fatalf("writeStream err = %v, want %v", err, errWriteFailed)
	}
	frames, _ := s.drainPendingControl(owner)
	if len(frames) != 1 || frames[0].SessionID != sid || !frames[0].HasFlag(frame.FlagRST) {
		t.Fatalf("requeued control frames = %#v, want RST for %x", frames, sid[:4])
	}
}

func TestExit_GCDoneSessionsPreservesActivityForActiveStream(t *testing.T) {
	s := mustExitTimingServer(t)
	owner := [frame.ClientIDLen]byte{0x7d}

	ch := s.activityFor(owner)
	gen := s.registerStream(owner)
	s.gcDoneSessions()

	s.mu.Lock()
	gotCh, channelAlive := s.activity[owner]
	activeGen, streamActive := s.activeStreams[owner]
	s.mu.Unlock()
	if !channelAlive {
		t.Fatal("gcDoneSessions removed activity channel while stream was active")
	}
	if gotCh != ch {
		t.Fatal("gcDoneSessions replaced activity channel while stream was active")
	}
	if !streamActive || activeGen != gen {
		t.Fatalf("active stream generation = (%d, %v), want (%d, true)", activeGen, streamActive, gen)
	}

	s.unregisterStream(owner, gen)
	s.gcDoneSessions()
	s.mu.Lock()
	_, channelAlive = s.activity[owner]
	_, streamActive = s.activeStreams[owner]
	s.mu.Unlock()
	if channelAlive {
		t.Fatal("gcDoneSessions kept activity channel after stream disconnected and no sessions remained")
	}
	if streamActive {
		t.Fatal("active stream entry remained after unregisterStream")
	}
}

func TestExit_StreamRoundTripToUpstream(t *testing.T) {
	s := mustExitTimingServer(t)
	c := mustExitTimingCrypto(t)
	upstream, closeUpstream := startMarkerServer(t, []byte("stream-upstream"), 0)
	defer closeUpstream()

	mux := http.NewServeMux()
	mux.HandleFunc("/stream", s.handleStream)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(srv.URL, "http")+"/stream", nil)
	if err != nil {
		t.Fatalf("dial stream: %v", err)
	}
	defer conn.CloseNow()

	clientID := [frame.ClientIDLen]byte{0x56}
	sessionID := [frame.SessionIDLen]byte{0x78}
	body, err := frame.EncodeBatchBinary(c, clientID, []*frame.Frame{{
		SessionID: sessionID,
		Flags:     frame.FlagSYN,
		Target:    upstream,
	}})
	if err != nil {
		t.Fatalf("encode syn: %v", err)
	}
	if err := conn.Write(ctx, websocket.MessageBinary, body); err != nil {
		t.Fatalf("write syn: %v", err)
	}

	typ, respBody, err := conn.Read(ctx)
	if err != nil {
		t.Fatalf("read stream response: %v", err)
	}
	if typ != websocket.MessageBinary {
		t.Fatalf("message type = %v, want binary", typ)
	}
	gotClient, frames, err := frame.DecodeBatchBinary(c, respBody)
	if err != nil {
		t.Fatalf("decode stream response: %v", err)
	}
	if gotClient != clientID {
		t.Fatalf("clientID = %x, want %x", gotClient, clientID)
	}
	if len(frames) == 0 {
		t.Fatal("stream response contained no frames")
	}
	if frames[0].SessionID != sessionID || string(frames[0].Payload) != "stream-upstream" {
		t.Fatalf("frame = session %x payload %q, want session %x payload stream-upstream",
			frames[0].SessionID[:4], frames[0].Payload, sessionID[:4])
	}
}

func TestExit_GCDoneSessionsExpiresReplayForDoneSessionWithoutOwnerActivity(t *testing.T) {
	s, err := New(Config{
		ListenAddr:              "127.0.0.1:0",
		AESKeyHex:               exitTimingTestKeyHex,
		DownstreamReplayEnabled: true,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	s.replay.maxAge = time.Millisecond
	owner := [frame.ClientIDLen]byte{0x8b}
	sid := [frame.SessionIDLen]byte{0x8c}
	sess := session.New(sid, "done.example:443", false)
	sess.RequestClose()
	_ = sess.DrainTx(protocol.MaxFramePayload)
	closeRxAndWaitDone(t, sess)
	s.mu.Lock()
	s.sessions[sid] = sess
	s.sessionOwners[sid] = owner
	s.lastActivity[sid] = time.Now().Add(-time.Hour)
	s.sessionCount.Store(1)
	s.mu.Unlock()
	s.replay.track(owner, []*frame.Frame{{
		SessionID: sid,
		Seq:       0,
		Payload:   []byte("old-final-frame"),
	}}, time.Now().Add(-time.Hour))

	s.gcDoneSessions()

	s.mu.Lock()
	_, alive := s.sessions[sid]
	count := s.sessionCount.Load()
	s.mu.Unlock()
	if alive {
		t.Fatal("done session with expired replay survived GC")
	}
	if count != 0 {
		t.Fatalf("sessionCount = %d, want 0 after replay expiry GC", count)
	}
	if s.streamBlockedByReplay(owner) {
		t.Fatal("expired replay remained pending after GC")
	}
}

func TestExit_StreamDisconnectKeepsSessionsDuringReconnectGrace(t *testing.T) {
	s := mustExitTimingServer(t)
	c := mustExitTimingCrypto(t)
	upstream, closeUpstream := startMarkerServer(t, []byte("stream-upstream"), 0)
	defer closeUpstream()

	mux := http.NewServeMux()
	mux.HandleFunc("/stream", s.handleStream)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(srv.URL, "http")+"/stream", nil)
	if err != nil {
		t.Fatalf("dial stream: %v", err)
	}

	clientID := [frame.ClientIDLen]byte{0x57}
	sessionID := [frame.SessionIDLen]byte{0x79}
	body, err := frame.EncodeBatchBinary(c, clientID, []*frame.Frame{{
		SessionID: sessionID,
		Flags:     frame.FlagSYN,
		Target:    upstream,
	}})
	if err != nil {
		t.Fatalf("encode syn: %v", err)
	}
	if err := conn.Write(ctx, websocket.MessageBinary, body); err != nil {
		t.Fatalf("write syn: %v", err)
	}
	if _, _, err := conn.Read(ctx); err != nil {
		t.Fatalf("read stream response: %v", err)
	}
	if err := conn.Close(websocket.StatusNormalClosure, "test done"); err != nil {
		t.Fatalf("close stream: %v", err)
	}

	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		s.mu.Lock()
		_, alive := s.sessions[sessionID]
		s.mu.Unlock()
		if !alive {
			t.Fatal("stream-owned session was aborted before reconnect grace elapsed")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestExit_StreamDisconnectCleanupAbortsWithoutPostFallback(t *testing.T) {
	s := mustExitTimingServer(t)
	owner := [frame.ClientIDLen]byte{0x58}
	sessionID := [frame.SessionIDLen]byte{0x7a}
	sess := session.New(sessionID, "example.com:443", false)
	defer sess.Stop()

	s.mu.Lock()
	s.sessions[sessionID] = sess
	s.sessionOwners[sessionID] = owner
	s.lastActivity[sessionID] = time.Now()
	s.mu.Unlock()

	gen := s.registerStream(owner)
	closedAt := time.Now()
	if got := s.cleanupDisconnectedStream(owner, gen, closedAt); got != 1 {
		t.Fatalf("cleanup disconnected stream = %d, want 1 aborted session", got)
	}
	s.mu.Lock()
	_, alive := s.sessions[sessionID]
	s.mu.Unlock()
	if alive {
		t.Fatal("session survived disconnected stream with no POST fallback")
	}
}

func TestExit_StreamDisconnectCleanupSkipsWhenPostFallbackArrived(t *testing.T) {
	s := mustExitTimingServer(t)
	owner := [frame.ClientIDLen]byte{0x59}
	sessionID := [frame.SessionIDLen]byte{0x7b}
	sess := session.New(sessionID, "example.com:443", false)
	defer sess.Stop()

	s.mu.Lock()
	s.sessions[sessionID] = sess
	s.sessionOwners[sessionID] = owner
	s.lastActivity[sessionID] = time.Now()
	s.mu.Unlock()

	gen := s.registerStream(owner)
	closedAt := time.Now()
	s.markPostActivity(owner, closedAt.Add(time.Millisecond))
	if got := s.cleanupDisconnectedStream(owner, gen, closedAt); got != 0 {
		t.Fatalf("cleanup disconnected stream = %d, want 0 with POST fallback", got)
	}
	s.mu.Lock()
	_, alive := s.sessions[sessionID]
	s.mu.Unlock()
	if !alive {
		t.Fatal("session was aborted even though POST fallback arrived after stream close")
	}
}

func TestExit_StreamDisconnectCleanupIgnoresPreClosePostAndNewerStream(t *testing.T) {
	s := mustExitTimingServer(t)
	owner := [frame.ClientIDLen]byte{0x5a}
	sessionID := [frame.SessionIDLen]byte{0x7c}
	sess := session.New(sessionID, "example.com:443", false)
	defer sess.Stop()

	s.mu.Lock()
	s.sessions[sessionID] = sess
	s.sessionOwners[sessionID] = owner
	s.lastActivity[sessionID] = time.Now()
	s.mu.Unlock()

	oldGen := s.registerStream(owner)
	closedAt := time.Now()
	s.markPostActivity(owner, closedAt.Add(-time.Millisecond))
	if got := s.cleanupDisconnectedStream(owner, oldGen, closedAt); got != 1 {
		t.Fatalf("cleanup with only pre-close POST = %d, want 1 aborted session", got)
	}

	// Re-create the session and prove a newer stream suppresses cleanup from
	// an older stream goroutine.
	sess = session.New(sessionID, "example.com:443", false)
	defer sess.Stop()
	s.mu.Lock()
	s.sessions[sessionID] = sess
	s.sessionOwners[sessionID] = owner
	s.lastActivity[sessionID] = time.Now()
	s.mu.Unlock()

	oldGen = s.registerStream(owner)
	_ = s.registerStream(owner)
	if got := s.cleanupDisconnectedStream(owner, oldGen, time.Now()); got != 0 {
		t.Fatalf("cleanup for stale stream generation = %d, want 0", got)
	}
	s.mu.Lock()
	_, alive := s.sessions[sessionID]
	s.mu.Unlock()
	if !alive {
		t.Fatal("newer stream did not suppress old stream cleanup")
	}
}

func invokeExitTunnel(tb testing.TB, s *Server, c *frame.Crypto, frames []*frame.Frame) time.Duration {
	tb.Helper()
	var clientID [frame.ClientIDLen]byte
	clientID[0] = 0x01 // distinguish from the all-zero "default" id
	body, err := frame.EncodeBatch(c, clientID, frames)
	if err != nil {
		tb.Fatalf("encode request: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/tunnel", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	t0 := time.Now()
	s.handleTunnel(rec, req)
	resp := rec.Result()
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return time.Since(t0)
}

func startSilentServer(tb testing.TB) (string, func()) {
	tb.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		tb.Fatalf("listen: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(io.Discard, c)
			}(conn)
		}
	}()
	return ln.Addr().String(), func() {
		_ = ln.Close()
		<-done
	}
}

func TestExitDrainWindow_EmptyPollUsesLongWindow(t *testing.T) {
	s := mustExitTimingServer(t)
	c := mustExitTimingCrypto(t)
	elapsed := invokeExitTunnel(t, s, c, nil)
	if elapsed < LongPollWindow-500*time.Millisecond {
		t.Fatalf("empty poll returned too quickly: %v", elapsed)
	}
}

func TestExitDrainWindow_ActiveBatchUsesShortWindow(t *testing.T) {
	s := mustExitTimingServer(t)
	c := mustExitTimingCrypto(t)
	target, closeFn := startSilentServer(t)
	defer closeFn()
	elapsed := invokeExitTunnel(t, s, c, []*frame.Frame{{
		SessionID: [frame.SessionIDLen]byte{1},
		Seq:       0,
		Flags:     frame.FlagSYN,
		Target:    target,
		Payload:   []byte("PING"),
	}})
	if elapsed > ActiveDrainWindow+350*time.Millisecond {
		t.Fatalf("active batch waited too long: %v", elapsed)
	}
}

func BenchmarkExitActiveSilent(b *testing.B) {
	s := mustExitTimingServer(b)
	c := mustExitTimingCrypto(b)
	target, closeFn := startSilentServer(b)
	defer closeFn()
	frames := []*frame.Frame{{
		SessionID: [frame.SessionIDLen]byte{2},
		Seq:       0,
		Flags:     frame.FlagSYN,
		Target:    target,
		Payload:   []byte("GET / HTTP/1.0\r\n\r\n"),
	}}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = invokeExitTunnel(b, s, c, frames)
	}
}

// startMarkerServer accepts TCP connections, waits writeDelay after each
// accept, then writes the marker and holds the connection open until closeFn
// is invoked. The delay lets two concurrent SYNs both register their sessions
// on the exit server before either upstream pump pushes downstream bytes,
// so the multi-client isolation test reliably exercises the racy drain path.
func startMarkerServer(tb testing.TB, marker []byte, writeDelay time.Duration) (string, func()) {
	tb.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		tb.Fatalf("listen: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				if writeDelay > 0 {
					time.Sleep(writeDelay)
				}
				_, _ = c.Write(marker)
				_, _ = io.Copy(io.Discard, c)
			}(conn)
		}
	}()
	return ln.Addr().String(), func() {
		_ = ln.Close()
		<-done
	}
}

// invokeAsClient runs one /tunnel POST as the given clientID and returns the
// decoded downstream frames the server replied with.
func invokeAsClient(tb testing.TB, s *Server, c *frame.Crypto, clientID [frame.ClientIDLen]byte, frames []*frame.Frame) []*frame.Frame {
	tb.Helper()
	body, err := frame.EncodeBatch(c, clientID, frames)
	if err != nil {
		tb.Fatalf("encode: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/tunnel", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	s.handleTunnel(rec, req)
	resp := rec.Result()
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if len(respBody) == 0 {
		return nil
	}
	_, out, err := frame.DecodeBatch(c, respBody)
	if err != nil {
		tb.Fatalf("decode response: %v", err)
	}
	return out
}

// TestExit_MultiClient_SessionIsolation is the regression test for issue #23:
// when two clients share one server, neither should ever see the other's
// downstream frames. Before the fix, drainAll() returned every queued frame
// to whichever client polled first, so client A would receive client B's bytes
// (which it then dropped as "unknown session"), breaking every TLS stream.
//
// The two SYNs are issued concurrently so the upstream pump goroutines
// queue both markers into s.txReady at overlapping times — that overlap is
// what triggers the buggy path on an unfixed server.
func TestExit_MultiClient_SessionIsolation(t *testing.T) {
	s := mustExitTimingServer(t)
	c := mustExitTimingCrypto(t)

	markerA := []byte("MARKER-A-payload-for-client-alpha")
	markerB := []byte("MARKER-B-payload-for-client-bravo")
	// 30ms write delay lets both SYN handlers spawn their pump goroutines
	// before either upstream produces bytes, so both markers reliably land
	// in s.txReady before either drainAll runs.
	upstreamA, closeA := startMarkerServer(t, markerA, 30*time.Millisecond)
	defer closeA()
	upstreamB, closeB := startMarkerServer(t, markerB, 30*time.Millisecond)
	defer closeB()

	clientA := [frame.ClientIDLen]byte{0xAA}
	clientB := [frame.ClientIDLen]byte{0xBB}
	sidA := [frame.SessionIDLen]byte{0xA1}
	sidB := [frame.SessionIDLen]byte{0xB1}

	type result struct {
		label  string
		frames []*frame.Frame
	}
	results := make(chan result, 2)
	var ready sync.WaitGroup
	ready.Add(2)
	start := make(chan struct{})

	go func() {
		ready.Done()
		<-start
		results <- result{"clientA", invokeAsClient(t, s, c, clientA, []*frame.Frame{{
			SessionID: sidA, Flags: frame.FlagSYN, Target: upstreamA,
		}})}
	}()
	go func() {
		ready.Done()
		<-start
		results <- result{"clientB", invokeAsClient(t, s, c, clientB, []*frame.Frame{{
			SessionID: sidB, Flags: frame.FlagSYN, Target: upstreamB,
		}})}
	}()

	ready.Wait()
	close(start)

	got := map[string][]*frame.Frame{}
	for i := 0; i < 2; i++ {
		select {
		case r := <-results:
			got[r.label] = r.frames
		case <-time.After(5 * time.Second):
			t.Fatal("timeout waiting for concurrent /tunnel calls")
		}
	}

	assertOnlyOwnSession(t, "clientA", got["clientA"], sidA, sidB, markerA)
	assertOnlyOwnSession(t, "clientB", got["clientB"], sidB, sidA, markerB)
}

// assertOnlyOwnSession fails if `frames` references foreignSID, fails if it
// does not contain a payload matching wantPayload, and fails on any other
// session id appearing.
func assertOnlyOwnSession(t *testing.T, label string, frames []*frame.Frame, ownSID, foreignSID [frame.SessionIDLen]byte, wantPayload []byte) {
	t.Helper()
	var sawPayload bool
	for _, f := range frames {
		if f.SessionID == foreignSID {
			t.Fatalf("%s: leaked frame for foreign session %x", label, foreignSID[:4])
		}
		if f.SessionID != ownSID {
			t.Fatalf("%s: unexpected session %x in response", label, f.SessionID[:4])
		}
		if bytes.Equal(f.Payload, wantPayload) {
			sawPayload = true
		}
	}
	if !sawPayload {
		t.Fatalf("%s: never received expected payload %q", label, wantPayload)
	}
}

// TestExit_MultiClient_RejectsSessionSpoof verifies that when client B sends
// a non-SYN frame for a session ID owned by client A, the server replies to
// client B with an RST and leaves client A's session intact.
func TestExit_MultiClient_RejectsSessionSpoof(t *testing.T) {
	s := mustExitTimingServer(t)
	c := mustExitTimingCrypto(t)

	upstream, closeUp := startMarkerServer(t, []byte("alpha-data"), 0)
	defer closeUp()

	clientA := [frame.ClientIDLen]byte{0xAA}
	clientB := [frame.ClientIDLen]byte{0xBB}
	sidA := [frame.SessionIDLen]byte{0xA1}

	// Client A opens the session.
	_ = invokeAsClient(t, s, c, clientA, []*frame.Frame{{
		SessionID: sidA, Flags: frame.FlagSYN, Target: upstream,
	}})

	// Client B sends a data frame claiming the same session ID.
	gotB := invokeAsClient(t, s, c, clientB, []*frame.Frame{{
		SessionID: sidA, Seq: 0, Payload: []byte("spoof"),
	}})

	var sawRST bool
	for _, f := range gotB {
		if f.SessionID == sidA && f.HasFlag(frame.FlagRST) {
			sawRST = true
		}
	}
	if !sawRST {
		t.Fatal("expected spoof attempt to receive RST, got no RST in response")
	}

	// Client A's session must still be alive on the server.
	s.mu.Lock()
	_, alive := s.sessions[sidA]
	s.mu.Unlock()
	if !alive {
		t.Fatal("client A's session was torn down by client B's spoof — owner check failed")
	}
}

// TestExit_SYNDialsRunInParallel is the regression test for the
// head-of-line blocking issue observed in production logs (issue #23
// follow-up): when a batch of N SYNs arrives and the first SYN dials a
// dead target, every subsequent SYN in the batch used to wait the full
// dial timeout sequentially. handleTunnel now parallelizes SYN dials.
//
// Three SYNs each take ~600 ms to dial. Sequentially that is ~1.8 s;
// in parallel it is ~600 ms. We assert the batch completes under
// 1.2 s — comfortably below sequential, comfortably above any flake
// floor on slow CI.
func TestExit_SYNDialsRunInParallel(t *testing.T) {
	s := mustExitTimingServer(t)
	c := mustExitTimingCrypto(t)

	const dialDelay = 600 * time.Millisecond
	setExitTimingDial(s, func(_, addr string, _ time.Duration) (net.Conn, error) {
		time.Sleep(dialDelay)
		return nil, &net.OpError{Op: "dial", Net: "tcp", Err: errSimulatedDialFail{}}
	})

	clientID := [frame.ClientIDLen]byte{0xCC}
	frames := []*frame.Frame{
		{SessionID: [frame.SessionIDLen]byte{0xA1}, Flags: frame.FlagSYN, Target: "127.0.0.1:10001"},
		{SessionID: [frame.SessionIDLen]byte{0xB2}, Flags: frame.FlagSYN, Target: "127.0.0.1:10002"},
		{SessionID: [frame.SessionIDLen]byte{0xC3}, Flags: frame.FlagSYN, Target: "127.0.0.1:10003"},
	}

	muteLogsForBench(t)
	body, err := frame.EncodeBatch(c, clientID, frames)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/tunnel", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	t0 := time.Now()
	s.handleTunnel(rec, req)
	elapsed := time.Since(t0)

	// Sequential bound = 3 × dialDelay = 1.8 s. Parallel bound ≈ dialDelay = 600 ms.
	// Plus the ActiveDrainWindow (350 ms) that handleTunnel waits after dialing.
	if elapsed > dialDelay+ActiveDrainWindow+250*time.Millisecond {
		t.Fatalf("3 SYNs dispatched serially: elapsed=%v (expected ~%v in parallel)",
			elapsed, dialDelay+ActiveDrainWindow)
	}
}

func TestExit_RouteIncomingBatchRoutesExistingDataBeforeSlowSYN(t *testing.T) {
	s := mustExitTimingServer(t)
	owner := [frame.ClientIDLen]byte{0xce}
	existingID := [frame.SessionIDLen]byte{0xd1}
	slowID := [frame.SessionIDLen]byte{0xd2}
	sess := session.New(existingID, "existing.example:443", false)
	defer sess.Stop()

	s.mu.Lock()
	s.sessions[existingID] = sess
	s.sessionOwners[existingID] = owner
	s.lastActivity[existingID] = time.Now()
	s.sessionCount.Store(1)
	s.mu.Unlock()

	slowStarted := make(chan struct{})
	releaseDial := make(chan struct{})
	var once sync.Once
	setExitTimingDial(s, func(_, _ string, _ time.Duration) (net.Conn, error) {
		once.Do(func() { close(slowStarted) })
		<-releaseDial
		return nil, &net.OpError{Op: "dial", Net: "tcp", Err: errSimulatedDialFail{}}
	})

	done := make(chan struct{})
	go func() {
		s.routeIncomingBatchContext(context.Background(), []*frame.Frame{
			{SessionID: slowID, Flags: frame.FlagSYN, Target: "203.0.113.1:443"},
			{SessionID: existingID, Payload: []byte("fast")},
		}, owner)
		close(done)
	}()

	select {
	case <-slowStarted:
	case <-time.After(500 * time.Millisecond):
		close(releaseDial)
		t.Fatal("slow SYN dial did not start")
	}

	var (
		got      []byte
		timedOut bool
	)
	select {
	case got = <-sess.RxChan:
	case <-time.After(75 * time.Millisecond):
		timedOut = true
	}
	close(releaseDial)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("routeIncomingBatchContext did not finish after dial release")
	}
	if timedOut {
		t.Fatal("existing DATA waited behind unrelated slow SYN")
	}
	if string(got) != "fast" {
		t.Fatalf("existing session payload = %q, want fast", got)
	}
}

func TestExit_RouteIncomingBatchRoutesNewSessionDataBeforeUnrelatedSlowSYN(t *testing.T) {
	s := mustExitTimingServer(t)
	owner := [frame.ClientIDLen]byte{0xd0}
	slowID := [frame.SessionIDLen]byte{0xe1}
	fastID := [frame.SessionIDLen]byte{0xe2}
	const slowTarget = "203.0.113.1:443"
	const fastTarget = "127.0.0.1:9443"

	slowStarted := make(chan struct{})
	releaseSlow := make(chan struct{})
	fastDialed := make(chan struct{})
	var fastPeer net.Conn
	var slowOnce, fastOnce sync.Once
	setExitTimingDial(s, func(_, addr string, _ time.Duration) (net.Conn, error) {
		if addr == slowTarget {
			slowOnce.Do(func() { close(slowStarted) })
			<-releaseSlow
			return nil, &net.OpError{Op: "dial", Net: "tcp", Err: errSimulatedDialFail{}}
		}
		if addr == fastTarget {
			fastOnce.Do(func() { close(fastDialed) })
			a, b := net.Pipe()
			fastPeer = b
			t.Cleanup(func() {
				_ = a.Close()
				_ = b.Close()
			})
			return a, nil
		}
		t.Fatalf("unexpected dial target %q", addr)
		return nil, nil
	})

	done := make(chan struct{})
	go func() {
		s.routeIncomingBatchContext(context.Background(), []*frame.Frame{
			{SessionID: slowID, Flags: frame.FlagSYN, Target: slowTarget},
			{SessionID: fastID, Flags: frame.FlagSYN, Target: fastTarget},
			{SessionID: fastID, Seq: 1, Payload: []byte("fast-data")},
		}, owner)
		close(done)
	}()

	select {
	case <-slowStarted:
	case <-time.After(time.Second):
		close(releaseSlow)
		t.Fatal("slow SYN dial did not start")
	}
	select {
	case <-fastDialed:
	case <-time.After(time.Second):
		close(releaseSlow)
		t.Fatal("fast SYN dial did not start")
	}

	var sess *session.Session
	deadline := time.Now().Add(250 * time.Millisecond)
	for time.Now().Before(deadline) {
		s.mu.Lock()
		sess = s.sessions[fastID]
		s.mu.Unlock()
		if sess != nil {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if sess == nil {
		close(releaseSlow)
		t.Fatal("fast session was not registered")
	}

	if err := fastPeer.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		close(releaseSlow)
		t.Fatalf("SetReadDeadline: %v", err)
	}
	buf := make([]byte, len("fast-data"))
	if _, err := io.ReadFull(fastPeer, buf); err != nil {
		close(releaseSlow)
		t.Fatalf("new-session DATA waited behind unrelated slow SYN: %v", err)
	}
	if string(buf) != "fast-data" {
		close(releaseSlow)
		t.Fatalf("fast upstream payload = %q, want fast-data", buf)
	}

	close(releaseSlow)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("routeIncomingBatchContext did not finish after slow dial release")
	}
}

func TestExit_HandleTunnelDrainsReadyResponseBeforeUnrelatedSlowSYN(t *testing.T) {
	s := mustExitTimingServer(t)
	c := mustExitTimingCrypto(t)
	owner := [frame.ClientIDLen]byte{0xd3}
	readyID := [frame.SessionIDLen]byte{0xd4}
	slowID := [frame.SessionIDLen]byte{0xd5}

	ready := session.New(readyID, "ready.example:443", false)
	defer ready.Stop()
	if err := ready.EnqueueTx([]byte("ready")); err != nil {
		t.Fatalf("enqueue ready: %v", err)
	}
	s.mu.Lock()
	s.sessions[readyID] = ready
	s.sessionOwners[readyID] = owner
	s.lastActivity[readyID] = time.Now()
	s.sessionCount.Store(1)
	s.markTxReadyLocked(owner, readyID)
	s.mu.Unlock()

	slowStarted := make(chan struct{})
	releaseSlow := make(chan struct{})
	var once sync.Once
	setExitTimingDial(s, func(_, _ string, _ time.Duration) (net.Conn, error) {
		once.Do(func() { close(slowStarted) })
		<-releaseSlow
		return nil, &net.OpError{Op: "dial", Net: "tcp", Err: errSimulatedDialFail{}}
	})

	body, err := frame.EncodeBatch(c, owner, []*frame.Frame{{
		SessionID: slowID,
		Flags:     frame.FlagSYN,
		Target:    "203.0.113.1:443",
	}})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/tunnel", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		s.handleTunnel(rec, req)
		close(done)
	}()

	select {
	case <-slowStarted:
	case <-time.After(time.Second):
		close(releaseSlow)
		t.Fatal("slow SYN dial did not start")
	}
	select {
	case <-done:
	case <-time.After(200 * time.Millisecond):
		close(releaseSlow)
		t.Fatal("handleTunnel waited behind unrelated slow SYN before draining ready response")
	}
	close(releaseSlow)

	if rec.Code != http.StatusOK {
		t.Fatalf("HTTP status = %d, want 200", rec.Code)
	}
	_, frames, err := frame.DecodeBatch(c, rec.Body.Bytes())
	if err != nil {
		t.Fatalf("decode response: %v", err)
	}
	assertOnlyOwnSession(t, "ready response", frames, readyID, slowID, []byte("ready"))
}

func TestExit_HandleTunnelProcessesRSTBeforeAsyncSlowSYNDrain(t *testing.T) {
	s := mustExitTimingServer(t)
	s.activeDrainWindow = 20 * time.Millisecond
	c := mustExitTimingCrypto(t)
	owner := [frame.ClientIDLen]byte{0xd6}
	existingID := [frame.SessionIDLen]byte{0xd7}
	slowID := [frame.SessionIDLen]byte{0xd8}

	existing := session.New(existingID, "existing.example:443", false)
	defer existing.Stop()
	if err := existing.EnqueueTx([]byte("must-not-send")); err != nil {
		t.Fatalf("enqueue existing: %v", err)
	}
	s.mu.Lock()
	s.sessions[existingID] = existing
	s.sessionOwners[existingID] = owner
	s.lastActivity[existingID] = time.Now()
	s.sessionCount.Store(1)
	s.markTxReadyLocked(owner, existingID)
	s.mu.Unlock()

	slowStarted := make(chan struct{})
	releaseSlow := make(chan struct{})
	var once sync.Once
	setExitTimingDial(s, func(_, _ string, _ time.Duration) (net.Conn, error) {
		once.Do(func() { close(slowStarted) })
		<-releaseSlow
		return nil, &net.OpError{Op: "dial", Net: "tcp", Err: errSimulatedDialFail{}}
	})

	body, err := frame.EncodeBatch(c, owner, []*frame.Frame{
		{SessionID: slowID, Flags: frame.FlagSYN, Target: "203.0.113.1:443"},
		{SessionID: existingID, Flags: frame.FlagRST},
	})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/tunnel", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		s.handleTunnel(rec, req)
		close(done)
	}()

	select {
	case <-slowStarted:
	case <-time.After(time.Second):
		close(releaseSlow)
		t.Fatal("slow SYN dial did not start")
	}
	select {
	case <-done:
	case <-time.After(300 * time.Millisecond):
		close(releaseSlow)
		t.Fatal("handleTunnel waited behind unrelated slow SYN after RST")
	}
	close(releaseSlow)

	_, frames, err := frame.DecodeBatch(c, rec.Body.Bytes())
	if err != nil {
		t.Fatalf("decode response: %v", err)
	}
	for _, f := range frames {
		if f.SessionID == existingID {
			t.Fatalf("response included reset session frame: flags=%d payload=%q", f.Flags, f.Payload)
		}
	}
	s.mu.Lock()
	_, alive := s.sessions[existingID]
	s.mu.Unlock()
	if alive {
		t.Fatal("RST session still registered")
	}
}

func TestExit_RouteIncomingBatchBoundsConcurrentSYNDials(t *testing.T) {
	s := mustExitTimingServer(t)
	owner := [frame.ClientIDLen]byte{0xcf}
	total := maxConcurrentSYNDials*2 + 3
	frames := make([]*frame.Frame, 0, total)
	for i := 0; i < total; i++ {
		var sid [frame.SessionIDLen]byte
		sid[0] = byte(i + 1)
		frames = append(frames, &frame.Frame{
			SessionID: sid,
			Flags:     frame.FlagSYN,
			Target:    "203.0.113.1:443",
		})
	}

	releaseDial := make(chan struct{})
	limitReached := make(chan struct{})
	var (
		mu        sync.Mutex
		active    int
		maxActive int
		once      sync.Once
	)
	setExitTimingDial(s, func(_, _ string, _ time.Duration) (net.Conn, error) {
		mu.Lock()
		active++
		if active > maxActive {
			maxActive = active
		}
		if active == maxConcurrentSYNDials {
			once.Do(func() { close(limitReached) })
		}
		mu.Unlock()
		<-releaseDial
		mu.Lock()
		active--
		mu.Unlock()
		return nil, &net.OpError{Op: "dial", Net: "tcp", Err: errSimulatedDialFail{}}
	})

	done := make(chan struct{})
	go func() {
		s.routeIncomingBatchContext(context.Background(), frames, owner)
		close(done)
	}()

	select {
	case <-limitReached:
	case <-time.After(time.Second):
		close(releaseDial)
		t.Fatalf("only reached %d active SYN dial(s), want %d", maxActive, maxConcurrentSYNDials)
	}
	time.Sleep(50 * time.Millisecond)
	mu.Lock()
	gotMax := maxActive
	mu.Unlock()
	close(releaseDial)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("routeIncomingBatchContext did not finish after dial release")
	}
	if gotMax > maxConcurrentSYNDials {
		t.Fatalf("max concurrent SYN dials = %d, want <= %d", gotMax, maxConcurrentSYNDials)
	}
}

func TestExit_RouteIncomingBatchAsyncCancelStopsPendingSYN(t *testing.T) {
	s := mustExitTimingServer(t)
	owner := [frame.ClientIDLen]byte{0xee}
	sessionID := [frame.SessionIDLen]byte{0xef}
	target := "203.0.113.1:443"
	started := make(chan struct{})
	releaseDial := make(chan struct{})
	var once sync.Once
	setExitTimingDial(s, func(_, _ string, _ time.Duration) (net.Conn, error) {
		once.Do(func() { close(started) })
		<-releaseDial
		return nil, &net.OpError{Op: "dial", Net: "tcp", Err: errSimulatedDialFail{}}
	})
	t.Cleanup(func() { close(releaseDial) })

	ctx, cancel := context.WithCancel(context.Background())
	done := s.routeIncomingBatchContextAsync(ctx, []*frame.Frame{{
		SessionID: sessionID,
		Flags:     frame.FlagSYN,
		Target:    target,
	}}, owner)

	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("async SYN dial did not start")
	}
	cancel()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("async route did not finish after context cancellation")
	}

	s.mu.Lock()
	_, stillOpening := s.opening[sessionID]
	_, stillSession := s.sessions[sessionID]
	s.mu.Unlock()
	if stillOpening || stillSession {
		t.Fatalf("canceled async SYN left state behind: opening=%v session=%v", stillOpening, stillSession)
	}
}

func TestExit_StreamSYNDialsRunInParallel(t *testing.T) {
	s := mustExitTimingServer(t)
	c := mustExitTimingCrypto(t)

	const dialDelay = 600 * time.Millisecond
	done := make(chan struct{})
	var (
		mu        sync.Mutex
		dialCount int
	)
	setExitTimingDial(s, func(_, addr string, _ time.Duration) (net.Conn, error) {
		time.Sleep(dialDelay)
		mu.Lock()
		dialCount++
		if dialCount == 3 {
			close(done)
		}
		mu.Unlock()
		return nil, &net.OpError{Op: "dial", Net: "tcp", Err: errSimulatedDialFail{}}
	})

	mux := http.NewServeMux()
	mux.HandleFunc("/stream", s.handleStream)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(srv.URL, "http")+"/stream", nil)
	if err != nil {
		t.Fatalf("dial stream: %v", err)
	}
	defer conn.CloseNow()

	clientID := [frame.ClientIDLen]byte{0xCD}
	frames := []*frame.Frame{
		{SessionID: [frame.SessionIDLen]byte{0xA1}, Flags: frame.FlagSYN, Target: "127.0.0.1:10101"},
		{SessionID: [frame.SessionIDLen]byte{0xB2}, Flags: frame.FlagSYN, Target: "127.0.0.1:10102"},
		{SessionID: [frame.SessionIDLen]byte{0xC3}, Flags: frame.FlagSYN, Target: "127.0.0.1:10103"},
	}
	body, err := frame.EncodeBatchBinary(c, clientID, frames)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	muteLogsForBench(t)
	t0 := time.Now()
	if err := conn.Write(ctx, websocket.MessageBinary, body); err != nil {
		t.Fatalf("write stream: %v", err)
	}
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatalf("timed out waiting for stream SYN dials: %v", ctx.Err())
	}
	elapsed := time.Since(t0)
	if elapsed > dialDelay+250*time.Millisecond {
		t.Fatalf("stream SYN dials dispatched serially: elapsed=%v (expected ~%v in parallel)",
			elapsed, dialDelay)
	}
}

type errSimulatedDialFail struct{}

func (errSimulatedDialFail) Error() string   { return "simulated dial fail" }
func (errSimulatedDialFail) Timeout() bool   { return false }
func (errSimulatedDialFail) Temporary() bool { return false }

func TestIsBackoffEligibleDialErr(t *testing.T) {
	if !isBackoffEligibleDialErr(&net.OpError{Err: syscall.ECONNREFUSED}) {
		t.Fatal("expected ECONNREFUSED to be backoff-eligible")
	}
	if !isBackoffEligibleDialErr(&net.DNSError{IsNotFound: true}) {
		t.Fatal("expected DNS not found to be backoff-eligible")
	}
	if isBackoffEligibleDialErr(errors.New("some other error")) {
		t.Fatal("unexpected generic error to be backoff-eligible")
	}
}

func TestDialSuppressionExpiry(t *testing.T) {
	s := mustExitTimingServer(t)
	target := "127.0.0.1:1"
	s.recordDialFailure(target, &net.OpError{Err: syscall.ECONNREFUSED})
	s.recordDialFailure(target, &net.OpError{Err: syscall.ECONNREFUSED})
	if !s.isDialSuppressed(target) {
		t.Fatal("expected target to be dial-suppressed after repeated helper-seeded failures")
	}

	s.mu.Lock()
	state := s.dialFail[target]
	state.until = time.Now().Add(-time.Millisecond)
	s.dialFail[target] = state
	s.mu.Unlock()
	if s.isDialSuppressed(target) {
		t.Fatal("expected expired suppression to clear")
	}

	s.mu.Lock()
	_, exists := s.dialFail[target]
	s.mu.Unlock()
	if !exists {
		t.Fatal("expected recent failure history to be retained after cooldown expiry")
	}

	s.mu.Lock()
	state = s.dialFail[target]
	state.until = time.Now().Add(-dialFailureHistoryRetain - time.Millisecond)
	s.dialFail[target] = state
	s.mu.Unlock()
	if s.isDialSuppressed(target) {
		t.Fatal("expected stale suppression to clear")
	}

	s.mu.Lock()
	_, exists = s.dialFail[target]
	s.mu.Unlock()
	if exists {
		t.Fatal("expected stale target entry to be deleted")
	}
}

func TestDialSuppressionBackoffGrowsAndClears(t *testing.T) {
	s := mustExitTimingServer(t)
	target := "127.0.0.1:10808"
	err := &net.OpError{Err: syscall.ECONNREFUSED}

	s.recordDialFailure(target, err)
	s.mu.Lock()
	first := s.dialFail[target]
	s.mu.Unlock()
	firstRemaining := time.Until(first.until)
	if first.failures != 1 {
		t.Fatalf("first failures = %d, want 1", first.failures)
	}
	if firstRemaining < dialFailureBackoffBase/2 || firstRemaining > dialFailureBackoffBase+time.Second {
		t.Fatalf("first backoff = %v, want about %v", firstRemaining, dialFailureBackoffBase)
	}
	if s.isDialSuppressed(target) {
		t.Fatal("first dial failure should not suppress until the target fails repeatedly")
	}

	s.recordDialFailure(target, err)
	s.mu.Lock()
	second := s.dialFail[target]
	s.mu.Unlock()
	secondRemaining := time.Until(second.until)
	if second.failures != 2 {
		t.Fatalf("second failures = %d, want 2", second.failures)
	}
	if secondRemaining < 3*time.Second || secondRemaining > 5*time.Second {
		t.Fatalf("second backoff = %v, want about 4s", secondRemaining)
	}
	if !s.isDialSuppressed(target) {
		t.Fatal("second dial failure should suppress the repeated-failing target")
	}

	for i := 0; i < 12; i++ {
		s.recordDialFailure(target, err)
	}
	s.mu.Lock()
	capped := s.dialFail[target]
	s.mu.Unlock()
	cappedRemaining := time.Until(capped.until)
	if cappedRemaining > dialFailureBackoffMax+time.Second {
		t.Fatalf("capped backoff = %v, want <= %v", cappedRemaining, dialFailureBackoffMax)
	}

	s.clearDialFailure(target)
	s.recordDialFailure(target, err)
	s.mu.Lock()
	reset := s.dialFail[target]
	s.mu.Unlock()
	if reset.failures != 1 {
		t.Fatalf("failures after clear = %d, want 1", reset.failures)
	}
}

func TestDialSuppressionBackoffGrowsAcrossExpiredCooldown(t *testing.T) {
	s := mustExitTimingServer(t)
	target := "127.0.0.1:10808"
	err := &net.OpError{Err: syscall.ECONNREFUSED}

	s.recordDialFailure(target, err)
	s.mu.Lock()
	state := s.dialFail[target]
	state.until = time.Now().Add(-time.Millisecond)
	s.dialFail[target] = state
	s.mu.Unlock()

	if s.isDialSuppressed(target) {
		t.Fatal("expired first cooldown should allow a retry")
	}

	s.recordDialFailure(target, err)
	s.mu.Lock()
	second := s.dialFail[target]
	s.mu.Unlock()
	if second.failures != 2 {
		t.Fatalf("failures after retry = %d, want 2", second.failures)
	}
	remaining := time.Until(second.until)
	if remaining < 3*time.Second || remaining > 5*time.Second {
		t.Fatalf("retry backoff = %v, want about 4s", remaining)
	}
	if !s.isDialSuppressed(target) {
		t.Fatal("repeated failure after cooldown should now suppress target")
	}
}

func TestDialFailureMapIsPrunedAndCapped(t *testing.T) {
	s := mustExitTimingServer(t)
	err := &net.OpError{Err: syscall.ECONNREFUSED}
	old := time.Now().Add(-dialFailureHistoryRetain - time.Minute)
	s.mu.Lock()
	s.dialFail["stale.example:443"] = dialFailureState{
		until:    old,
		updated:  old,
		failures: dialFailureSuppressAfter,
	}
	s.mu.Unlock()

	for i := 0; i < dialFailureMaxEntries+16; i++ {
		s.recordDialFailure(fmt.Sprintf("target-%d.example:443", i), err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.dialFail["stale.example:443"]; ok {
		t.Fatal("stale dial failure entry survived prune")
	}
	if got := len(s.dialFail); got > dialFailureMaxEntries {
		t.Fatalf("dialFail entries = %d, want <= %d", got, dialFailureMaxEntries)
	}
}

func TestPendingRSTsAreDeduplicatedAndCapped(t *testing.T) {
	s := mustExitTimingServer(t)
	owner := [frame.ClientIDLen]byte{0x46}
	sessionID := [frame.SessionIDLen]byte{0x47}

	s.queueRST(owner, sessionID)
	s.queueRST(owner, sessionID)

	s.mu.Lock()
	got := len(s.pendingRSTs[owner])
	s.mu.Unlock()
	if got != 1 {
		t.Fatalf("duplicate queued RST count = %d, want 1", got)
	}

	for i := 0; i < pendingControlMaxFramesPerOwner+16; i++ {
		id := benchSessionID(i + 13000)
		s.queueRST(owner, id)
	}
	s.mu.Lock()
	got = len(s.pendingRSTs[owner])
	s.mu.Unlock()
	if got > pendingControlMaxFramesPerOwner {
		t.Fatalf("pending RST count = %d, want <= %d", got, pendingControlMaxFramesPerOwner)
	}
}

func TestGCPrunesInactivePendingControl(t *testing.T) {
	s := mustExitTimingServer(t)
	owner := [frame.ClientIDLen]byte{0x48}
	sessionID := [frame.SessionIDLen]byte{0x49}

	s.mu.Lock()
	s.postActivity[owner] = time.Now().Add(-pendingControlInactiveTTL - time.Second)
	s.enqueuePendingRSTLocked(owner, sessionID)
	s.enqueuePendingControlLocked(owner, &frame.Frame{
		SessionID: [frame.SessionIDLen]byte{0x4a},
		Flags:     frame.FlagRST,
		Payload:   []byte("version"),
	})
	s.mu.Unlock()

	s.gcDoneSessions()

	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.pendingRSTs[owner]) != 0 || len(s.pendingCtrl[owner]) != 0 {
		t.Fatalf("inactive pending control survived GC: rsts=%d ctrl=%d", len(s.pendingRSTs[owner]), len(s.pendingCtrl[owner]))
	}
}

func TestDrainAll_RespectsBatchFrameCap(t *testing.T) {
	t.Run("normal_cap", func(t *testing.T) {
		s := mustExitTimingServer(t)
		total := busySessionThreshold - 1
		if total <= 0 {
			total = 1
		}
		for i := 0; i < total; i++ {
			id := benchSessionID(i + 100)
			sess := session.New(id, "x:1", false)
			sess.EnqueueTx([]byte("x"))
			s.sessions[id] = sess
			s.txReady[id] = struct{}{}
		}
		var owner [frame.ClientIDLen]byte
		owner[0] = 0x01
		// Tag the populated sessions with this owner so the filter passes.
		for id := range s.sessions {
			s.sessionOwners[id] = owner
		}
		frames, _ := s.drainAll(owner, maxResponseBytesPreEncode)
		expected := total
		if expected > maxDrainFramesPerBatch {
			expected = maxDrainFramesPerBatch
		}
		if len(frames) != expected {
			t.Fatalf("expected %d frames, got %d", expected, len(frames))
		}
	})

	t.Run("busy_cap", func(t *testing.T) {
		s := mustExitTimingServer(t)
		total := maxDrainFramesPerBatchBusy * 2
		if total < busySessionThreshold+1 {
			total = busySessionThreshold + 1
		}
		for i := 0; i < total; i++ {
			id := benchSessionID(i + 500)
			sess := session.New(id, "x:1", false)
			sess.EnqueueTx([]byte("x"))
			s.sessions[id] = sess
			s.txReady[id] = struct{}{}
		}
		var owner [frame.ClientIDLen]byte
		owner[0] = 0x01
		// Tag the populated sessions with this owner so the filter passes.
		for id := range s.sessions {
			s.sessionOwners[id] = owner
		}
		frames, _ := s.drainAll(owner, maxResponseBytesPreEncode)
		if len(frames) != maxDrainFramesPerBatchBusy {
			t.Fatalf("expected busy cap %d frames, got %d", maxDrainFramesPerBatchBusy, len(frames))
		}
	})
}

func TestDrainAll_RespectsBatchFrameCapForPendingControl(t *testing.T) {
	s := mustExitTimingServer(t)
	owner := [frame.ClientIDLen]byte{0x43}
	total := maxDrainFramesPerBatch + 2

	s.mu.Lock()
	for i := 0; i < total; i++ {
		id := benchSessionID(i + 12000)
		s.pendingRSTs[owner] = append(s.pendingRSTs[owner], &frame.Frame{
			SessionID: id,
			Flags:     frame.FlagRST,
		})
	}
	s.mu.Unlock()

	frames, urgent := s.drainAll(owner, maxResponseBytesPreEncode)
	if !urgent {
		t.Fatal("pending control drain was not marked urgent")
	}
	if len(frames) != maxDrainFramesPerBatch {
		t.Fatalf("first drain returned %d frame(s), want cap %d", len(frames), maxDrainFramesPerBatch)
	}
	s.mu.Lock()
	left := len(s.pendingRSTs[owner])
	s.mu.Unlock()
	if left != 2 {
		t.Fatalf("pending RST leftovers = %d, want 2", left)
	}
	frames, _ = s.drainAll(owner, maxResponseBytesPreEncode)
	if len(frames) != 2 {
		t.Fatalf("second drain returned %d frame(s), want remaining 2", len(frames))
	}
}

func TestExit_OpenSessionDirectDialObservesContextCancel(t *testing.T) {
	s := mustExitTimingServer(t)
	owner := [frame.ClientIDLen]byte{0x44}
	sessionID := [frame.SessionIDLen]byte{0x45}
	started := make(chan struct{})
	releaseDial := make(chan struct{})
	s.dialContext = func(ctx context.Context, _ string, _ string, _ time.Duration) (net.Conn, error) {
		close(started)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-releaseDial:
			return nil, &net.OpError{Op: "dial", Net: "tcp", Err: errSimulatedDialFail{}}
		}
	}
	t.Cleanup(func() { close(releaseDial) })

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := s.openSessionContext(ctx, sessionID, "127.0.0.1:443", owner)
		done <- err
	}()

	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("direct dial did not start")
	}
	cancel()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("openSessionContext err = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("openSessionContext did not return after context cancellation")
	}
	s.mu.Lock()
	_, stillOpening := s.opening[sessionID]
	s.mu.Unlock()
	if stillOpening {
		t.Fatal("canceled direct dial left opening state behind")
	}
}

// TestDrainAll_RespectsByteBudget is the regression test for issue #22
// (relay response too large; download-mode silent drops). Without a
// byte-level budget, busy mode could pack 144 × 256KB = 36MB raw → ~48MB
// base64, exceeding the carrier client's 32MB cap. The fix caps total
// payload bytes per response at maxResponseBytesPreEncode.
//
// We populate enough sessions, each with a full max-payload buffer, that
// the frame count cap (144) would naturally produce ~36MB. The byte
// budget must hold the response under maxResponseBytesPreEncode + the
// last drained session's per-session overshoot (worst case: one final
// max-sized frame past the budget = ~256KB slack).
func TestDrainAll_RespectsByteBudget(t *testing.T) {
	s := mustExitTimingServer(t)
	// Enough sessions to cross busySessionThreshold AND to provide more
	// total bytes than the budget. Each session contributes one full
	// MaxFramePayload-sized frame on drain.
	totalSessions := busySessionThreshold + maxDrainFramesPerBatchBusy
	chunk := bytes.Repeat([]byte("x"), MaxFramePayload)

	var owner [frame.ClientIDLen]byte
	owner[0] = 0x42
	for i := 0; i < totalSessions; i++ {
		id := benchSessionID(i + 9000)
		sess := session.New(id, "x:1", false)
		sess.EnqueueTx(chunk)
		s.sessions[id] = sess
		s.sessionOwners[id] = owner
		s.txReady[id] = struct{}{}
	}

	frames, _ := s.drainAll(owner, maxResponseBytesPreEncode)
	if len(frames) == 0 {
		t.Fatal("drainAll returned no frames; test setup did not exercise the budget")
	}

	var totalBytes int
	for _, f := range frames {
		totalBytes += len(f.Payload)
	}

	// The loop checks the byte budget BEFORE adding each session's frames,
	// so the worst-case overshoot is one session's perSessionCap of
	// max-sized frames. Allow that slack; the goal is "stays under client
	// cap (32MB)", not "exact match".
	maxAllowed := maxResponseBytesPreEncode + s.maxDrainFramesPerSession*MaxFramePayload
	if totalBytes > maxAllowed {
		t.Fatalf("response bytes = %d, want ≤ %d (budget=%d, slack=%d)",
			totalBytes, maxAllowed, maxResponseBytesPreEncode,
			s.maxDrainFramesPerSession*MaxFramePayload)
	}

	// And under the carrier client's 32MB cap, with margin for base64 (1.33×)
	// and crypto/header overhead. The whole point of #22 is that this
	// invariant must hold.
	const clientCap = 32 * 1024 * 1024
	estimatedWireBytes := totalBytes * 4 / 3 // base64 inflation
	if estimatedWireBytes > clientCap {
		t.Fatalf("estimated wire response = %d bytes, exceeds carrier client cap %d",
			estimatedWireBytes, clientCap)
	}
}

// BenchmarkExitRouteIncoming_NSessions measures the cost of routing a data
// frame to one of N already-open sessions on the server. This surfaces any
// regression in lock contention or per-frame routing work as session fan-out
// grows. Sessions are populated directly into s.sessions to avoid the openSession
// dial path (covered separately by BenchmarkExitActiveSilent).
func BenchmarkExitRouteIncoming_NSessions(b *testing.B) {
	muteLogsForBench(b)
	for _, n := range []int{1, 8, 64} {
		b.Run("sessions_"+strconv.Itoa(n), func(b *testing.B) {
			s := mustExitTimingServer(b)
			ids := make([][frame.SessionIDLen]byte, n)
			for i := range ids {
				ids[i] = benchSessionID(i + 1)
				sess := session.New(ids[i], "x:1", false)
				s.sessions[ids[i]] = sess
			}
			var owner [frame.ClientIDLen]byte
			owner[0] = 0x01
			for _, id := range ids {
				s.sessionOwners[id] = owner
			}
			payload := bytes.Repeat([]byte{'x'}, 1024)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				id := ids[i%n]
				s.routeIncoming(&frame.Frame{
					SessionID: id,
					Seq:       uint64(i),
					Payload:   payload,
				}, owner)
			}
		})
	}
}

func BenchmarkExitDialFailureBackoffComparison(b *testing.B) {
	target := "bench.invalid:443"
	muteLogsForBench(b)
	const burnCycles = 2048

	b.Run("before_no_backoff", func(b *testing.B) {
		s := mustExitTimingServer(b)
		dialCalls := 0
		setExitTimingDial(s, func(_, _ string, _ time.Duration) (net.Conn, error) {
			dialCalls++
			burnCPU(burnCycles)
			return nil, &net.OpError{Err: syscall.ECONNREFUSED}
		})
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			f := &frame.Frame{
				SessionID: benchSessionID(i + 1),
				Flags:     frame.FlagSYN,
				Target:    target,
			}
			routeIncomingNoBackoff(s, f)
		}
		b.ReportMetric(float64(dialCalls)/float64(b.N), "dials/op")
	})

	b.Run("after_with_backoff", func(b *testing.B) {
		s := mustExitTimingServer(b)
		dialCalls := 0
		setExitTimingDial(s, func(_, _ string, _ time.Duration) (net.Conn, error) {
			dialCalls++
			burnCPU(burnCycles)
			return nil, &net.OpError{Err: syscall.ECONNREFUSED}
		})
		var owner [frame.ClientIDLen]byte
		owner[0] = 0x01
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			f := &frame.Frame{
				SessionID: benchSessionID(i + 1),
				Flags:     frame.FlagSYN,
				Target:    target,
			}
			s.routeIncoming(f, owner)
		}
		b.ReportMetric(float64(dialCalls)/float64(b.N), "dials/op")
	})
}

func burnCPU(cycles int) {
	x := 0
	for i := 0; i < cycles; i++ {
		x += i
	}
	if x == -1 {
		panic("unreachable")
	}
}

func routeIncomingNoBackoff(s *Server, f *frame.Frame) {
	s.mu.Lock()
	sess, exists := s.sessions[f.SessionID]
	s.mu.Unlock()

	if !exists {
		if !f.HasFlag(frame.FlagSYN) {
			return
		}
		var owner [frame.ClientIDLen]byte
		owner[0] = 0x01
		var err error
		sess, err = s.openSession(f.SessionID, f.Target, owner)
		if err != nil {
			return
		}
	}
	sess.ProcessRx(f)
}

func benchSessionID(n int) [frame.SessionIDLen]byte {
	var id [frame.SessionIDLen]byte
	u := uint64(n)
	for i := 0; i < frame.SessionIDLen; i++ {
		id[i] = byte(u >> (8 * i))
	}
	return id
}

func muteLogsForBench(tb testing.TB) {
	tb.Helper()
	prev := log.Writer()
	log.SetOutput(io.Discard)
	tb.Cleanup(func() {
		log.SetOutput(prev)
	})
}
