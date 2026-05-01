package exit

import (
	"bytes"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/kianmhz/GooseRelayVPN/internal/frame"
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
	s.dial = func(_, addr string, _ time.Duration) (net.Conn, error) {
		time.Sleep(dialDelay)
		return nil, &net.OpError{Op: "dial", Net: "tcp", Err: errSimulatedDialFail{}}
	}

	clientID := [frame.ClientIDLen]byte{0xCC}
	frames := []*frame.Frame{
		{SessionID: [frame.SessionIDLen]byte{0xA1}, Flags: frame.FlagSYN, Target: "a.example:443"},
		{SessionID: [frame.SessionIDLen]byte{0xB2}, Flags: frame.FlagSYN, Target: "b.example:443"},
		{SessionID: [frame.SessionIDLen]byte{0xC3}, Flags: frame.FlagSYN, Target: "c.example:443"},
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
	if !s.isDialSuppressed(target) {
		t.Fatal("expected target to be dial-suppressed")
	}

	s.mu.Lock()
	s.dialFail[target] = time.Now().Add(-time.Millisecond)
	s.mu.Unlock()
	if s.isDialSuppressed(target) {
		t.Fatal("expected expired suppression to clear")
	}

	s.mu.Lock()
	_, exists := s.dialFail[target]
	s.mu.Unlock()
	if exists {
		t.Fatal("expected expired target entry to be deleted")
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
		frames, _ := s.drainAll(owner)
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
		frames, _ := s.drainAll(owner)
		if len(frames) != maxDrainFramesPerBatchBusy {
			t.Fatalf("expected busy cap %d frames, got %d", maxDrainFramesPerBatchBusy, len(frames))
		}
	})
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
		s.dial = func(_, _ string, _ time.Duration) (net.Conn, error) {
			dialCalls++
			burnCPU(burnCycles)
			return nil, &net.OpError{Err: syscall.ECONNREFUSED}
		}
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
		s.dial = func(_, _ string, _ time.Duration) (net.Conn, error) {
			dialCalls++
			burnCPU(burnCycles)
			return nil, &net.OpError{Err: syscall.ECONNREFUSED}
		}
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
