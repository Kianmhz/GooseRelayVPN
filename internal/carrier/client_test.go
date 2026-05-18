package carrier

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/kianmhz/GooseRelayVPN/internal/frame"
)

const testKeyHex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

type carrierErrReader struct{}

func (carrierErrReader) Read([]byte) (int, error) {
	return 0, errors.New("reader should not be called")
}

func TestReadRelayResponseBodyBoundsAndPreallocates(t *testing.T) {
	_, err := readRelayResponseBody(bytes.NewReader([]byte("abcdef")), -1, 5)
	if err == nil {
		t.Fatal("readRelayResponseBody succeeded for over-limit unknown-length body")
	}

	_, err = readRelayResponseBody(carrierErrReader{}, 6, 5)
	if err == nil {
		t.Fatal("readRelayResponseBody succeeded for over-limit Content-Length")
	}

	got, err := readRelayResponseBody(bytes.NewReader([]byte("abcde")), int64(len("abcde")), 5)
	if err != nil {
		t.Fatalf("readRelayResponseBody: %v", err)
	}
	if string(got) != "abcde" {
		t.Fatalf("readRelayResponseBody = %q, want abcde", got)
	}
}

// echoServer decodes the incoming batch, echoes each frame's payload back
// (with the SYN bit cleared and seq reset per session), and returns it.
func echoServer(t *testing.T, aead *frame.Crypto) (*httptest.Server, *int) {
	t.Helper()
	var hits int
	var mu sync.Mutex
	rxSeqBySession := map[[frame.SessionIDLen]byte]uint64{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits++
		mu.Unlock()
		body, _ := io.ReadAll(r.Body)
		clientID, in, err := frame.DecodeBatch(aead, body)
		if err != nil {
			t.Errorf("server decode: %v", err)
			w.WriteHeader(500)
			return
		}
		var out []*frame.Frame
		mu.Lock()
		for _, f := range in {
			seq := rxSeqBySession[f.SessionID]
			rxSeqBySession[f.SessionID] = seq + 1
			out = append(out, &frame.Frame{
				SessionID: f.SessionID,
				Seq:       seq,
				Payload:   f.Payload,
			})
		}
		mu.Unlock()
		respBody, _ := frame.EncodeBatch(aead, clientID, out)
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write(respBody)
	}))
	return srv, &hits
}

func TestCarrier_RoundTripEcho(t *testing.T) {
	aead, err := frame.NewCryptoFromHexKey(testKeyHex)
	if err != nil {
		t.Fatalf("crypto: %v", err)
	}
	srv, _ := echoServer(t, aead)
	defer srv.Close()

	c, err := New(Config{
		ScriptURLs: []string{srv.URL},
		AESKeyHex:  testKeyHex,
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		_ = c.Run(ctx)
		close(done)
	}()

	s := c.NewSession("example.com:80")
	s.EnqueueTx([]byte("hello"))

	// Read the echoed payload from the session's RxChan.
	select {
	case got := <-s.RxChan:
		if string(got) != "hello" {
			t.Fatalf("got %q want %q", got, "hello")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for echoed payload")
	}

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run() did not return after cancel")
	}
}

func TestCarrier_UnknownSessionFramesDropped(t *testing.T) {
	aead, _ := frame.NewCryptoFromHexKey(testKeyHex)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Always reply with one frame for an unknown session ID.
		var unknown [frame.SessionIDLen]byte
		for i := range unknown {
			unknown[i] = 0xEE
		}
		var ghostClient [frame.ClientIDLen]byte
		body, _ := frame.EncodeBatch(aead, ghostClient, []*frame.Frame{
			{SessionID: unknown, Seq: 0, Payload: []byte("ghost")},
		})
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	c, err := New(Config{ScriptURLs: []string{srv.URL}, AESKeyHex: testKeyHex})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = c.Run(ctx) }()

	// Just let it run a couple of poll cycles. A panic / data race here is
	// the failure mode; the assertion is "doesn't crash."
	time.Sleep(200 * time.Millisecond)
}

func TestCarrier_PollOnceDropsNonBatchPayload(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<!doctype html><html><body>quota exceeded</body></html>"))
	}))
	defer srv.Close()

	c, err := New(Config{ScriptURLs: []string{srv.URL}, AESKeyHex: testKeyHex})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	c.httpClients = []*http.Client{srv.Client()}

	if didWork := c.pollOnce(context.Background()); didWork {
		t.Fatal("expected no work for non-batch relay payload")
	}
}

func TestIsLikelyNonBatchRelayPayload(t *testing.T) {
	tests := []struct {
		name string
		in   []byte
		want bool
	}{
		{name: "html", in: []byte("<html>oops</html>"), want: true},
		{name: "doctype", in: []byte("<!DOCTYPE html>"), want: true},
		{name: "json", in: []byte(`{"e":"quota"}`), want: true},
		{name: "http", in: []byte("HTTP/1.1 502 Bad Gateway"), want: true},
		{name: "base64ish", in: []byte("QUJDRA=="), want: false},
		{name: "empty", in: []byte(" \r\n\t "), want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := isLikelyNonBatchRelayPayload(tc.in); got != tc.want {
				t.Fatalf("got %v want %v", got, tc.want)
			}
		})
	}
}

func TestCarrier_FailsOverToHealthyScriptURLWithoutTxLoss(t *testing.T) {
	aead, err := frame.NewCryptoFromHexKey(testKeyHex)
	if err != nil {
		t.Fatalf("crypto: %v", err)
	}

	badSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte("quota"))
	}))
	defer badSrv.Close()

	goodSrv, _ := echoServer(t, aead)
	defer goodSrv.Close()

	c, err := New(Config{ScriptURLs: []string{badSrv.URL, goodSrv.URL}, AESKeyHex: testKeyHex})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		_ = c.Run(ctx)
		close(done)
	}()

	s := c.NewSession("example.com:80")
	s.EnqueueTx([]byte("hello-failover"))

	select {
	case got := <-s.RxChan:
		if string(got) != "hello-failover" {
			t.Fatalf("got %q want %q", got, "hello-failover")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for failover response")
	}

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run() did not return after cancel")
	}
}

// TestCarrier_PureDownloadIdleCap is the regression test for issue #41
// (excessive upload during downloads in v1.4.1). Before the fix, the
// pure-download branch let numWorkers-1 workers each hold an idle long-poll
// concurrently. Every downstream chunk woke all of them; only one received
// the chunk while the rest re-POSTed empty bodies, multiplying upload
// bandwidth by the worker count. The cap in pure-download mode is now
// max(pureDownloadIdleCap, len(endpoints)): one poll per endpoint, with a
// floor of 2 for single-endpoint configs. This fixes both the upload
// amplification of #41 and the throughput collapse in multi-endpoint configs
// after initial SYNs completed (issue #73).
func TestCarrier_PureDownloadIdleCap(t *testing.T) {
	aead, err := frame.NewCryptoFromHexKey(testKeyHex)
	if err != nil {
		t.Fatalf("crypto: %v", err)
	}

	var (
		mu       sync.Mutex
		current  int
		peak     int
		totalReq int
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		current++
		totalReq++
		if current > peak {
			peak = current
		}
		mu.Unlock()
		// Hold the request long enough that any racing worker gets a chance
		// to attempt its own idle poll before this one returns. Long enough
		// that a thundering herd would be visible in the peak count.
		time.Sleep(400 * time.Millisecond)
		mu.Lock()
		current--
		mu.Unlock()

		// Empty batch response — keeps the client in pure-download mode.
		var clientID [frame.ClientIDLen]byte
		body, _ := frame.EncodeBatch(aead, clientID, nil)
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	// Four endpoints labeled under four distinct accounts → bucketCount = 4,
	// numWorkers = workersPerEndpoint × 4 = 12. Pre-fix idleCap would have been
	// numWorkers-1 = 11; new cap is max(pureDownloadIdleCap, bucketCount) = 4.
	// Labeling matters: with no labels these would collapse to one bucket and
	// the test wouldn't exercise the cap.
	urls := []string{
		srv.URL + "/a", srv.URL + "/b", srv.URL + "/c", srv.URL + "/d",
	}
	accounts := []string{"A", "B", "C", "D"}
	c, err := New(Config{ScriptURLs: urls, ScriptAccounts: accounts, AESKeyHex: testKeyHex})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	c.httpClients = []*http.Client{srv.Client()}

	if c.numWorkers <= pureDownloadIdleCap+1 {
		t.Fatalf("test setup: need numWorkers (%d) > pureDownloadIdleCap+1 (%d) "+
			"to actually exercise the cap", c.numWorkers, pureDownloadIdleCap+1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		_ = c.Run(ctx)
		close(done)
	}()

	// Let the workers spin for several poll cycles so the peak measurement is
	// stable. With 400ms hold + 10ms re-entry, ~1.5s covers ≥3 cycles.
	time.Sleep(1500 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run() did not return after cancel")
	}

	mu.Lock()
	gotPeak := peak
	gotTotal := totalReq
	mu.Unlock()

	wantCap := pureDownloadIdleCap
	if c.bucketCount > wantCap {
		wantCap = c.bucketCount
	}
	if gotPeak > wantCap {
		t.Fatalf("peak concurrent idle long-polls = %d, want ≤ %d "+
			"(numWorkers=%d, buckets=%d, len(endpoints)=%d, totalReq=%d)",
			gotPeak, wantCap, c.numWorkers, c.bucketCount, len(c.endpoints), gotTotal)
	}
	if gotPeak == 0 {
		t.Fatal("no polls were issued; test did not exercise the cap")
	}
}

// TestCarrier_IdleSlotsPerBucket verifies that the IdleSlotsPerBucket config
// knob multiplies the per-bucket idle long-poll cap. With 2 buckets and
// IdleSlotsPerBucket=2, the cap should be 4 (not 2 from the default of 1).
func TestCarrier_IdleSlotsPerBucket(t *testing.T) {
	aead, err := frame.NewCryptoFromHexKey(testKeyHex)
	if err != nil {
		t.Fatalf("crypto: %v", err)
	}

	var (
		mu       sync.Mutex
		current  int
		peak     int
		totalReq int
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		current++
		totalReq++
		if current > peak {
			peak = current
		}
		mu.Unlock()
		time.Sleep(400 * time.Millisecond)
		mu.Lock()
		current--
		mu.Unlock()

		var clientID [frame.ClientIDLen]byte
		body, _ := frame.EncodeBatch(aead, clientID, nil)
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	// 4 endpoints, 2 distinct accounts (A,A,B,B), IdleSlotsPerBucket=2:
	//   bucketCount=2, idleCap=bucketCount×IdleSlotsPerBucket=4,
	//   numWorkers=(workersPerEndpoint+IdleSlotsPerBucket-1)×bucketCount=8.
	// The +1 worker per bucket preserves TX capacity when the extra idle
	// slot camps an additional worker on a long-poll. Default
	// IdleSlotsPerBucket=1 would cap at 2 idle slots and 6 workers.
	urls := []string{srv.URL + "/a", srv.URL + "/b", srv.URL + "/c", srv.URL + "/d"}
	accounts := []string{"A", "A", "B", "B"}
	c, err := New(Config{
		ScriptURLs:         urls,
		ScriptAccounts:     accounts,
		AESKeyHex:          testKeyHex,
		IdleSlotsPerBucket: 2,
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	c.httpClients = []*http.Client{srv.Client()}

	wantCap := c.bucketCount * c.idleSlotsPerBucket
	if wantCap != 4 {
		t.Fatalf("test setup: bucketCount=%d × idleSlotsPerBucket=%d = %d, want 4",
			c.bucketCount, c.idleSlotsPerBucket, wantCap)
	}
	if c.numWorkers <= wantCap {
		t.Fatalf("test setup: numWorkers (%d) must exceed wantCap (%d) to exercise it",
			c.numWorkers, wantCap)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		_ = c.Run(ctx)
		close(done)
	}()

	time.Sleep(1500 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run() did not return after cancel")
	}

	mu.Lock()
	gotPeak := peak
	gotTotal := totalReq
	mu.Unlock()

	if gotPeak > wantCap {
		t.Fatalf("peak concurrent idle long-polls = %d, want ≤ %d "+
			"(buckets=%d, idleSlotsPerBucket=%d, totalReq=%d)",
			gotPeak, wantCap, c.bucketCount, c.idleSlotsPerBucket, gotTotal)
	}
	// Sanity check: with 2 buckets × 2 slots = 4 cap and 6 workers, we should
	// observe peak ≥ 3 — anything lower means the knob isn't lifting the cap
	// past the default-1 behavior (which would peak at 2).
	if gotPeak < 3 {
		t.Fatalf("peak concurrent idle long-polls = %d, want ≥ 3 "+
			"(IdleSlotsPerBucket=2 should lift cap above default; totalReq=%d)",
			gotPeak, gotTotal)
	}
}

// TestCarrier_KickCoalesceDisabled verifies kick() broadcasts immediately
// when adaptive coalescing is off (default). A worker waiting on the wake
// channel must observe the broadcast without any added delay.
func TestCarrier_KickCoalesceDisabled(t *testing.T) {
	c, err := New(Config{
		ScriptURLs: []string{"http://example.invalid/exec"},
		AESKeyHex:  testKeyHex,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	wakeCh := c.wake.C()
	start := time.Now()
	c.kick()
	select {
	case <-wakeCh:
	case <-time.After(50 * time.Millisecond):
		t.Fatalf("wake not received within 50ms (coalescing should be disabled)")
	}
	if elapsed := time.Since(start); elapsed > 10*time.Millisecond {
		t.Errorf("immediate kick took %v, want < 10ms", elapsed)
	}
}

// TestCarrier_KickCoalesceDelaysSingleKick verifies a lone kick is delayed
// by approximately coalesceStep before the wake fires.
func TestCarrier_KickCoalesceDelaysSingleKick(t *testing.T) {
	step := 30 * time.Millisecond
	c, err := New(Config{
		ScriptURLs:   []string{"http://example.invalid/exec"},
		AESKeyHex:    testKeyHex,
		CoalesceStep: step,
		CoalesceMax:  500 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	wakeCh := c.wake.C()
	start := time.Now()
	c.kick()
	select {
	case <-wakeCh:
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("wake never fired")
	}
	elapsed := time.Since(start)
	if elapsed < step-5*time.Millisecond {
		t.Errorf("wake fired too early: %v < step %v", elapsed, step)
	}
	if elapsed > step+50*time.Millisecond {
		t.Errorf("wake fired too late: %v >> step %v", elapsed, step)
	}
}

// TestCarrier_KickCoalesceResetsOnBurst verifies that successive kicks within
// the step window reset the timer so the wake fires step after the LAST kick,
// collapsing the whole burst into one wake.
func TestCarrier_KickCoalesceResetsOnBurst(t *testing.T) {
	step := 40 * time.Millisecond
	c, err := New(Config{
		ScriptURLs:   []string{"http://example.invalid/exec"},
		AESKeyHex:    testKeyHex,
		CoalesceStep: step,
		CoalesceMax:  500 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	wakeCh := c.wake.C()
	start := time.Now()

	// Kick three times spaced step/2 apart: each kick resets the timer, so
	// the wake should fire ~step after the last kick (~2*step total).
	c.kick()
	time.Sleep(step / 2)
	c.kick()
	time.Sleep(step / 2)
	c.kick()
	lastKick := time.Now()

	select {
	case <-wakeCh:
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("wake never fired")
	}
	sinceLast := time.Since(lastKick)
	if sinceLast < step-10*time.Millisecond {
		t.Errorf("wake fired %v after last kick, want >= step %v", sinceLast, step)
	}
	totalElapsed := time.Since(start)
	if totalElapsed < 2*step-10*time.Millisecond {
		t.Errorf("burst collapsed too early: total %v, expected at least 2*step %v", totalElapsed, 2*step)
	}
}

// TestCarrier_KickCoalesceHardCap verifies that continuous kicks past the
// hard deadline still let the wake fire near coalesceMax — a steady stream
// cannot starve the workers indefinitely.
func TestCarrier_KickCoalesceHardCap(t *testing.T) {
	// Step and kick interval are deliberately well above Windows' default
	// timer resolution (~15.6ms). A tighter budget (step=20ms, kicks every
	// 10ms) flakes on windows-latest because the ticker can't actually fire
	// faster than the step, so the step timer fires at ~step instead of
	// waiting for the hard cap and the test reads "wake fired before hard
	// cap." With step=50ms / kick every 25ms, even a 30ms-jitter Windows
	// tick still resets the step before it expires.
	step := 50 * time.Millisecond
	max := 200 * time.Millisecond
	c, err := New(Config{
		ScriptURLs:   []string{"http://example.invalid/exec"},
		AESKeyHex:    testKeyHex,
		CoalesceStep: step,
		CoalesceMax:  max,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	wakeCh := c.wake.C()
	start := time.Now()

	// Kick continuously every step/2 for longer than max; the hard cap should
	// fire the wake despite the constant resets.
	stopKicking := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(step / 2)
		defer ticker.Stop()
		c.kick()
		for {
			select {
			case <-stopKicking:
				return
			case <-ticker.C:
				c.kick()
			}
		}
	}()

	select {
	case <-wakeCh:
	case <-time.After(2 * max):
		close(stopKicking)
		<-done
		t.Fatalf("wake never fired despite hard cap of %v", max)
	}
	close(stopKicking)
	<-done

	elapsed := time.Since(start)
	if elapsed < max-10*time.Millisecond {
		t.Errorf("wake fired before hard cap: %v < %v", elapsed, max)
	}
	if elapsed > max+50*time.Millisecond {
		t.Errorf("wake fired well past hard cap: %v > %v", elapsed, max)
	}
}

// TestCarrier_IdleBackoffSchedule guards the adaptive backoff curve so a
// future "tweak" cannot accidentally regress to a tight 10ms loop on idle
// workers (the upload-amplification half of issue #41).
func TestCarrier_IdleBackoffSchedule(t *testing.T) {
	cases := []struct {
		n    int
		want time.Duration
	}{
		{0, pollIdleSleep},
		{2, pollIdleSleep},
		{3, 50 * time.Millisecond},
		{9, 50 * time.Millisecond},
		{10, 250 * time.Millisecond},
		{29, 250 * time.Millisecond},
		{30, time.Second},
		{1000, time.Second},
	}
	for _, tc := range cases {
		if got := idleBackoff(tc.n); got != tc.want {
			t.Errorf("idleBackoff(%d) = %v, want %v", tc.n, got, tc.want)
		}
	}
}
