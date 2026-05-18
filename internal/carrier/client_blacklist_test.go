package carrier

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/kianmhz/GooseRelayVPN/internal/frame"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

// TestEndpointFullRecoveryFromHighFailCount: a single successful response must
// fully clear failCount and blacklistedTill, regardless of how badly the
// endpoint was previously failing. This is the load-bearing invariant for
// post-quota-reset recovery: once Apps Script returns one valid 200, we go
// back to healthy.
func TestEndpointFullRecoveryFromHighFailCount(t *testing.T) {
	c, err := New(Config{
		ScriptURLs: []string{"https://example.invalid/exec"},
		AESKeyHex:  testKeyHex,
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	// Simulate a long quota outage: hammer the endpoint with 403s, then a few
	// generic failures during the still-broken probe window.
	for i := 0; i < 50; i++ {
		c.markEndpoint403(0)
	}
	for i := 0; i < 20; i++ {
		c.markEndpointFailure(0)
	}

	c.endpointMu.Lock()
	failBefore := c.endpoints[0].failCount
	blBefore := c.endpoints[0].blacklistedTill
	c.endpointMu.Unlock()
	if failBefore == 0 {
		t.Fatalf("expected failCount > 0 after failures, got 0")
	}
	if !blBefore.After(time.Now()) {
		t.Fatalf("expected blacklistedTill in the future, got %v", blBefore)
	}

	c.markEndpointSuccess(0)

	c.endpointMu.Lock()
	failAfter := c.endpoints[0].failCount
	blAfter := c.endpoints[0].blacklistedTill
	c.endpointMu.Unlock()

	if failAfter != 0 {
		t.Fatalf("failCount not reset on success: got %d, want 0", failAfter)
	}
	if !blAfter.IsZero() {
		t.Fatalf("blacklistedTill not cleared on success: got %v, want zero", blAfter)
	}
}

// TestBlacklistTTLBoundedByMax: repeated failures must not push blacklistedTill
// arbitrarily far into the future. The TTL ramp tops out at
// endpointBlacklistMaxTTL (1h). If it weren't capped, a long outage could
// schedule recovery many hours past the actual quota reset.
func TestBlacklistTTLBoundedByMax(t *testing.T) {
	c, err := New(Config{
		ScriptURLs: []string{"https://example.invalid/exec"},
		AESKeyHex:  testKeyHex,
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	for i := 0; i < 1000; i++ {
		c.markEndpoint403(0)
	}

	c.endpointMu.Lock()
	bl := c.endpoints[0].blacklistedTill
	c.endpointMu.Unlock()

	now := time.Now()
	maxAcceptable := now.Add(endpointBlacklistMaxTTL + 5*time.Second)
	if bl.After(maxAcceptable) {
		t.Fatalf("blacklistedTill grew past the documented cap: got %v, max %v (cap %s)",
			bl, maxAcceptable, endpointBlacklistMaxTTL)
	}
	if !bl.After(now.Add(endpointBlacklistMaxTTL - 5*time.Second)) {
		t.Fatalf("after many 403s, expected TTL near the 1h cap; got %v (now=%v)", bl, now)
	}
}

// TestPickRelayEndpointAllBlacklistedRefuses: when every endpoint is
// blacklisted, pickRelayEndpoint must return -1 so the caller waits out the
// TTL instead of sending real traffic to a flagged deployment. Hammering
// blacklisted endpoints (the previous fallback behaviour) plausibly extends
// Apps Script's per-deployment cooldown beyond the 24h daily reset window
// (see issues #121 and #126).
func TestPickRelayEndpointAllBlacklistedRefuses(t *testing.T) {
	c, err := New(Config{
		ScriptURLs: []string{
			"https://a.invalid/exec",
			"https://b.invalid/exec",
			"https://c.invalid/exec",
		},
		AESKeyHex: testKeyHex,
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	now := time.Now()
	c.endpointMu.Lock()
	c.endpoints[0].blacklistedTill = now.Add(45 * time.Minute)
	c.endpoints[1].blacklistedTill = now.Add(10 * time.Minute)
	c.endpoints[2].blacklistedTill = now.Add(60 * time.Minute)
	c.endpointMu.Unlock()

	idx, url := c.pickRelayEndpoint()
	if idx >= 0 || url != "" {
		t.Fatalf("expected (-1, \"\") when all endpoints blacklisted; got (%d, %q)", idx, url)
	}

	// Sanity: when one endpoint's TTL has passed, it should now be picked.
	c.endpointMu.Lock()
	c.endpoints[1].blacklistedTill = now.Add(-1 * time.Second) // expired
	c.endpointMu.Unlock()
	idx, _ = c.pickRelayEndpoint()
	if idx != 1 {
		t.Fatalf("after TTL expiry on endpoint 1, picker should select it; got %d", idx)
	}
}

func TestLocalNetworkOfflineClassificationAndBackoff(t *testing.T) {
	wrapped := &url.Error{
		Op:  "Post",
		URL: "https://script.google.com/macros/s/test/exec",
		Err: &net.OpError{
			Op:  "dial",
			Err: &os.SyscallError{Syscall: "connect", Err: syscall.ENETUNREACH},
		},
	}
	if !isLocalNetworkOffline(wrapped) {
		t.Fatal("wrapped ENETUNREACH dial error should be classified as local offline")
	}
	if isLocalNetworkOffline(errors.New("relay returned HTTP 500")) {
		t.Fatal("generic relay/server failure must not be classified as local offline")
	}

	c, err := New(Config{
		ScriptURLs: []string{"https://example.invalid/exec"},
		AESKeyHex:  testKeyHex,
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	c.markEndpointLocalNetworkFailure(0)

	c.endpointMu.Lock()
	ep := c.endpoints[0]
	c.endpointMu.Unlock()
	if ep.failCount != 0 {
		t.Fatalf("local offline failCount = %d, want 0 so standard backoff tiers do not ramp", ep.failCount)
	}
	if !ep.localNetworkOffline {
		t.Fatal("localNetworkOffline flag not set")
	}
	remaining := time.Until(ep.blacklistedTill)
	if remaining <= 0 || remaining > localNetworkOfflineBlacklistTTL+2*time.Second {
		t.Fatalf("local offline blacklist remaining = %v, want short cap around %v", remaining, localNetworkOfflineBlacklistTTL)
	}
}

func TestRecoveryProbeClearsOnlyLocalNetworkFailures(t *testing.T) {
	c, err := New(Config{
		ScriptURLs: []string{
			"https://local-offline.example/exec",
			"https://generic-failure.example/exec",
		},
		AESKeyHex: testKeyHex,
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	now := time.Now()
	c.endpointMu.Lock()
	c.endpoints[0].blacklistedTill = now.Add(time.Minute)
	c.endpoints[0].localNetworkOffline = true
	c.endpoints[1].blacklistedTill = now.Add(time.Minute)
	c.endpoints[1].failCount = 7
	c.endpointMu.Unlock()

	cleared := c.resetLocalNetworkFailures()
	if cleared != 1 {
		t.Fatalf("resetLocalNetworkFailures cleared %d endpoint(s), want 1", cleared)
	}

	c.endpointMu.Lock()
	first := c.endpoints[0]
	second := c.endpoints[1]
	c.endpointMu.Unlock()
	if !first.blacklistedTill.IsZero() || first.localNetworkOffline {
		t.Fatalf("local-offline endpoint was not fully reset: %+v", first)
	}
	if second.blacklistedTill.IsZero() || second.failCount != 7 || second.localNetworkOffline {
		t.Fatalf("generic blacklist should be preserved, got: %+v", second)
	}
}

func TestRecoveryProbeClearsLocalNetworkFailuresWhenNetworkReturns(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err == nil {
			_ = conn.Close()
		}
	}()

	c, err := New(Config{
		ScriptURLs: []string{"https://local-offline.example/exec"},
		AESKeyHex:  testKeyHex,
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	c.recoveryProbeAddr = ln.Addr().String()
	c.endpointMu.Lock()
	c.endpoints[0].blacklistedTill = time.Now().Add(time.Minute)
	c.endpoints[0].localNetworkOffline = true
	c.endpointMu.Unlock()

	if !c.runEndpointRecoveryProbeOnce(context.Background()) {
		t.Fatal("recovery probe did not report a successful reset")
	}
	c.endpointMu.Lock()
	ep := c.endpoints[0]
	c.endpointMu.Unlock()
	if !ep.blacklistedTill.IsZero() || ep.failCount != 0 || ep.localNetworkOffline {
		t.Fatalf("local network recovery did not clear transient backoff: %+v", ep)
	}
}

func TestPollOnceMarksOnlyDoErrorsAsLocalNetworkFailures(t *testing.T) {
	offlineErr := &net.OpError{
		Op:  "dial",
		Err: &os.SyscallError{Syscall: "connect", Err: syscall.ENETUNREACH},
	}
	c, err := New(Config{ScriptURLs: []string{"http://offline.example/exec"}, AESKeyHex: testKeyHex})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	c.httpClients = []*http.Client{{
		Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return nil, offlineErr
		}),
	}}
	c.pollOnce(context.Background())
	c.endpointMu.Lock()
	local := c.endpoints[0]
	c.endpointMu.Unlock()
	if local.failCount != 0 || !local.localNetworkOffline {
		t.Fatalf("Do dial error should use local offline backoff, got failCount=%d local=%v", local.failCount, local.localNetworkOffline)
	}

	c2, err := New(Config{ScriptURLs: []string{"http://server-error.example/exec"}, AESKeyHex: testKeyHex})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	c2.httpClients = []*http.Client{{
		Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusInternalServerError,
				Body:       io.NopCloser(strings.NewReader("server error")),
				Header:     make(http.Header),
			}, nil
		}),
	}}
	c2.pollOnce(context.Background())
	c2.endpointMu.Lock()
	generic := c2.endpoints[0]
	c2.endpointMu.Unlock()
	if generic.failCount == 0 || generic.localNetworkOffline {
		t.Fatalf("HTTP 500 should use normal endpoint failure, got failCount=%d local=%v", generic.failCount, generic.localNetworkOffline)
	}
}

// TestPollOnce_AllBlacklistedSendsNoTraffic: integration check that no HTTP
// request goes out when every endpoint is blacklisted. Before the fix, the
// carrier kept POSTing to the soonest-expiring endpoint at the idle-backoff
// rate (~4 req/sec/endpoint), 100% of which were 403'd — extending Google's
// per-deployment penalty.
func TestPollOnce_AllBlacklistedSendsNoTraffic(t *testing.T) {
	aead, err := frame.NewCryptoFromHexKey(testKeyHex)
	if err != nil {
		t.Fatalf("crypto: %v", err)
	}
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()
	_ = aead

	c, err := New(Config{ScriptURLs: []string{srv.URL}, AESKeyHex: testKeyHex})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	// Manually blacklist the sole endpoint for 30 minutes.
	c.endpointMu.Lock()
	c.endpoints[0].blacklistedTill = time.Now().Add(30 * time.Minute)
	c.endpoints[0].failCount = 7
	c.endpointMu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		_ = c.Run(ctx)
		close(done)
	}()

	// Open a session so the carrier has real TX work to do — this is exactly
	// the scenario where the old code would hammer the blacklisted endpoint.
	s := c.NewSession("example.com:80")
	s.EnqueueTx([]byte("would-be-traffic"))

	time.Sleep(2 * time.Second)
	cancel()
	<-done

	if got := hits.Load(); got != 0 {
		t.Fatalf("expected zero requests to blacklisted endpoint over 2s, got %d", got)
	}
}

// blacklistHammerServer counts hits and returns either 403 (during the
// "outage") or echoes the batch (after the outage ends). It also tracks how
// many decoded frames it has seen after the outage ended, which is the signal
// for whether the carrier retransmitted dropped frames.
type blacklistHammerServer struct {
	t                 *testing.T
	aead              *frame.Crypto
	hits              atomic.Int64
	outage            atomic.Bool
	framesAfterOutage atomic.Int64
	rxSeqMu           sync.Mutex
	rxSeq             map[[frame.SessionIDLen]byte]uint64
}

func newBlacklistHammerServer(t *testing.T, aead *frame.Crypto) *blacklistHammerServer {
	return &blacklistHammerServer{t: t, aead: aead, rxSeq: map[[frame.SessionIDLen]byte]uint64{}}
}

func (s *blacklistHammerServer) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.hits.Add(1)
		if s.outage.Load() {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte("quota exhausted"))
			return
		}
		body, _ := io.ReadAll(r.Body)
		clientID, in, err := frame.DecodeBatch(s.aead, body)
		if err != nil {
			s.t.Errorf("decode: %v", err)
			w.WriteHeader(500)
			return
		}
		s.framesAfterOutage.Add(int64(len(in)))
		s.rxSeqMu.Lock()
		out := make([]*frame.Frame, 0, len(in))
		for _, f := range in {
			seq := s.rxSeq[f.SessionID]
			s.rxSeq[f.SessionID] = seq + 1
			out = append(out, &frame.Frame{
				SessionID: f.SessionID,
				Seq:       seq,
				Payload:   f.Payload,
			})
		}
		s.rxSeqMu.Unlock()
		resp, _ := frame.EncodeBatch(s.aead, clientID, out)
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write(resp)
	}
}

// TestSinglePostOutageSuccessRestoresTraffic: integration test. The relay
// returns 403 for a short window, then starts echoing. The carrier must
// recover and deliver an echoed payload promptly (within the fallback-probe
// rate of the all-blacklisted branch). This is the behaviour that determines
// whether users actually see traffic flow after Apps Script's midnight Pacific
// quota reset.
func TestSinglePostOutageSuccessRestoresTraffic(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test; skipped under -short")
	}
	aead, err := frame.NewCryptoFromHexKey(testKeyHex)
	if err != nil {
		t.Fatalf("crypto: %v", err)
	}
	bs := newBlacklistHammerServer(t, aead)
	bs.outage.Store(true)
	srv := httptest.NewServer(bs.handler())
	defer srv.Close()

	c, err := New(Config{ScriptURLs: []string{srv.URL}, AESKeyHex: testKeyHex})
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

	// Stay in outage for 2s so the endpoint gets blacklisted at the 5-min tier.
	time.Sleep(2 * time.Second)
	hitsDuringOutage := bs.hits.Load()
	bs.outage.Store(false)
	// Simulate the blacklist TTL elapsing. In production this happens
	// naturally after the failCount-driven TTL (5 min → 1 h); in a 10-second
	// integration test we force-expire so we can assert the actual rollback
	// behaviour rather than how long we wait.
	c.endpointMu.Lock()
	for i := range c.endpoints {
		c.endpoints[i].blacklistedTill = time.Time{}
		c.endpoints[i].failCount = 0
	}
	c.endpointMu.Unlock()
	c.kick()

	select {
	case got := <-s.RxChan:
		if string(got) != "hello" {
			t.Fatalf("got %q want %q", got, "hello")
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("no echo received after outage ended.\n"+
			"  hits during outage:     %d (server returned 403)\n"+
			"  total hits at giveup:   %d\n"+
			"  frames decoded after outage ended: %d  (==0 indicates carrier sent only empty polls — SYN/payload was not retransmitted after the 403 drop)",
			hitsDuringOutage, bs.hits.Load(), bs.framesAfterOutage.Load())
	}

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run() did not return after cancel")
	}

	t.Logf("hits during 2s outage: %d, total hits at recovery: %d",
		hitsDuringOutage, bs.hits.Load())
}
