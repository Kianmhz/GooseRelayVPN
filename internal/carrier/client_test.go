package carrier

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kianmhz/GooseRelayVPN/internal/frame"
	"github.com/kianmhz/GooseRelayVPN/internal/protocol"
)

const testKeyHex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

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

func binaryEchoServer(t *testing.T, aead *frame.Crypto) (*httptest.Server, *int) {
	t.Helper()
	var hits int
	var mu sync.Mutex
	rxSeqBySession := map[[frame.SessionIDLen]byte]uint64{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Content-Type"); got != "application/octet-stream" {
			t.Errorf("Content-Type = %q, want application/octet-stream", got)
		}
		mu.Lock()
		hits++
		mu.Unlock()
		body, _ := io.ReadAll(r.Body)
		clientID, in, err := frame.DecodeBatchBinary(aead, body)
		if err != nil {
			t.Errorf("server binary decode: %v", err)
			w.WriteHeader(500)
			return
		}
		var out []*frame.Frame
		mu.Lock()
		for _, f := range in {
			seq := rxSeqBySession[f.SessionID]
			rxSeqBySession[f.SessionID] = seq + 1
			out = append(out, &frame.Frame{SessionID: f.SessionID, Seq: seq, Payload: f.Payload})
		}
		mu.Unlock()
		respBody, _ := frame.EncodeBatchBinary(aead, clientID, out)
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(respBody)
	}))
	return srv, &hits
}

func TestCarrier_DiagnoseDirectPostSkipsAppsScriptGET(t *testing.T) {
	aead, err := frame.NewCryptoFromHexKey(testKeyHex)
	if err != nil {
		t.Fatalf("crypto: %v", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			t.Fatalf("direct_post diagnose must not use Apps Script GET probe")
		}
		if r.Method != http.MethodPost {
			t.Fatalf("method = %s, want POST", r.Method)
		}
		if got := r.Header.Get("Content-Type"); got != "application/octet-stream" {
			t.Fatalf("Content-Type = %q, want application/octet-stream", got)
		}
		body, _ := io.ReadAll(r.Body)
		clientID, in, err := frame.DecodeBatchBinary(aead, body)
		if err != nil {
			t.Fatalf("decode probe: %v", err)
		}
		if len(in) != 1 {
			t.Fatalf("probe frames = %d, want 1", len(in))
		}
		payload, err := protocol.EncodeVersionInfo("test-server", protocol.MaxFramePayload, nil)
		if err != nil {
			t.Fatalf("version payload: %v", err)
		}
		respBody, err := frame.EncodeBatchBinary(aead, clientID, []*frame.Frame{{
			SessionID: in[0].SessionID,
			Flags:     frame.FlagRST,
			Payload:   payload,
		}})
		if err != nil {
			t.Fatalf("encode response: %v", err)
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(respBody)
	}))
	defer srv.Close()

	c, err := New(Config{
		TransportMode: "direct_post",
		ScriptURLs:    []string{srv.URL},
		AESKeyHex:     testKeyHex,
		BinaryDirect:  true,
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	if err := c.Diagnose(context.Background()); err != nil {
		t.Fatalf("Diagnose: %v", err)
	}
}

func TestClassifyRelayErrorBody_UpstreamStatus204(t *testing.T) {
	reason, hard := classifyRelayErrorBody([]byte(`{"e":"upstream_status","status":204,"body":""}`))
	if !hard {
		t.Fatal("HTTP 204 upstream status should be classified as hard")
	}
	if !strings.Contains(strings.ToLower(reason), "tunnel_key") {
		t.Fatalf("reason = %q, want tunnel_key guidance", reason)
	}
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

func TestCarrier_DirectBinaryRoundTripEcho(t *testing.T) {
	aead, err := frame.NewCryptoFromHexKey(testKeyHex)
	if err != nil {
		t.Fatalf("crypto: %v", err)
	}
	srv, _ := binaryEchoServer(t, aead)
	defer srv.Close()

	c, err := New(Config{
		ScriptURLs:   []string{srv.URL},
		AESKeyHex:    testKeyHex,
		BinaryDirect: true,
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
	s.EnqueueTx([]byte("hello-binary"))

	select {
	case got := <-s.RxChan:
		if string(got) != "hello-binary" {
			t.Fatalf("got %q want hello-binary", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for binary echo")
	}

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run() did not return after cancel")
	}
}

func TestCarrier_NewAllowsDirectStreamOnly(t *testing.T) {
	c, err := New(Config{
		TransportMode:    "direct_stream",
		DirectStreamURLs: []string{"ws://127.0.0.1:8443/stream"},
		AESKeyHex:        testKeyHex,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if len(c.endpoints) != 0 {
		t.Fatalf("endpoints = %d, want 0 for direct-stream-only mode", len(c.endpoints))
	}
	if c.numWorkers != 0 {
		t.Fatalf("numWorkers = %d, want 0 because POST fallback is disabled", c.numWorkers)
	}
	if !c.streamEnabled() || c.postEnabled() {
		t.Fatalf("transport gates wrong: streamEnabled=%v postEnabled=%v", c.streamEnabled(), c.postEnabled())
	}
}

func TestCarrier_AutoTransportUsesPostFallbackWhenStreamInactive(t *testing.T) {
	c, err := New(Config{
		TransportMode:    "auto",
		DirectStreamURLs: []string{"ws://127.0.0.1:8443/stream"},
		ScriptURLs:       []string{"http://127.0.0.1:8443/tunnel"},
		AESKeyHex:        testKeyHex,
		BinaryDirect:     true,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if !c.streamEnabled() || !c.postEnabled() {
		t.Fatalf("auto transport should enable both stream and POST fallback")
	}
	if c.numWorkers == 0 {
		t.Fatal("auto transport with POST fallback should keep POST workers available")
	}
}

func TestCarrier_UpdateEndpointsAddsNewURLWithoutRestart(t *testing.T) {
	c, err := New(Config{
		ScriptURLs:     []string{"https://script.google.com/macros/s/old/exec"},
		ScriptAccounts: []string{"account-a"},
		AESKeyHex:      testKeyHex,
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	c.markEndpoint403(0)

	count := c.UpdateEndpoints(
		[]string{"https://script.google.com/macros/s/new/exec"},
		[]string{"account-b"},
	)
	if count != 1 {
		t.Fatalf("UpdateEndpoints returned %d, want 1", count)
	}

	c.endpointMu.Lock()
	defer c.endpointMu.Unlock()
	if len(c.endpoints) != 1 {
		t.Fatalf("endpoint count = %d, want 1", len(c.endpoints))
	}
	ep := c.endpoints[0]
	if ep.url != "https://script.google.com/macros/s/new/exec" {
		t.Fatalf("url = %q", ep.url)
	}
	if ep.account != "account-b" {
		t.Fatalf("account = %q", ep.account)
	}
	if !ep.blacklistedTill.IsZero() || ep.failCount != 0 {
		t.Fatal("new endpoint should not inherit old endpoint blacklist state")
	}
}

func TestCarrier_UpdateEndpointsPreservesKnownEndpointState(t *testing.T) {
	url := "https://script.google.com/macros/s/old/exec"
	c, err := New(Config{
		ScriptURLs:     []string{url},
		ScriptAccounts: []string{"account-a"},
		AESKeyHex:      testKeyHex,
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	c.markEndpoint403(0)

	c.UpdateEndpoints([]string{url}, []string{"renamed-account"})

	c.endpointMu.Lock()
	defer c.endpointMu.Unlock()
	if c.endpoints[0].blacklistedTill.IsZero() || c.endpoints[0].failCount == 0 {
		t.Fatal("known endpoint should preserve failure/blacklist state")
	}
	if c.endpoints[0].account != "renamed-account" {
		t.Fatalf("account = %q", c.endpoints[0].account)
	}
}

func TestCarrier_HoldsThenClosesSessionsWhenAllEndpointsBlacklisted(t *testing.T) {
	c, err := New(Config{
		ScriptURLs: []string{
			"https://script.google.com/macros/s/a/exec",
			"https://script.google.com/macros/s/b/exec",
		},
		AESKeyHex:           testKeyHex,
		EndpointOutageGrace: time.Millisecond,
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	s := c.NewSession("example.com:443")

	c.endpointMu.Lock()
	for i := range c.endpoints {
		c.endpoints[i].blacklistedTill = time.Now().Add(time.Minute)
	}
	c.endpointMu.Unlock()

	if closed := c.closeSessionsIfAllEndpointsBlacklisted("test"); closed {
		t.Fatal("first all-endpoints outage check should hold sessions during grace")
	}
	time.Sleep(2 * time.Millisecond)
	if closed := c.closeSessionsIfAllEndpointsBlacklisted("test"); !closed {
		t.Fatal("expected sessions to close after endpoint outage grace")
	}
	c.mu.Lock()
	sessionCount := len(c.sessions)
	readyCount := len(c.txReady)
	inFlightCount := len(c.inFlight)
	c.mu.Unlock()
	if sessionCount != 0 || readyCount != 0 || inFlightCount != 0 {
		t.Fatalf("client maps not cleared: sessions=%d txReady=%d inFlight=%d", sessionCount, readyCount, inFlightCount)
	}
	if _, ok := <-s.RxChan; ok {
		t.Fatal("session RxChan should close so the SOCKS side reconnects")
	}
	s.EnqueueTx([]byte("after-close"))
	if frames := s.DrainTx(64 * 1024); len(frames) != 0 {
		t.Fatalf("closed session should not drain TX, got %d frame(s)", len(frames))
	}
}

func TestCarrier_DoesNotCloseSessionsWhenAnyEndpointHealthy(t *testing.T) {
	c, err := New(Config{
		ScriptURLs: []string{
			"https://script.google.com/macros/s/a/exec",
			"https://script.google.com/macros/s/b/exec",
		},
		AESKeyHex: testKeyHex,
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	_ = c.NewSession("example.com:443")

	c.endpointMu.Lock()
	c.endpoints[0].blacklistedTill = time.Now().Add(time.Minute)
	c.endpointMu.Unlock()

	if closed := c.closeSessionsIfAllEndpointsBlacklisted("test"); closed {
		t.Fatal("should not close sessions while at least one endpoint is healthy")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.sessions) != 1 {
		t.Fatalf("sessions = %d, want 1", len(c.sessions))
	}
}

func TestCarrier_RunWorkerClosesSessionsAfterQuotaFailureWithQueuedTx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<!doctype html><html><body>Service invoked too many times for one day</body></html>"))
	}))
	defer srv.Close()

	c, err := New(Config{
		ScriptURLs:          []string{srv.URL + "/a", srv.URL + "/b"},
		AESKeyHex:           testKeyHex,
		EndpointOutageGrace: time.Millisecond,
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	c.httpClients = []*http.Client{srv.Client()}
	s := c.NewSession("example.com:443")
	s.EnqueueTx([]byte("hello"))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		c.runWorker(ctx)
		close(done)
	}()

	select {
	case _, ok := <-s.RxChan:
		if ok {
			t.Fatal("RxChan delivered data instead of closing")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for worker to close frozen session")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("worker did not stop after context cancel")
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

func TestCarrier_PollOnceRetriesAlternateDeploymentAfterQuotaPayload(t *testing.T) {
	aead, err := frame.NewCryptoFromHexKey(testKeyHex)
	if err != nil {
		t.Fatalf("crypto: %v", err)
	}
	var firstHits, secondHits int
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		firstHits++
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html>Service invoked too many times for one day: urlfetch.</html>"))
	}))
	defer first.Close()
	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		secondHits++
		body, _ := io.ReadAll(r.Body)
		clientID, in, err := frame.DecodeBatch(aead, body)
		if err != nil {
			t.Fatalf("second decode: %v", err)
		}
		if len(in) != 1 || string(in[0].Payload) != "hello" {
			t.Fatalf("second got frames=%d payload=%q, want one hello frame", len(in), func() []byte {
				if len(in) == 0 {
					return nil
				}
				return in[0].Payload
			}())
		}
		resp, err := frame.EncodeBatch(aead, clientID, []*frame.Frame{{
			SessionID: in[0].SessionID,
			Seq:       0,
			Payload:   []byte("ok"),
		}})
		if err != nil {
			t.Fatalf("second encode: %v", err)
		}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write(resp)
	}))
	defer second.Close()

	c, err := New(Config{
		ScriptURLs:     []string{first.URL, second.URL},
		ScriptAccounts: []string{"exhausted-account", "fresh-account"},
		AESKeyHex:      testKeyHex,
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	s := c.NewSession("example.com:443")
	if err := s.EnqueueTx([]byte("hello")); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	if didWork := c.pollOnce(context.Background()); !didWork {
		t.Fatal("pollOnce returned no work; want retry on second deployment to succeed")
	}
	if firstHits != 1 || secondHits != 1 {
		t.Fatalf("hits first=%d second=%d, want 1/1", firstHits, secondHits)
	}
	select {
	case got := <-s.RxChan:
		if string(got) != "ok" {
			t.Fatalf("rx = %q, want ok", got)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for response from alternate deployment")
	}
	c.endpointMu.Lock()
	firstUnavailable := c.endpointUnavailableLocked(&c.endpoints[0], time.Now())
	secondUnavailable := c.endpointUnavailableLocked(&c.endpoints[1], time.Now())
	c.endpointMu.Unlock()
	if !firstUnavailable {
		t.Fatal("quota deployment should be unavailable after quota payload")
	}
	if secondUnavailable {
		t.Fatal("alternate deployment should remain available")
	}
}

func TestCarrier_PollOnceTriesAllDeploymentsForDrainedTxPayload(t *testing.T) {
	aead, err := frame.NewCryptoFromHexKey(testKeyHex)
	if err != nil {
		t.Fatalf("crypto: %v", err)
	}
	var firstHits, secondHits, thirdHits int
	quotaHandler := func(counter *int) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			*counter = *counter + 1
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("<html>Service invoked too many times for one day: urlfetch.</html>"))
		}
	}
	first := httptest.NewServer(quotaHandler(&firstHits))
	defer first.Close()
	second := httptest.NewServer(quotaHandler(&secondHits))
	defer second.Close()
	third := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		thirdHits++
		body, _ := io.ReadAll(r.Body)
		clientID, in, err := frame.DecodeBatch(aead, body)
		if err != nil {
			t.Fatalf("third decode: %v", err)
		}
		if len(in) != 1 || string(in[0].Payload) != "payload-that-must-survive" {
			t.Fatalf("third got frames=%d, want preserved payload", len(in))
		}
		resp, err := frame.EncodeBatch(aead, clientID, []*frame.Frame{{
			SessionID: in[0].SessionID,
			Seq:       0,
			Payload:   []byte("survived"),
		}})
		if err != nil {
			t.Fatalf("third encode: %v", err)
		}
		_, _ = w.Write(resp)
	}))
	defer third.Close()

	c, err := New(Config{
		ScriptURLs:     []string{first.URL, second.URL, third.URL},
		ScriptAccounts: []string{"account-a", "account-b", "account-c"},
		AESKeyHex:      testKeyHex,
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	s := c.NewSession("example.com:443")
	if err := s.EnqueueTx([]byte("payload-that-must-survive")); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	if didWork := c.pollOnce(context.Background()); !didWork {
		t.Fatal("pollOnce returned no work; want third deployment to succeed")
	}
	if firstHits != 1 || secondHits != 1 || thirdHits != 1 {
		t.Fatalf("hits first=%d second=%d third=%d, want 1/1/1", firstHits, secondHits, thirdHits)
	}
	select {
	case got := <-s.RxChan:
		if string(got) != "survived" {
			t.Fatalf("rx = %q, want survived", got)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for third deployment response")
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
		{name: "loop guard", in: []byte("relay_loop_detected: RELAY_URLS must point to VPS"), want: true},
		{name: "apps script exception", in: []byte("Exception: Address unavailable"), want: true},
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

func TestClassifyRelayErrorBody_LoopGuard(t *testing.T) {
	reason, hard := classifyRelayErrorBody([]byte("relay_loop_detected: RELAY_URLS must point to your VPS"))
	if !hard {
		t.Fatal("loop guard error should be classified as hard")
	}
	if !strings.Contains(reason, "RELAY_URLS") {
		t.Fatalf("reason = %q, want RELAY_URLS guidance", reason)
	}
}

func TestCarrier_DirectBinarySkipsTextErrorHeuristic(t *testing.T) {
	aead, err := frame.NewCryptoFromHexKey(testKeyHex)
	if err != nil {
		t.Fatalf("crypto: %v", err)
	}
	response, err := frame.EncodeBatchBinary(aead, [frame.ClientIDLen]byte{1}, nil)
	if err != nil {
		t.Fatalf("EncodeBatchBinary: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(response)
	}))
	defer srv.Close()

	c, err := New(Config{
		TransportMode: "direct_post",
		ScriptURLs:    []string{srv.URL},
		AESKeyHex:     testKeyHex,
		BinaryDirect:  true,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	c.httpClients = []*http.Client{srv.Client()}

	_ = c.pollOnce(context.Background())

	c.endpointMu.Lock()
	failCount := c.endpoints[0].failCount
	c.endpointMu.Unlock()
	if failCount != 0 {
		t.Fatalf("direct binary response was treated as text error payload; failCount=%d", failCount)
	}
}

func TestReadRelayResponseBodyRejectsOverLimit(t *testing.T) {
	_, err := readRelayResponseBody(bytes.NewReader([]byte("abcdef")), -1, 5)
	if err == nil {
		t.Fatal("readRelayResponseBody succeeded for over-limit body")
	}
}

func TestReadRelayResponseBodyRejectsLargeContentLengthBeforeReading(t *testing.T) {
	_, err := readRelayResponseBody(carrierErrReader{}, 6, 5)
	if err == nil || !strings.Contains(err.Error(), "relay response too large") {
		t.Fatalf("readRelayResponseBody err = %v, want relay response too large", err)
	}
}

func TestReadRelayResponseBodyAllowsLimitSizedBody(t *testing.T) {
	got, err := readRelayResponseBody(bytes.NewReader([]byte("abcde")), int64(len("abcde")), 5)
	if err != nil {
		t.Fatalf("readRelayResponseBody: %v", err)
	}
	if string(got) != "abcde" {
		t.Fatalf("got %q, want abcde", got)
	}
}

type carrierErrReader struct{}

func (carrierErrReader) Read([]byte) (int, error) {
	return 0, errors.New("reader should not be touched")
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

func TestCarrier_UrgentKickBypassesCoalesce(t *testing.T) {
	c, err := New(Config{
		ScriptURLs:   []string{"http://example.invalid/exec"},
		AESKeyHex:    testKeyHex,
		CoalesceStep: 200 * time.Millisecond,
		CoalesceMax:  500 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	wakeCh := c.wake.C()
	start := time.Now()
	c.kickUrgent()
	select {
	case <-wakeCh:
	case <-time.After(50 * time.Millisecond):
		t.Fatal("urgent wake not received within 50ms")
	}
	if elapsed := time.Since(start); elapsed > 50*time.Millisecond {
		t.Fatalf("urgent kick took %v, want immediate wake", elapsed)
	}
}

func TestCarrier_UrgentKickCancelsPendingCoalesce(t *testing.T) {
	c, err := New(Config{
		ScriptURLs:   []string{"http://example.invalid/exec"},
		AESKeyHex:    testKeyHex,
		CoalesceStep: 200 * time.Millisecond,
		CoalesceMax:  500 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	wakeCh := c.wake.C()
	c.kick()
	c.kickUrgent()
	select {
	case <-wakeCh:
	case <-time.After(50 * time.Millisecond):
		t.Fatal("urgent wake did not cancel pending coalesce")
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

func TestCarrier_AdvancedPerformanceConfigResolvesRuntimeKnobs(t *testing.T) {
	c, err := New(Config{
		ScriptURLs:               []string{"http://example.invalid/exec"},
		AESKeyHex:                testKeyHex,
		IdleSlotsPerBucket:       2,
		WorkersPerEndpoint:       6,
		PollIdleSleep:            3 * time.Millisecond,
		EndpointBlacklistBaseTTL: 20 * time.Millisecond,
		EndpointBlacklistMaxTTL:  50 * time.Millisecond,
		MaxRequestBytesPreEncode: 512 * 1024,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if c.numWorkers != 7 {
		t.Fatalf("numWorkers = %d, want (6 + 2 - 1) * 1 = 7", c.numWorkers)
	}
	if got := c.idleBackoff(0); got != 3*time.Millisecond {
		t.Fatalf("idleBackoff(0) = %v, want 3ms", got)
	}
	if got := c.endpointBlacklistTTL(3); got != 50*time.Millisecond {
		t.Fatalf("endpointBlacklistTTL(3) = %v, want capped 50ms", got)
	}
	if c.maxRequestBytesPreEncode != 512*1024 {
		t.Fatalf("maxRequestBytesPreEncode = %d, want 512KiB", c.maxRequestBytesPreEncode)
	}
}

func TestEndpointBlacklistTTLWithJitterStaysBounded(t *testing.T) {
	const baseTTL = 100 * time.Millisecond
	const maxTTL = 500 * time.Millisecond

	for _, endpoint := range []string{
		"https://relay-a.example/tunnel",
		"https://relay-b.example/tunnel",
		"https://relay-c.example/tunnel",
	} {
		got := endpointBlacklistTTLWithJitter(baseTTL, maxTTL, endpoint, 2)
		if got < 80*time.Millisecond || got > 120*time.Millisecond {
			t.Fatalf("jittered ttl for %q = %v, want within +/-20%% of %v", endpoint, got, baseTTL)
		}
	}
}

func TestEndpointBlacklistTTLWithJitterSpreadsEndpointsAndCapsMax(t *testing.T) {
	const maxTTL = 500 * time.Millisecond
	a := endpointBlacklistTTLWithJitter(100*time.Millisecond, maxTTL, "https://relay-a.example/tunnel", 4)
	b := endpointBlacklistTTLWithJitter(100*time.Millisecond, maxTTL, "https://relay-b.example/tunnel", 4)
	if a == b {
		t.Fatalf("jittered ttl should differ for distinct endpoints, both were %v", a)
	}

	got := endpointBlacklistTTLWithJitter(maxTTL, maxTTL, "https://relay-c.example/tunnel", 8)
	if got > maxTTL {
		t.Fatalf("jittered ttl = %v, want capped at %v", got, maxTTL)
	}
}

func TestCarrier_PickRelayEndpointPrefersLowerObservedRTT(t *testing.T) {
	c, err := New(Config{
		ScriptURLs: []string{
			"http://slow.example/exec",
			"http://fast.example/exec",
		},
		AESKeyHex: testKeyHex,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	c.markEndpointSuccessWithRTT(0, 200*time.Millisecond, false)
	c.markEndpointSuccessWithRTT(1, 20*time.Millisecond, false)

	idx, url := c.pickRelayEndpoint()
	if idx != 1 || url != "http://fast.example/exec" {
		t.Fatalf("picked idx=%d url=%q, want fast endpoint", idx, url)
	}
}

func TestCarrier_PickRelayEndpointStillSkipsBlacklistedFastEndpoint(t *testing.T) {
	c, err := New(Config{
		ScriptURLs: []string{
			"http://slow.example/exec",
			"http://fast.example/exec",
		},
		AESKeyHex: testKeyHex,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	c.markEndpointSuccessWithRTT(0, 200*time.Millisecond, false)
	c.markEndpointSuccessWithRTT(1, 20*time.Millisecond, false)
	c.endpoints[1].blacklistedTill = time.Now().Add(time.Minute)

	idx, url := c.pickRelayEndpoint()
	if idx != 0 || url != "http://slow.example/exec" {
		t.Fatalf("picked idx=%d url=%q, want non-blacklisted endpoint", idx, url)
	}
}

func TestCarrier_PickRelayEndpointAvoidsNearQuotaEndpoint(t *testing.T) {
	c, err := New(Config{
		ScriptURLs: []string{
			"http://fast-near-quota.example/exec",
			"http://slower-fresh.example/exec",
		},
		ScriptAccounts: []string{"account-a", "account-b"},
		AESKeyHex:      testKeyHex,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	c.markEndpointSuccessWithRTT(0, 20*time.Millisecond, false)
	c.markEndpointSuccessWithRTT(1, 120*time.Millisecond, false)
	c.endpointMu.Lock()
	c.endpoints[0].scriptCount = 19000
	c.endpoints[0].scriptCountAt = time.Now()
	c.endpoints[1].scriptCount = 100
	c.endpoints[1].scriptCountAt = time.Now()
	c.endpointMu.Unlock()

	idx, url := c.pickRelayEndpoint()
	if idx != 1 || url != "http://slower-fresh.example/exec" {
		t.Fatalf("picked idx=%d url=%q, want lower-quota endpoint", idx, url)
	}
}

func TestCarrier_PickRelayEndpointSpreadsLoadAcrossHealthyDeployments(t *testing.T) {
	c, err := New(Config{
		ScriptURLs: []string{
			"http://busy.example/exec",
			"http://quiet.example/exec",
		},
		ScriptAccounts: []string{"account-a", "account-a"},
		AESKeyHex:      testKeyHex,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	c.endpointMu.Lock()
	c.endpoints[0].dailyCount = 900
	c.endpoints[0].rttEWMA = 100 * time.Millisecond
	c.endpoints[1].dailyCount = 10
	c.endpoints[1].rttEWMA = 150 * time.Millisecond
	c.endpointMu.Unlock()

	idx, url := c.pickRelayEndpoint()
	if idx != 1 || url != "http://quiet.example/exec" {
		t.Fatalf("picked idx=%d url=%q, want less-used endpoint", idx, url)
	}
}

func TestCarrier_AvailableRelayBucketCountIgnoresUnavailableAccounts(t *testing.T) {
	c, err := New(Config{
		ScriptURLs: []string{
			"http://a1.example/exec",
			"http://a2.example/exec",
			"http://b1.example/exec",
			"http://c1.example/exec",
		},
		ScriptAccounts: []string{"account-a", "account-a", "account-b", "account-c"},
		AESKeyHex:      testKeyHex,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	c.endpointMu.Lock()
	c.endpoints[0].blacklistedTill = time.Now().Add(time.Minute)
	c.endpoints[1].blacklistedTill = time.Now().Add(time.Minute)
	c.endpoints[2].quotaExhaustedUntil = time.Now().Add(time.Minute)
	c.endpointMu.Unlock()

	if got := c.availableRelayBucketCount(); got != 1 {
		t.Fatalf("availableRelayBucketCount = %d, want only account-c available", got)
	}
}

func TestCarrier_QuotaExhaustionSkipsEveryEndpointOnSameAccount(t *testing.T) {
	c, err := New(Config{
		ScriptURLs: []string{
			"http://a1.example/exec",
			"http://a2.example/exec",
			"http://b1.example/exec",
		},
		ScriptAccounts: []string{"account-a", "account-a", "account-b"},
		AESKeyHex:      testKeyHex,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	c.markEndpointQuotaExhausted(0)

	idx, url := c.pickRelayEndpoint()
	if idx != 2 || url != "http://b1.example/exec" {
		t.Fatalf("picked idx=%d url=%q, want endpoint from non-exhausted account-b", idx, url)
	}
}

func TestCarrier_PickRelayEndpointReturnsNoneWhenOnlyAccountExhausted(t *testing.T) {
	c, err := New(Config{
		ScriptURLs: []string{
			"http://a1.example/exec",
			"http://a2.example/exec",
		},
		ScriptAccounts: []string{"account-a", "account-a"},
		AESKeyHex:      testKeyHex,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	c.markEndpointQuotaExhausted(0)

	idx, url := c.pickRelayEndpoint()
	if idx != -1 || url != "" {
		t.Fatalf("picked idx=%d url=%q, want no endpoint while account quota is exhausted", idx, url)
	}
}

func TestCarrier_AccountQuotaPressureDoesNotDoubleCountScriptAndLocalCounts(t *testing.T) {
	now := time.Now()
	c := &Client{endpoints: []relayEndpoint{
		{
			url:           "http://a1.example/exec",
			account:       "account-a",
			dailyCount:    6000,
			dailyResetAt:  now.Add(time.Hour),
			scriptCount:   10000,
			scriptCountAt: now,
		},
		{
			url:           "http://a2.example/exec",
			account:       "account-a",
			dailyCount:    4000,
			dailyResetAt:  now.Add(time.Hour),
			scriptCount:   10000,
			scriptCountAt: now,
		},
	}}

	c.endpointMu.Lock()
	pressure := c.accountQuotaPressureLocked(now)["account-a"]
	c.endpointMu.Unlock()

	if pressure != 500 {
		t.Fatalf("quota pressure = %d permille, want 500; script and local counts should not be added together", pressure)
	}
}

func TestCarrier_PickRelayEndpointReturnsNoneWhenAllBlacklisted(t *testing.T) {
	c, err := New(Config{
		ScriptURLs: []string{
			"http://a.example/exec",
			"http://b.example/exec",
		},
		AESKeyHex: testKeyHex,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	c.endpointMu.Lock()
	for i := range c.endpoints {
		c.endpoints[i].blacklistedTill = time.Now().Add(time.Minute)
	}
	c.endpointMu.Unlock()

	idx, url := c.pickRelayEndpoint()
	if idx != -1 || url != "" {
		t.Fatalf("picked idx=%d url=%q, want no endpoint while all are blacklisted", idx, url)
	}
}

func TestCarrier_PollOnceDoesNotDrainTxWhileAllEndpointsBlacklisted(t *testing.T) {
	c, err := New(Config{
		ScriptURLs: []string{
			"http://a.example/exec",
			"http://b.example/exec",
		},
		AESKeyHex: testKeyHex,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	s := c.NewSession("example.com:443")
	s.EnqueueTx([]byte("still-pending"))
	c.endpointMu.Lock()
	for i := range c.endpoints {
		c.endpoints[i].blacklistedTill = time.Now().Add(time.Minute)
	}
	c.endpointMu.Unlock()

	if didWork := c.pollOnce(context.Background()); didWork {
		t.Fatal("pollOnce should not report work while every endpoint is blacklisted")
	}
	if !s.HasPendingTx() {
		t.Fatal("pollOnce drained TX despite having no usable endpoint")
	}
}
