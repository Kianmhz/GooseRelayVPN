package carrier

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/kianmhz/GooseRelayVPN/internal/frame"
	"github.com/kianmhz/GooseRelayVPN/internal/protocol"
	"github.com/kianmhz/GooseRelayVPN/internal/session"
)

const testKeyHex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func testBatchPlainLen(frames []*frame.Frame) int {
	n := 1 + frame.ClientIDLen + 2
	for _, f := range frames {
		n += 4 + f.EncodedLen()
	}
	return n
}

func TestCarrierEncodeBatchRecordsCompressionStats(t *testing.T) {
	aead, err := frame.NewCryptoFromHexKey(testKeyHex)
	if err != nil {
		t.Fatal(err)
	}
	c := &Client{aead: aead}
	frames := []*frame.Frame{{
		SessionID: [frame.SessionIDLen]byte{1},
		Payload:   bytes.Repeat([]byte("carrier-compressible-"), 128),
	}}

	if _, err := c.encodeBatch(frames); err != nil {
		t.Fatalf("encodeBatch: %v", err)
	}

	if got := c.stats.compressAttempted.Load(); got != 1 {
		t.Fatalf("compressAttempted = %d, want 1", got)
	}
	if got := c.stats.compressUsed.Load(); got != 1 {
		t.Fatalf("compressUsed = %d, want 1", got)
	}
	if got := c.stats.compressZstd.Load(); got != 1 {
		t.Fatalf("compressZstd = %d, want 1", got)
	}
	if c.stats.compressSaved.Load() == 0 {
		t.Fatal("compressSaved = 0, want saved bytes")
	}
	if c.stats.compressWireBytes.Load() == 0 || c.stats.compressRawBytes.Load() == 0 || c.stats.compressBodyBytes.Load() == 0 {
		t.Fatalf("compression byte counters missing: raw=%d body=%d wire=%d",
			c.stats.compressRawBytes.Load(), c.stats.compressBodyBytes.Load(), c.stats.compressWireBytes.Load())
	}
}

func TestCarrierCompressionStatsMap(t *testing.T) {
	c := &Client{}
	c.stats.compressAttempted.Add(2)
	c.stats.compressUsed.Add(1)
	c.stats.compressSkipped.Add(1)
	c.stats.compressRaw.Add(1)
	c.stats.compressZstd.Add(1)
	c.stats.compressRawBytes.Add(1000)
	c.stats.compressBodyBytes.Add(700)
	c.stats.compressWireBytes.Add(940)
	c.stats.compressSaved.Add(300)
	c.stats.compressLost.Add(12)

	stats := c.compressionStatsMap()
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

func TestCarrierDecodeBatchRejectsForeignClientID(t *testing.T) {
	aead, err := frame.NewCryptoFromHexKey(testKeyHex)
	if err != nil {
		t.Fatalf("crypto: %v", err)
	}
	c, err := New(Config{ScriptURLs: []string{"http://127.0.0.1:1/tunnel"}, AESKeyHex: testKeyHex})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	foreignID := c.clientID
	foreignID[0] ^= 0xff

	cases := []struct {
		name   string
		binary bool
		encode func() ([]byte, error)
	}{
		{
			name: "text",
			encode: func() ([]byte, error) {
				return frame.EncodeBatch(aead, foreignID, nil)
			},
		},
		{
			name:   "binary",
			binary: true,
			encode: func() ([]byte, error) {
				return frame.EncodeBatchBinary(aead, foreignID, nil)
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body, err := tc.encode()
			if err != nil {
				t.Fatalf("encode: %v", err)
			}
			c.binaryDirect = tc.binary
			if _, _, err := c.decodeBatch(body); err == nil {
				t.Fatal("decodeBatch accepted response for a different client ID")
			}
		})
	}
}

func TestShouldRunScriptStatsOnlyForFrontedAppsScriptEndpoints(t *testing.T) {
	cases := []struct {
		name        string
		useFronting bool
		endpoints   []relayEndpoint
		want        bool
	}{
		{
			name:        "apps script endpoint",
			useFronting: true,
			endpoints:   []relayEndpoint{{url: "https://script.google.com/macros/s/AKfycbx/exec"}},
			want:        true,
		},
		{
			name:        "direct post endpoint",
			useFronting: false,
			endpoints:   []relayEndpoint{{url: "http://127.0.0.1:8443/tunnel"}},
			want:        false,
		},
		{
			name:        "fronting without endpoints",
			useFronting: true,
			endpoints:   nil,
			want:        false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := shouldRunScriptStats(tc.useFronting, tc.endpoints); got != tc.want {
				t.Fatalf("shouldRunScriptStats(%v, endpoints=%d) = %v, want %v", tc.useFronting, len(tc.endpoints), got, tc.want)
			}
		})
	}
}

func TestBumpDailyCountOnlyCountsFrontedAppsScriptRequests(t *testing.T) {
	c := &Client{
		useFronting: false,
		endpoints:   []relayEndpoint{{url: "http://127.0.0.1:8443/tunnel"}},
	}
	c.bumpDailyCount(0)
	if got := c.endpoints[0].dailyCount; got != 0 {
		t.Fatalf("direct POST dailyCount = %d, want 0", got)
	}

	c.useFronting = true
	c.bumpDailyCount(0)
	if got := c.endpoints[0].dailyCount; got != 1 {
		t.Fatalf("Apps Script dailyCount = %d, want 1", got)
	}
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
		payload, err := protocol.EncodeVersionInfo("test-server", protocol.MaxFramePayload, []string{protocol.FeatureBinaryBatchV1})
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
	if !c.binaryDirect {
		t.Fatal("binary direct was not kept enabled after advertised feature")
	}
}

func TestCarrier_DiagnoseSendsFreshStartResetProbe(t *testing.T) {
	aead, err := frame.NewCryptoFromHexKey(testKeyHex)
	if err != nil {
		t.Fatalf("crypto: %v", err)
	}
	var gotProbe *protocol.VersionProbe
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		clientID, in, err := frame.DecodeBatch(aead, body)
		if err != nil {
			t.Fatalf("decode probe: %v", err)
		}
		if len(in) != 1 {
			t.Fatalf("probe frames = %d, want 1", len(in))
		}
		probe, ok := protocol.DecodeProbePayload(in[0].Payload)
		if !ok {
			t.Fatalf("probe payload was not a version probe: %q", string(in[0].Payload))
		}
		gotProbe = probe
		payload, err := protocol.EncodeVersionInfo("test-server", protocol.MaxFramePayload, []string{protocol.FeatureClientRunResetV1})
		if err != nil {
			t.Fatalf("version payload: %v", err)
		}
		respBody, err := frame.EncodeBatch(aead, clientID, []*frame.Frame{{
			SessionID: in[0].SessionID,
			Flags:     frame.FlagRST,
			Payload:   payload,
		}})
		if err != nil {
			t.Fatalf("encode response: %v", err)
		}
		_, _ = w.Write(respBody)
	}))
	defer srv.Close()

	c, err := New(Config{
		TransportMode:        "direct_post",
		ScriptURLs:           []string{srv.URL},
		AESKeyHex:            testKeyHex,
		ClientVersion:        "client-test",
		FreshStartReset:      true,
		ClientInstanceID:     "phone-main",
		ClientRunID:          "run-abc",
		DownstreamReplayMode: downstreamReplayModeOff,
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	if err := c.Diagnose(context.Background()); err != nil {
		t.Fatalf("Diagnose: %v", err)
	}
	if gotProbe == nil {
		t.Fatal("server did not receive probe")
	}
	if gotProbe.ClientInstanceID != "phone-main" || gotProbe.RunID != "run-abc" || !gotProbe.ResetPrevious {
		t.Fatalf("probe = %#v, want instance/run/reset fields", gotProbe)
	}
}

func TestCarrier_StreamHelloIncludesFreshStartResetProbe(t *testing.T) {
	aead, err := frame.NewCryptoFromHexKey(testKeyHex)
	if err != nil {
		t.Fatalf("crypto: %v", err)
	}
	c, err := New(Config{
		TransportMode:        "direct_stream",
		DirectStreamURLs:     []string{"ws://127.0.0.1:1/stream"},
		AESKeyHex:            testKeyHex,
		ClientVersion:        "client-test",
		FreshStartReset:      true,
		ClientInstanceID:     "phone-main",
		ClientRunID:          "run-abc",
		IdlePollMode:         idlePollModeAdaptive,
		BinaryDirect:         true,
		UseFronting:          false,
		ScriptURLs:           nil,
		ScriptAccounts:       nil,
		DownstreamReplayMode: downstreamReplayModeOff,
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	frames, err := c.streamHelloFrames()
	if err != nil {
		t.Fatalf("streamHelloFrames: %v", err)
	}
	if len(frames) != 1 {
		t.Fatalf("hello frames = %d, want 1 probe", len(frames))
	}
	body, err := c.encodeStreamBatch(frames)
	if err != nil {
		t.Fatalf("encode stream batch: %v", err)
	}
	_, decoded, err := frame.DecodeBatchBinary(aead, body)
	if err != nil {
		t.Fatalf("decode stream hello: %v", err)
	}
	if len(decoded) != 1 {
		t.Fatalf("decoded hello frames = %d, want 1", len(decoded))
	}
	probe, ok := protocol.DecodeProbePayload(decoded[0].Payload)
	if !ok {
		t.Fatalf("stream hello payload was not a probe: %q", string(decoded[0].Payload))
	}
	if probe.ClientInstanceID != "phone-main" || probe.RunID != "run-abc" || !probe.ResetPrevious {
		t.Fatalf("probe = %#v, want instance/run/reset fields", probe)
	}
}

func TestCarrier_DiagnoseDirectPostTextModeWorksWithOfficialServer(t *testing.T) {
	aead, err := frame.NewCryptoFromHexKey(testKeyHex)
	if err != nil {
		t.Fatalf("crypto: %v", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			t.Fatalf("direct_post diagnose must not use Apps Script GET probe")
		}
		if got := r.Header.Get("Content-Type"); got != "text/plain" {
			t.Fatalf("Content-Type = %q, want text/plain", got)
		}
		body, _ := io.ReadAll(r.Body)
		clientID, in, err := frame.DecodeBatch(aead, body)
		if err != nil {
			t.Fatalf("decode text probe: %v", err)
		}
		payload, err := protocol.EncodeVersionInfo("official-like-server", protocol.MaxFramePayload, nil)
		if err != nil {
			t.Fatalf("version payload: %v", err)
		}
		respBody, err := frame.EncodeBatch(aead, clientID, []*frame.Frame{{
			SessionID: in[0].SessionID,
			Flags:     frame.FlagRST,
			Payload:   payload,
		}})
		if err != nil {
			t.Fatalf("encode text response: %v", err)
		}
		_, _ = w.Write(respBody)
	}))
	defer srv.Close()

	c, err := New(Config{
		TransportMode: "direct_post",
		ScriptURLs:    []string{srv.URL},
		AESKeyHex:     testKeyHex,
		BinaryDirect:  false,
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	if err := c.Diagnose(context.Background()); err != nil {
		t.Fatalf("Diagnose: %v", err)
	}
	if c.binaryDirect {
		t.Fatal("binary direct enabled without advertised feature")
	}
}

func TestCarrier_DiagnoseDirectPostSwitchesToBinaryWhenAdvertised(t *testing.T) {
	aead, err := frame.NewCryptoFromHexKey(testKeyHex)
	if err != nil {
		t.Fatalf("crypto: %v", err)
	}
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqNum := requests.Add(1)
		body, _ := io.ReadAll(r.Body)
		switch reqNum {
		case 1:
			if got := r.Header.Get("Content-Type"); got != "text/plain" {
				t.Fatalf("diagnose Content-Type = %q, want text/plain compatibility probe", got)
			}
			clientID, in, err := frame.DecodeBatch(aead, body)
			if err != nil {
				t.Fatalf("decode text diagnose probe: %v", err)
			}
			payload, err := protocol.EncodeVersionInfo("binary-capable-server", protocol.MaxFramePayload, []string{protocol.FeatureBinaryBatchV1})
			if err != nil {
				t.Fatalf("version payload: %v", err)
			}
			respBody, err := frame.EncodeBatch(aead, clientID, []*frame.Frame{{
				SessionID: in[0].SessionID,
				Flags:     frame.FlagRST,
				Payload:   payload,
			}})
			if err != nil {
				t.Fatalf("encode text diagnose response: %v", err)
			}
			_, _ = w.Write(respBody)
		case 2:
			if got := r.Header.Get("Content-Type"); got != "application/octet-stream" {
				t.Fatalf("poll Content-Type = %q, want application/octet-stream after feature negotiation", got)
			}
			clientID, in, err := frame.DecodeBatchBinary(aead, body)
			if err != nil {
				t.Fatalf("decode binary poll: %v", err)
			}
			gotPayload := ""
			if len(in) > 0 {
				gotPayload = string(in[0].Payload)
			}
			if len(in) != 1 || gotPayload != "hello" {
				t.Fatalf("binary poll frames=%d payload=%q, want one hello frame", len(in), gotPayload)
			}
			respBody, err := frame.EncodeBatchBinary(aead, clientID, []*frame.Frame{{
				SessionID: in[0].SessionID,
				Seq:       0,
				Payload:   []byte("world"),
			}})
			if err != nil {
				t.Fatalf("encode binary poll response: %v", err)
			}
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = w.Write(respBody)
		default:
			t.Fatalf("unexpected request %d", reqNum)
		}
	}))
	defer srv.Close()

	c, err := New(Config{
		TransportMode: "direct_post",
		ScriptURLs:    []string{srv.URL},
		AESKeyHex:     testKeyHex,
		BinaryDirect:  false,
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	if err := c.Diagnose(context.Background()); err != nil {
		t.Fatalf("Diagnose: %v", err)
	}
	if !c.binaryDirect {
		t.Fatal("binary direct was not enabled after advertised feature")
	}
	s := c.NewSession("example.com:443")
	if err := s.EnqueueTx([]byte("hello")); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	if didWork := c.pollOnce(context.Background()); !didWork {
		t.Fatal("pollOnce returned no work; want binary direct poll to succeed")
	}
	select {
	case got := <-s.RxChan:
		if string(got) != "world" {
			t.Fatalf("rx = %q, want world", got)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for binary direct response")
	}
	if got := requests.Load(); got != 2 {
		t.Fatalf("requests = %d, want 2", got)
	}
}

func TestCarrier_DiagnoseEnablesDownstreamReplayWhenAdvertised(t *testing.T) {
	aead, err := frame.NewCryptoFromHexKey(testKeyHex)
	if err != nil {
		t.Fatalf("crypto: %v", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		clientID, in, err := frame.DecodeBatchBinary(aead, body)
		if err != nil {
			t.Fatalf("decode probe: %v", err)
		}
		payload, err := protocol.EncodeVersionInfo("test-server", protocol.MaxFramePayload, []string{protocol.FeatureDownstreamReplayV1})
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
		TransportMode:        "direct_post",
		ScriptURLs:           []string{srv.URL},
		AESKeyHex:            testKeyHex,
		BinaryDirect:         true,
		DownstreamReplayMode: "auto",
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	if err := c.Diagnose(context.Background()); err != nil {
		t.Fatalf("Diagnose: %v", err)
	}
	if !c.downstreamReplayActive.Load() {
		t.Fatal("downstream replay was not activated after advertised feature")
	}
}

func TestCarrier_DiagnoseKeepsDownstreamReplayOffWithoutFeature(t *testing.T) {
	aead, err := frame.NewCryptoFromHexKey(testKeyHex)
	if err != nil {
		t.Fatalf("crypto: %v", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		clientID, in, err := frame.DecodeBatchBinary(aead, body)
		if err != nil {
			t.Fatalf("decode probe: %v", err)
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
		TransportMode:        "direct_post",
		ScriptURLs:           []string{srv.URL},
		AESKeyHex:            testKeyHex,
		BinaryDirect:         true,
		DownstreamReplayMode: "auto",
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	if err := c.Diagnose(context.Background()); err != nil {
		t.Fatalf("Diagnose: %v", err)
	}
	if c.downstreamReplayActive.Load() {
		t.Fatal("downstream replay activated without advertised feature")
	}
}

func TestCarrier_DiagnoseQuarantinesQuotaEndpointAndSucceedsWithHealthyAlternate(t *testing.T) {
	aead, err := frame.NewCryptoFromHexKey(testKeyHex)
	if err != nil {
		t.Fatalf("crypto: %v", err)
	}
	quotaSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("Exception: Service invoked too many times for one day: urlfetch."))
	}))
	defer quotaSrv.Close()

	healthySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		clientID, in, err := frame.DecodeBatch(aead, body)
		if err != nil {
			t.Fatalf("decode probe: %v", err)
		}
		if len(in) != 1 {
			t.Fatalf("probe frames = %d, want 1", len(in))
		}
		payload, err := protocol.EncodeVersionInfo("healthy-server", protocol.MaxFramePayload, nil)
		if err != nil {
			t.Fatalf("version payload: %v", err)
		}
		respBody, err := frame.EncodeBatch(aead, clientID, []*frame.Frame{{
			SessionID: in[0].SessionID,
			Flags:     frame.FlagRST,
			Payload:   payload,
		}})
		if err != nil {
			t.Fatalf("encode response: %v", err)
		}
		_, _ = w.Write(respBody)
	}))
	defer healthySrv.Close()

	c, err := New(Config{
		ScriptURLs:     []string{quotaSrv.URL, healthySrv.URL},
		ScriptAccounts: []string{"quota-account", "healthy-account"},
		AESKeyHex:      testKeyHex,
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	if err := c.Diagnose(context.Background()); err != nil {
		t.Fatalf("Diagnose: %v", err)
	}
	idx, got := c.pickRelayEndpointForPoll(false)
	if idx != 1 || got != healthySrv.URL {
		t.Fatalf("next endpoint = %d %q, want healthy endpoint %q", idx, got, healthySrv.URL)
	}
}

func TestCarrier_DiagnoseSkipsSameAccountAfterQuotaFailure(t *testing.T) {
	aead, err := frame.NewCryptoFromHexKey(testKeyHex)
	if err != nil {
		t.Fatalf("crypto: %v", err)
	}
	quotaSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("Exception: Service invoked too many times for one day: urlfetch."))
	}))
	defer quotaSrv.Close()
	var sameAccountCalls atomic.Int32
	sameAccountSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sameAccountCalls.Add(1)
		_, _ = w.Write([]byte("Exception: Service invoked too many times for one day: urlfetch."))
	}))
	defer sameAccountSrv.Close()
	healthySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		clientID, in, err := frame.DecodeBatch(aead, body)
		if err != nil {
			t.Fatalf("decode probe: %v", err)
		}
		payload, err := protocol.EncodeVersionInfo("healthy-server", protocol.MaxFramePayload, nil)
		if err != nil {
			t.Fatalf("version payload: %v", err)
		}
		respBody, err := frame.EncodeBatch(aead, clientID, []*frame.Frame{{
			SessionID: in[0].SessionID,
			Flags:     frame.FlagRST,
			Payload:   payload,
		}})
		if err != nil {
			t.Fatalf("encode response: %v", err)
		}
		_, _ = w.Write(respBody)
	}))
	defer healthySrv.Close()

	c, err := New(Config{
		ScriptURLs:     []string{quotaSrv.URL, sameAccountSrv.URL, healthySrv.URL},
		ScriptAccounts: []string{"quota-account", "quota-account", "healthy-account"},
		AESKeyHex:      testKeyHex,
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	if err := c.Diagnose(context.Background()); err != nil {
		t.Fatalf("Diagnose: %v", err)
	}
	if got := sameAccountCalls.Load(); got != 0 {
		t.Fatalf("same-account endpoint was probed %d time(s) after account quota failure, want 0", got)
	}
	idx, got := c.pickRelayEndpointForPoll(false)
	if idx != 2 || got != healthySrv.URL {
		t.Fatalf("next endpoint = %d %q, want healthy endpoint %q", idx, got, healthySrv.URL)
	}
}

func TestCarrier_DiagnoseClassifiesHTTP429AsRateLimit(t *testing.T) {
	aead, err := frame.NewCryptoFromHexKey(testKeyHex)
	if err != nil {
		t.Fatalf("crypto: %v", err)
	}
	rateSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "too many requests", http.StatusTooManyRequests)
	}))
	defer rateSrv.Close()
	healthySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		clientID, in, err := frame.DecodeBatch(aead, body)
		if err != nil {
			t.Fatalf("decode probe: %v", err)
		}
		payload, err := protocol.EncodeVersionInfo("healthy-server", protocol.MaxFramePayload, nil)
		if err != nil {
			t.Fatalf("version payload: %v", err)
		}
		respBody, err := frame.EncodeBatch(aead, clientID, []*frame.Frame{{
			SessionID: in[0].SessionID,
			Flags:     frame.FlagRST,
			Payload:   payload,
		}})
		if err != nil {
			t.Fatalf("encode response: %v", err)
		}
		_, _ = w.Write(respBody)
	}))
	defer healthySrv.Close()

	c, err := New(Config{
		ScriptURLs:     []string{rateSrv.URL, healthySrv.URL},
		ScriptAccounts: []string{"rate-account", "healthy-account"},
		AESKeyHex:      testKeyHex,
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	if err := c.Diagnose(context.Background()); err != nil {
		t.Fatalf("Diagnose: %v", err)
	}
	line := c.endpointStatsLine()
	if !strings.Contains(line, "rate_limit=1") {
		t.Fatalf("endpoint stats = %q, want rate_limit=1", line)
	}
}

func TestCarrier_DrainAllEmitsDownstreamACKAfterRxAdvance(t *testing.T) {
	c, err := New(Config{
		TransportMode:        "direct_post",
		ScriptURLs:           []string{"http://127.0.0.1:1/tunnel"},
		AESKeyHex:            testKeyHex,
		BinaryDirect:         true,
		DownstreamReplayMode: "auto",
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	c.downstreamReplayActive.Store(true)

	s := c.NewSession("example.com:443")
	_, drainedIDs, _ := c.drainAll()
	c.releaseInFlight(drainedIDs)

	c.routeRx(&frame.Frame{SessionID: s.ID, Seq: 0, Payload: []byte("downstream")})
	if got := <-s.RxChan; string(got) != "downstream" {
		t.Fatalf("payload = %q", got)
	}

	frames := waitForCarrierDrainFrames(t, c, 1)
	if len(frames) != 1 || !frames[0].HasFlag(frame.FlagACK) {
		t.Fatalf("frames = %#v, want one ACK frame", frames)
	}
	if ack, ok := protocol.DecodeDownstreamACK(frames[0].Payload); !ok || ack != 1 {
		t.Fatalf("ACK payload = (%d,%v), want (1,true)", ack, ok)
	}
}

func TestCarrier_DrainAllPrependsDownstreamACKBeforeUploadFrames(t *testing.T) {
	c, err := New(Config{
		TransportMode:        "direct_post",
		ScriptURLs:           []string{"http://127.0.0.1:1/tunnel"},
		AESKeyHex:            testKeyHex,
		BinaryDirect:         true,
		DownstreamReplayMode: "auto",
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	c.downstreamReplayActive.Store(true)

	s := c.NewSession("example.com:443")
	_, drainedIDs, _ := c.drainAll()
	c.releaseInFlight(drainedIDs)

	c.routeRx(&frame.Frame{SessionID: s.ID, Seq: 0, Payload: []byte("downstream")})
	if got := <-s.RxChan; string(got) != "downstream" {
		t.Fatalf("payload = %q", got)
	}
	if err := s.EnqueueTx([]byte("upload")); err != nil {
		t.Fatalf("EnqueueTx: %v", err)
	}

	frames := waitForCarrierDrainFrames(t, c, 2)
	if len(frames) < 2 {
		t.Fatalf("frames = %d, want at least 2", len(frames))
	}
	if !frames[0].HasFlag(frame.FlagACK) {
		t.Fatalf("first frame = %#v, want ACK first", frames[0])
	}
	if frames[1].HasFlag(frame.FlagACK) || string(frames[1].Payload) != "upload" {
		t.Fatalf("second frame = %#v, want upload payload", frames[1])
	}
}

func TestCarrier_DrainAllForStreamDoesNotEmitDownstreamACK(t *testing.T) {
	c, err := New(Config{
		TransportMode:        "direct_post",
		ScriptURLs:           []string{"http://127.0.0.1:1/tunnel"},
		AESKeyHex:            testKeyHex,
		BinaryDirect:         true,
		DownstreamReplayMode: "auto",
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	c.downstreamReplayActive.Store(true)

	s := c.NewSession("example.com:443")
	_, drainedIDs, _ := c.drainAll()
	c.releaseInFlight(drainedIDs)

	c.routeRx(&frame.Frame{SessionID: s.ID, Seq: 0, Payload: []byte("stream-downstream")})
	if got := <-s.RxChan; string(got) != "stream-downstream" {
		t.Fatalf("payload = %q", got)
	}

	frames, _, _ := c.drainAllForStream()
	if len(frames) != 0 {
		t.Fatalf("stream drain frames = %#v, want no ACK frame", frames)
	}
	frames = waitForCarrierDrainFrames(t, c, 1)
	if len(frames) != 1 || !frames[0].HasFlag(frame.FlagACK) {
		t.Fatalf("post drain frames = %#v, want pending ACK preserved for POST", frames)
	}
}

func TestCarrier_WriteStreamKeepsSessionInFlightUntilWriteCompletes(t *testing.T) {
	c, err := New(Config{
		TransportMode:          "auto",
		ScriptURLs:             []string{"http://127.0.0.1:1/tunnel"},
		DirectStreamURLs:       []string{"ws://127.0.0.1:1/stream"},
		AESKeyHex:              testKeyHex,
		BinaryDirect:           true,
		StreamPingInterval:     time.Hour,
		StreamConnectTimeout:   time.Second,
		StreamReconnectBackoff: time.Second,
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	s := c.NewSession("stream.example:443")
	defer s.Stop()

	writer := &blockingStreamWriter{
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- c.writeStream(ctx, writer) }()

	select {
	case <-writer.started:
	case <-time.After(time.Second):
		t.Fatal("stream write did not start")
	}
	c.mu.Lock()
	inFlightDuringWrite := c.inFlight[s.ID]
	c.mu.Unlock()
	if !inFlightDuringWrite {
		t.Fatal("session was released from inFlight before stream write completed")
	}

	close(writer.release)
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		c.mu.Lock()
		inFlightAfterWrite := c.inFlight[s.ID]
		c.mu.Unlock()
		if !inFlightAfterWrite {
			cancel()
			<-done
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("session stayed inFlight after successful stream write")
}

type blockingStreamWriter struct {
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (w *blockingStreamWriter) Write(ctx context.Context, _ websocket.MessageType, _ []byte) error {
	w.once.Do(func() { close(w.started) })
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-w.release:
		return nil
	}
}

func (w *blockingStreamWriter) Ping(ctx context.Context) error {
	return ctx.Err()
}

func TestCarrier_DrainAllPeriodicallyRefreshesDownstreamACK(t *testing.T) {
	c, err := New(Config{
		TransportMode:        "direct_post",
		ScriptURLs:           []string{"http://127.0.0.1:1/tunnel"},
		AESKeyHex:            testKeyHex,
		BinaryDirect:         true,
		DownstreamReplayMode: "auto",
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	c.downstreamReplayActive.Store(true)

	s := c.NewSession("example.com:443")
	_, drainedIDs, _ := c.drainAll()
	c.releaseInFlight(drainedIDs)

	c.routeRx(&frame.Frame{SessionID: s.ID, Seq: 0, Payload: []byte("downstream")})
	if got := <-s.RxChan; string(got) != "downstream" {
		t.Fatalf("payload = %q", got)
	}
	frames := waitForCarrierDrainFrames(t, c, 1)
	if len(frames) != 1 || !frames[0].HasFlag(frame.FlagACK) {
		t.Fatalf("initial frames = %#v, want ACK", frames)
	}
	frames, _, _ = c.drainAll()
	if len(frames) != 0 {
		t.Fatalf("immediate refresh frames = %#v, want none", frames)
	}

	c.mu.Lock()
	c.ackLastSent[s.ID] = time.Now().Add(-downstreamACKRefreshInterval)
	c.mu.Unlock()
	frames = waitForCarrierDrainFrames(t, c, 1)
	if len(frames) != 1 || !frames[0].HasFlag(frame.FlagACK) {
		t.Fatalf("refreshed frames = %#v, want ACK", frames)
	}
	if ack, ok := protocol.DecodeDownstreamACK(frames[0].Payload); !ok || ack != 1 {
		t.Fatalf("refresh ACK payload = (%d,%v), want (1,true)", ack, ok)
	}
}

func TestCarrier_DrainAllReservesSlotForTxWhenACKsFillBatch(t *testing.T) {
	c, err := New(Config{
		TransportMode:        "direct_post",
		ScriptURLs:           []string{"http://127.0.0.1:1/tunnel"},
		AESKeyHex:            testKeyHex,
		BinaryDirect:         true,
		DownstreamReplayMode: "auto",
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	c.downstreamReplayActive.Store(true)

	expectedCap := maxDrainFramesPerBatchBusy
	c.mu.Lock()
	for i := 0; i < expectedCap; i++ {
		var id [frame.SessionIDLen]byte
		id[0] = byte(i + 1)
		s := session.New(id, "ack.example:443", false)
		defer s.Stop()
		c.sessions[id] = s
		c.ackLatest[id] = 1
		c.ackReady[id] = 1
	}
	c.mu.Unlock()

	tx := c.NewSession("upload.example:443")
	defer tx.Stop()
	if err := tx.EnqueueTx([]byte("upload")); err != nil {
		t.Fatalf("EnqueueTx: %v", err)
	}

	frames, drainedIDs, _ := c.drainAll()
	c.releaseInFlight(drainedIDs)
	if len(frames) != expectedCap {
		t.Fatalf("drained frames = %d, want %d", len(frames), expectedCap)
	}
	ackCount := 0
	nonACKCount := 0
	for _, f := range frames {
		if f.HasFlag(frame.FlagACK) {
			ackCount++
		} else {
			nonACKCount++
		}
	}
	if ackCount != expectedCap-1 || nonACKCount != 1 {
		t.Fatalf("ack/non-ack counts = %d/%d, want %d/1", ackCount, nonACKCount, expectedCap-1)
	}
}

func TestCarrier_MaxRequestBytesPreEncodeBoundsPlainBatch(t *testing.T) {
	const capBytes = 512 * 1024
	c, err := New(Config{
		TransportMode:            "direct_post",
		ScriptURLs:               []string{"http://127.0.0.1:1/tunnel"},
		AESKeyHex:                testKeyHex,
		BinaryDirect:             true,
		MaxRequestBytesPreEncode: capBytes,
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	s := c.NewSession("upload.example:443")
	defer s.Stop()
	if err := s.EnqueueTx(bytes.Repeat([]byte("x"), capBytes)); err != nil {
		t.Fatalf("EnqueueTx: %v", err)
	}

	frames, drainedIDs, _ := c.drainAll()
	c.releaseInFlight(drainedIDs)
	if len(frames) == 0 {
		t.Fatal("drainAll returned no frames")
	}
	if got := testBatchPlainLen(frames); got > capBytes {
		t.Fatalf("plain batch len = %d, want <= max_request_bytes_pre_encode %d", got, capBytes)
	}
}

func TestCarrier_RollbackRestoresDrainedDownstreamACK(t *testing.T) {
	c, err := New(Config{
		TransportMode:        "direct_post",
		ScriptURLs:           []string{"http://127.0.0.1:1/tunnel"},
		AESKeyHex:            testKeyHex,
		BinaryDirect:         true,
		DownstreamReplayMode: "auto",
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	c.downstreamReplayActive.Store(true)

	s := c.NewSession("ack.example:443")
	defer s.Stop()
	_, drainedIDs, _ := c.drainAll()
	c.releaseInFlight(drainedIDs)
	c.mu.Lock()
	c.ackLatest[s.ID] = 7
	c.ackReady[s.ID] = 7
	c.mu.Unlock()

	frames := waitForCarrierDrainFrames(t, c, 1)
	if len(frames) != 1 || !frames[0].HasFlag(frame.FlagACK) {
		t.Fatalf("frames = %#v, want one ACK frame", frames)
	}
	if ack, ok := protocol.DecodeDownstreamACK(frames[0].Payload); !ok || ack != 7 {
		t.Fatalf("ACK payload = (%d,%v), want (7,true)", ack, ok)
	}

	c.rollbackDrainedBatch(frames, nil)
	frames = waitForCarrierDrainFrames(t, c, 1)
	if len(frames) != 1 || !frames[0].HasFlag(frame.FlagACK) {
		t.Fatalf("restored frames = %#v, want one ACK frame", frames)
	}
	if ack, ok := protocol.DecodeDownstreamACK(frames[0].Payload); !ok || ack != 7 {
		t.Fatalf("restored ACK payload = (%d,%v), want (7,true)", ack, ok)
	}
}

func TestCarrier_FailDrainedBatchRestoresACKOnlyBatch(t *testing.T) {
	c, err := New(Config{
		TransportMode:        "direct_post",
		ScriptURLs:           []string{"http://127.0.0.1:1/tunnel"},
		AESKeyHex:            testKeyHex,
		BinaryDirect:         true,
		DownstreamReplayMode: "auto",
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	c.downstreamReplayActive.Store(true)

	s := c.NewSession("ack.example:443")
	defer s.Stop()
	_, drainedIDs, _ := c.drainAll()
	c.releaseInFlight(drainedIDs)
	c.mu.Lock()
	c.ackLatest[s.ID] = 9
	c.ackReady[s.ID] = 9
	c.mu.Unlock()

	frames := waitForCarrierDrainFrames(t, c, 1)
	if len(frames) != 1 || !frames[0].HasFlag(frame.FlagACK) {
		t.Fatalf("frames = %#v, want one ACK frame", frames)
	}
	c.mu.Lock()
	_, stillReady := c.ackReady[s.ID]
	c.mu.Unlock()
	if stillReady {
		t.Fatal("ACK stayed ready after drain; test setup failed")
	}

	c.failDrainedBatch(frames, nil, "ack-only POST failed")

	frames = waitForCarrierDrainFrames(t, c, 1)
	if len(frames) != 1 || !frames[0].HasFlag(frame.FlagACK) {
		t.Fatalf("restored frames = %#v, want one ACK frame", frames)
	}
	if ack, ok := protocol.DecodeDownstreamACK(frames[0].Payload); !ok || ack != 9 {
		t.Fatalf("restored ACK payload = (%d,%v), want (9,true)", ack, ok)
	}
}

func TestCarrier_ACKRollbackRestoresOnlyFailedBatchACKs(t *testing.T) {
	c, err := New(Config{
		TransportMode:        "direct_post",
		ScriptURLs:           []string{"http://127.0.0.1:1/tunnel"},
		AESKeyHex:            testKeyHex,
		DownstreamReplayMode: "auto",
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	c.downstreamReplayActive.Store(true)
	first := c.NewSession("first.example:443")
	second := c.NewSession("second.example:443")
	defer first.Stop()
	defer second.Stop()

	now := time.Now()
	c.mu.Lock()
	c.ackLatest[first.ID] = 5
	c.ackLatest[second.ID] = 7
	c.ackLastSent[first.ID] = now
	c.ackLastSent[second.ID] = now
	c.mu.Unlock()

	c.rollbackDrainedBatch([]*frame.Frame{{
		SessionID: first.ID,
		Flags:     frame.FlagACK,
		Payload:   protocol.EncodeDownstreamACK(5),
	}}, nil)

	c.mu.Lock()
	defer c.mu.Unlock()
	if got := c.ackReady[first.ID]; got != 5 {
		t.Fatalf("first ackReady = %d, want restored 5", got)
	}
	if _, ok := c.ackReady[second.ID]; ok {
		t.Fatal("second ackReady was restored even though its ACK was not in the failed batch")
	}
	if _, ok := c.ackLastSent[first.ID]; ok {
		t.Fatal("first ackLastSent still present after rollback")
	}
	if _, ok := c.ackLastSent[second.ID]; !ok {
		t.Fatal("second ackLastSent was cleared even though its ACK was not in the failed batch")
	}
}

func TestCarrier_PollOnceCountsACKOnlyPOSTs(t *testing.T) {
	aead, err := frame.NewCryptoFromHexKey(testKeyHex)
	if err != nil {
		t.Fatalf("crypto: %v", err)
	}
	var posts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		posts.Add(1)
		body, _ := io.ReadAll(r.Body)
		clientID, frames, err := frame.DecodeBatchBinary(aead, body)
		if err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if len(frames) == 0 {
			t.Fatalf("request frames = %#v, want ACK frames", frames)
		}
		for _, f := range frames {
			if !f.HasFlag(frame.FlagACK) {
				t.Fatalf("request frames = %#v, want only ACK frames", frames)
			}
		}
		if ack, ok := protocol.DecodeDownstreamACK(frames[0].Payload); !ok || ack != 9 {
			t.Fatalf("ACK payload = (%d,%v), want (9,true)", ack, ok)
		}
		respBody, err := frame.EncodeBatchBinary(aead, clientID, nil)
		if err != nil {
			t.Fatalf("encode response: %v", err)
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(respBody)
	}))
	defer srv.Close()

	c, err := New(Config{
		TransportMode:        "direct_post",
		ScriptURLs:           []string{srv.URL},
		AESKeyHex:            testKeyHex,
		BinaryDirect:         true,
		DownstreamReplayMode: "auto",
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	c.downstreamReplayActive.Store(true)

	s := c.NewSession("ack.example:443")
	defer s.Stop()
	_, drainedIDs, _ := c.drainAll()
	c.releaseInFlight(drainedIDs)
	c.mu.Lock()
	c.ackLatest[s.ID] = 9
	c.ackReady[s.ID] = 9
	c.mu.Unlock()

	if didWork := c.pollOnce(context.Background()); !didWork {
		t.Fatal("pollOnce returned no work for ACK-only POST")
	}
	if got := posts.Load(); got != 1 {
		t.Fatalf("posts = %d, want 1", got)
	}
	if got := c.stats.ackOnlyPosts.Load(); got != 1 {
		t.Fatalf("ackOnlyPosts = %d, want 1", got)
	}
	if got := c.stats.ackOnlyFrames.Load(); got != 1 {
		t.Fatalf("ackOnlyFrames = %d, want 1", got)
	}
}

func TestCarrier_ACKOnlyPOSTUsesIdleSlotLimit(t *testing.T) {
	aead, err := frame.NewCryptoFromHexKey(testKeyHex)
	if err != nil {
		t.Fatalf("crypto: %v", err)
	}

	blockedRequests := make(chan int, 2)
	releaseBlocked := []chan struct{}{make(chan struct{}), make(chan struct{})}
	var releaseOnce [2]sync.Once
	t.Cleanup(func() {
		for i := range releaseBlocked {
			i := i
			releaseOnce[i].Do(func() { close(releaseBlocked[i]) })
		}
	})
	var posts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		post := posts.Add(1)
		body, _ := io.ReadAll(r.Body)
		clientID, frames, err := frame.DecodeBatchBinary(aead, body)
		if err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if len(frames) == 0 {
			t.Fatalf("request frames = %#v, want ACK frames", frames)
		}
		for _, f := range frames {
			if !f.HasFlag(frame.FlagACK) {
				t.Fatalf("request frames = %#v, want only ACK frames", frames)
			}
		}
		if post <= 2 {
			blockedRequests <- int(post)
			<-releaseBlocked[post-1]
		}
		respBody, err := frame.EncodeBatchBinary(aead, clientID, nil)
		if err != nil {
			t.Fatalf("encode response: %v", err)
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(respBody)
	}))
	defer srv.Close()

	c, err := New(Config{
		TransportMode:        "direct_post",
		ScriptURLs:           []string{srv.URL},
		ScriptAccounts:       []string{"acct-a"},
		AESKeyHex:            testKeyHex,
		BinaryDirect:         true,
		DownstreamReplayMode: "auto",
		IdleSlotsPerBucket:   1,
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	c.httpClients = []*http.Client{srv.Client()}
	c.downstreamReplayActive.Store(true)

	first := c.NewSession("ack1.example:443")
	second := c.NewSession("ack2.example:443")
	third := c.NewSession("ack3.example:443")
	defer first.Stop()
	defer second.Stop()
	defer third.Stop()
	_, drainedIDs, _ := c.drainAll()
	c.releaseInFlight(drainedIDs)

	c.mu.Lock()
	c.ackLatest[first.ID] = 1
	c.ackReady[first.ID] = 1
	c.mu.Unlock()

	done := make(chan bool, 1)
	go func() {
		done <- c.pollOnce(context.Background())
	}()

	select {
	case <-blockedRequests:
	case <-time.After(time.Second):
		t.Fatal("first ACK-only POST did not start")
	}

	c.mu.Lock()
	c.ackLatest[second.ID] = 1
	c.ackReady[second.ID] = 1
	c.mu.Unlock()

	if didWork := c.pollOnce(context.Background()); didWork {
		t.Fatal("second ACK-only poll bypassed one-slot account limit")
	}
	if got := posts.Load(); got != 1 {
		t.Fatalf("posts while first slot busy = %d, want 1", got)
	}

	releaseOnce[0].Do(func() { close(releaseBlocked[0]) })
	select {
	case didWork := <-done:
		if !didWork {
			t.Fatal("first ACK-only poll returned no work")
		}
	case <-time.After(time.Second):
		t.Fatal("first ACK-only poll did not finish")
	}

	secondDone := make(chan bool, 1)
	go func() {
		secondDone <- c.pollOnce(context.Background())
	}()

	select {
	case <-blockedRequests:
	case <-time.After(time.Second):
		t.Fatal("second ACK-only POST did not start after first slot released")
	}

	c.mu.Lock()
	c.ackLatest[third.ID] = 1
	c.ackReady[third.ID] = 1
	c.mu.Unlock()

	if didWork := c.pollOnce(context.Background()); didWork {
		t.Fatal("third ACK-only poll bypassed one-slot account limit")
	}
	if got := posts.Load(); got != 2 {
		t.Fatalf("posts while second slot busy = %d, want 2", got)
	}

	releaseOnce[1].Do(func() { close(releaseBlocked[1]) })
	select {
	case didWork := <-secondDone:
		if !didWork {
			t.Fatal("second ACK-only poll returned no work")
		}
	case <-time.After(time.Second):
		t.Fatal("second ACK-only poll did not finish")
	}

	if didWork := c.pollOnce(context.Background()); !didWork {
		t.Fatal("third ACK was not restored after idle slot rejection")
	}
	if got := posts.Load(); got != 3 {
		t.Fatalf("posts after slot released = %d, want 3", got)
	}
}

func TestCarrier_FailDrainedBatchRestoresACKFromMixedBatch(t *testing.T) {
	c, err := New(Config{
		TransportMode:        "direct_post",
		ScriptURLs:           []string{"http://127.0.0.1:1/tunnel"},
		AESKeyHex:            testKeyHex,
		BinaryDirect:         true,
		DownstreamReplayMode: "auto",
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	c.downstreamReplayActive.Store(true)

	ackSession := c.NewSession("ack.example:443")
	defer ackSession.Stop()
	_, drainedIDs, _ := c.drainAll()
	c.releaseInFlight(drainedIDs)
	c.mu.Lock()
	c.ackLatest[ackSession.ID] = 11
	c.ackReady[ackSession.ID] = 11
	c.mu.Unlock()

	uploadSession := c.NewSession("upload.example:443")
	defer uploadSession.Stop()
	if err := uploadSession.EnqueueTx([]byte("upload")); err != nil {
		t.Fatalf("EnqueueTx: %v", err)
	}

	frames := waitForCarrierDrainFrames(t, c, 2)
	var uploadDrained [][frame.SessionIDLen]byte
	for _, f := range frames {
		if f.SessionID == uploadSession.ID && !f.HasFlag(frame.FlagACK) {
			uploadDrained = append(uploadDrained, uploadSession.ID)
			break
		}
	}
	if len(uploadDrained) == 0 {
		t.Fatalf("frames = %#v, want an upload frame", frames)
	}

	c.failDrainedBatch(frames, uploadDrained, "mixed ACK/upload POST failed")

	c.mu.Lock()
	_, uploadAlive := c.sessions[uploadSession.ID]
	c.mu.Unlock()
	if uploadAlive {
		t.Fatal("upload session stayed alive after failed drained upload batch")
	}
	frames = waitForCarrierDrainFrames(t, c, 1)
	if len(frames) != 1 || !frames[0].HasFlag(frame.FlagACK) {
		t.Fatalf("restored frames = %#v, want one ACK frame", frames)
	}
	if ack, ok := protocol.DecodeDownstreamACK(frames[0].Payload); !ok || ack != 11 {
		t.Fatalf("restored ACK payload = (%d,%v), want (11,true)", ack, ok)
	}
}

func waitForCarrierDrainFrames(t *testing.T, c *Client, wantAtLeast int) []*frame.Frame {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		frames, _, _ := c.drainAll()
		if len(frames) >= wantAtLeast {
			return frames
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timed out waiting for at least %d drained frame(s)", wantAtLeast)
	return nil
}

func TestCarrier_AbortAllSessionsClearsDebugStarts(t *testing.T) {
	c, err := New(Config{
		ScriptURLs: []string{"http://127.0.0.1:1/tunnel"},
		AESKeyHex:  testKeyHex,
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	s1 := c.NewSession("one.example:443")
	s2 := c.NewSession("two.example:443")

	if got := c.abortAllSessions("test outage"); got != 2 {
		t.Fatalf("abortAllSessions = %d, want 2", got)
	}
	for _, id := range [][frame.SessionIDLen]byte{s1.ID, s2.ID} {
		if _, ok := c.debugStarts.Load(id); ok {
			t.Fatalf("debugStarts still contains session %x after abortAllSessions", id[:4])
		}
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

func TestCarrier_UpdateEndpointsClearsQuotaWhenAccountLabelChanges(t *testing.T) {
	url := "https://script.google.com/macros/s/old/exec"
	c, err := New(Config{
		ScriptURLs:     []string{url},
		ScriptAccounts: []string{"old-account"},
		AESKeyHex:      testKeyHex,
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	c.markEndpointQuotaExhausted(0)

	c.UpdateEndpoints([]string{url}, []string{"new-account"})

	c.endpointMu.Lock()
	defer c.endpointMu.Unlock()
	if !c.endpoints[0].quotaExhaustedUntil.IsZero() {
		t.Fatalf("quotaExhaustedUntil = %v, want cleared after account relabel", c.endpoints[0].quotaExhaustedUntil)
	}
	if !c.endpoints[0].blacklistedTill.IsZero() {
		t.Fatalf("blacklistedTill = %v, want quota blacklist cleared after account relabel", c.endpoints[0].blacklistedTill)
	}
}

func TestCarrier_UnlabeledEndpointSuccessDoesNotClearPeerQuota(t *testing.T) {
	resetAt := time.Now().Add(time.Hour)
	c := &Client{endpoints: []relayEndpoint{
		{
			url:                 "https://script.google.com/macros/s/quota/exec",
			quotaExhaustedUntil: resetAt,
			blacklistedTill:     resetAt,
		},
		{
			url: "https://script.google.com/macros/s/healthy/exec",
		},
	}}

	c.markEndpointSuccess(1)

	if !c.endpoints[0].quotaExhaustedUntil.Equal(resetAt) {
		t.Fatalf("unlabeled quota endpoint was cleared: %v", c.endpoints[0].quotaExhaustedUntil)
	}
}

func TestShortScriptKeyLabelsDirectRelayURL(t *testing.T) {
	got := shortScriptKey("http://127.0.0.1:8443/tunnel")
	if got == "(unknown)" || got == "" {
		t.Fatalf("shortScriptKey direct URL = %q, want useful endpoint label", got)
	}
	if !strings.Contains(got, "127.0.0.1") {
		t.Fatalf("shortScriptKey direct URL = %q, want host in label", got)
	}
}

func TestShortScriptKeyRedactsDirectURLUserinfoPathAndQuery(t *testing.T) {
	got := shortScriptKey("https://user:secret@example.com:8443/s/private/token/path?token=abc123")
	if got != "example.com:8443" {
		t.Fatalf("shortScriptKey = %q, want only host:port", got)
	}
	if strings.Contains(got, "secret") || strings.Contains(got, "token") || strings.Contains(got, "private") {
		t.Fatalf("shortScriptKey leaked direct URL sensitive details: %q", got)
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

func TestCarrier_RelayEndpointOutageUsesShorterGraceThanLocalOffline(t *testing.T) {
	c, err := New(Config{
		ScriptURLs:              []string{"https://script.google.com/macros/s/a/exec"},
		AESKeyHex:               testKeyHex,
		EndpointOutageGrace:     5 * time.Minute,
		EndpointBlacklistMaxTTL: time.Hour,
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	s := c.NewSession("example.com:443")

	c.endpointMu.Lock()
	c.endpoints[0].blacklistedTill = time.Now().Add(time.Hour)
	c.endpoints[0].localNetworkOffline = false
	c.endpointMu.Unlock()
	c.endpointOutageStarted = time.Now().Add(-relayEndpointOutageGraceMax - time.Millisecond)

	if closed := c.closeSessionsIfAllEndpointsBlacklisted("test"); !closed {
		t.Fatal("relay-side outage did not close after the shorter relay grace")
	}
	if _, ok := <-s.RxChan; ok {
		t.Fatal("session RxChan should close after relay-side outage grace")
	}
}

func TestCarrier_QuotaEndpointWithStaleLocalOfflineUsesRelayGrace(t *testing.T) {
	c, err := New(Config{
		ScriptURLs:              []string{"https://script.google.com/macros/s/a/exec"},
		AESKeyHex:               testKeyHex,
		EndpointOutageGrace:     5 * time.Minute,
		EndpointBlacklistMaxTTL: time.Hour,
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	s := c.NewSession("example.com:443")

	now := time.Now()
	c.endpointMu.Lock()
	c.endpoints[0].blacklistedTill = now.Add(time.Hour)
	c.endpoints[0].quotaExhaustedUntil = now.Add(time.Hour)
	c.endpoints[0].localNetworkOffline = true
	c.endpointMu.Unlock()
	c.endpointOutageStarted = now.Add(-relayEndpointOutageGraceMax - time.Millisecond)

	if closed := c.closeSessionsIfAllEndpointsBlacklisted("test"); !closed {
		t.Fatal("quota endpoint with stale local-offline flag used local-network grace")
	}
	if _, ok := <-s.RxChan; ok {
		t.Fatal("session RxChan should close after relay-side outage grace")
	}
}

func TestCarrier_LocalNetworkOutageKeepsConfiguredGrace(t *testing.T) {
	c, err := New(Config{
		ScriptURLs:              []string{"https://script.google.com/macros/s/a/exec"},
		AESKeyHex:               testKeyHex,
		EndpointOutageGrace:     5 * time.Minute,
		EndpointBlacklistMaxTTL: time.Hour,
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	s := c.NewSession("example.com:443")

	c.endpointMu.Lock()
	c.endpoints[0].blacklistedTill = time.Now().Add(time.Hour)
	c.endpoints[0].localNetworkOffline = true
	c.endpointMu.Unlock()
	c.endpointOutageStarted = time.Now().Add(-relayEndpointOutageGraceMax - time.Millisecond)

	if closed := c.closeSessionsIfAllEndpointsBlacklisted("test"); closed {
		t.Fatal("local network outage used shorter relay grace instead of configured grace")
	}
	select {
	case _, ok := <-s.RxChan:
		if !ok {
			t.Fatal("session closed before configured local network outage grace")
		}
	default:
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

func TestCarrier_PollOnceRollsBackAppsScriptHTTPStatusFailure(t *testing.T) {
	aead, err := frame.NewCryptoFromHexKey(testKeyHex)
	if err != nil {
		t.Fatalf("crypto: %v", err)
	}

	var (
		mu           sync.Mutex
		hits         int
		secondFrames []*frame.Frame
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits++
		hit := hits
		mu.Unlock()

		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("ReadAll: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if hit == 1 {
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte("<!doctype html><html><body>not found</body></html>"))
			return
		}

		clientID, frames, err := frame.DecodeBatch(aead, body)
		if err != nil {
			t.Errorf("DecodeBatch: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		mu.Lock()
		secondFrames = append(secondFrames[:0], frames...)
		mu.Unlock()

		resp, err := frame.EncodeBatch(aead, clientID, nil)
		if err != nil {
			t.Errorf("EncodeBatch: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write(resp)
	}))
	defer srv.Close()

	c, err := New(Config{ScriptURLs: []string{srv.URL}, AESKeyHex: testKeyHex})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	c.httpClients = []*http.Client{srv.Client()}
	c.useFronting = true

	s := c.NewSession("rollback.example:443")
	defer s.Stop()
	if err := s.EnqueueTx([]byte("hello")); err != nil {
		t.Fatalf("EnqueueTx: %v", err)
	}

	if didWork := c.pollOnce(context.Background()); didWork {
		t.Fatal("first failed poll reported work")
	}
	select {
	case _, ok := <-s.RxChan:
		if !ok {
			t.Fatal("session was aborted after Apps Script wrapper-level HTTP failure")
		}
	default:
	}

	c.markEndpointSuccess(0)
	if didWork := c.pollOnce(context.Background()); !didWork {
		t.Fatal("second poll did not resend rolled-back frames")
	}

	mu.Lock()
	defer mu.Unlock()
	if hits != 2 {
		t.Fatalf("hits = %d, want 2", hits)
	}
	if len(secondFrames) == 0 {
		t.Fatal("second request had no frames; drained TX was not restored")
	}
	if string(secondFrames[0].Payload) != "hello" {
		t.Fatalf("resent payload = %q, want hello", secondFrames[0].Payload)
	}
}

func TestCarrier_PollOnceRollsBackAppsScriptSoftNonBatchFailure(t *testing.T) {
	aead, err := frame.NewCryptoFromHexKey(testKeyHex)
	if err != nil {
		t.Fatalf("crypto: %v", err)
	}

	var (
		mu           sync.Mutex
		hits         int
		secondFrames []*frame.Frame
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits++
		hit := hits
		mu.Unlock()

		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("ReadAll: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if hit == 1 {
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("upstream fetch error: Exception: Address unavailable"))
			return
		}

		clientID, frames, err := frame.DecodeBatch(aead, body)
		if err != nil {
			t.Errorf("DecodeBatch: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		mu.Lock()
		secondFrames = append(secondFrames[:0], frames...)
		mu.Unlock()

		resp, err := frame.EncodeBatch(aead, clientID, nil)
		if err != nil {
			t.Errorf("EncodeBatch: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write(resp)
	}))
	defer srv.Close()

	c, err := New(Config{ScriptURLs: []string{srv.URL}, AESKeyHex: testKeyHex})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	c.httpClients = []*http.Client{srv.Client()}
	c.useFronting = true

	s := c.NewSession("rollback.example:443")
	defer s.Stop()
	if err := s.EnqueueTx([]byte("hello")); err != nil {
		t.Fatalf("EnqueueTx: %v", err)
	}

	if didWork := c.pollOnce(context.Background()); didWork {
		t.Fatal("first failed poll reported work")
	}
	select {
	case _, ok := <-s.RxChan:
		if !ok {
			t.Fatal("session was aborted after soft Apps Script non-batch failure")
		}
	default:
	}

	c.markEndpointSuccess(0)
	if didWork := c.pollOnce(context.Background()); !didWork {
		t.Fatal("second poll did not resend rolled-back frames")
	}

	mu.Lock()
	defer mu.Unlock()
	if hits != 2 {
		t.Fatalf("hits = %d, want 2", hits)
	}
	if len(secondFrames) == 0 {
		t.Fatal("second request had no frames; drained TX was not restored")
	}
	if string(secondFrames[0].Payload) != "hello" {
		t.Fatalf("resent payload = %q, want hello", secondFrames[0].Payload)
	}
}

func TestCarrier_EndpointStatsIncludesFailureReasons(t *testing.T) {
	nonBatch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<!doctype html><html><body>deployment is stale</body></html>"))
	}))
	defer nonBatch.Close()

	c, err := New(Config{ScriptURLs: []string{nonBatch.URL}, AESKeyHex: testKeyHex})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	c.httpClients = []*http.Client{nonBatch.Client()}

	_ = c.pollOnce(context.Background())
	line := c.endpointStatsLine()
	if !strings.Contains(line, "reasons={non_batch=1}") {
		t.Fatalf("endpoint stats = %q, want non_batch failure reason", line)
	}
	items := c.endpointStatsItems()
	if len(items) != 1 {
		t.Fatalf("endpointStatsItems len = %d, want 1", len(items))
	}
	reasons, ok := items[0]["reasons"].(map[string]uint64)
	if !ok || reasons["non_batch"] != 1 {
		t.Fatalf("endpointStatsItems reasons = %#v, want non_batch=1", items[0]["reasons"])
	}

	c.httpClients = []*http.Client{{
		Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return nil, errors.New("net/http: TLS handshake timeout")
		}),
	}}
	c.markEndpointSuccess(0)
	_ = c.pollOnce(context.Background())
	line = c.endpointStatsLine()
	if !strings.Contains(line, "local_offline=1") {
		t.Fatalf("endpoint stats = %q, want local_offline failure reason", line)
	}
}

func TestCarrier_ReceiveAbortStatsLine(t *testing.T) {
	c, err := New(Config{ScriptURLs: []string{"http://relay.example/exec"}, AESKeyHex: testKeyHex})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	c.recordReceiveAbort("rx_reorder_overflow")
	c.recordReceiveAbort("rx_inbox_timeout")
	c.recordReceiveAbort("unexpected_abort")

	line := c.receiveAbortStatsLine()
	for _, want := range []string{
		"rx_inbox_timeout=1",
		"rx_reorder_overflow=1",
		"other=1",
	} {
		if !strings.Contains(line, want) {
			t.Fatalf("receive abort stats = %q, want %s", line, want)
		}
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

func TestCarrier_PollOnceHTTP403DoesNotQuarantineSameAccountAlternate(t *testing.T) {
	aead, err := frame.NewCryptoFromHexKey(testKeyHex)
	if err != nil {
		t.Fatalf("crypto: %v", err)
	}
	var firstHits, secondHits int
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		firstHits++
		w.WriteHeader(http.StatusForbidden)
	}))
	defer first.Close()
	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		secondHits++
		body, _ := io.ReadAll(r.Body)
		clientID, in, err := frame.DecodeBatch(aead, body)
		if err != nil {
			t.Fatalf("second decode: %v", err)
		}
		resp, err := frame.EncodeBatch(aead, clientID, []*frame.Frame{{
			SessionID: in[0].SessionID,
			Seq:       0,
			Payload:   []byte("ok"),
		}})
		if err != nil {
			t.Fatalf("second encode: %v", err)
		}
		_, _ = w.Write(resp)
	}))
	defer second.Close()

	c, err := New(Config{
		ScriptURLs:     []string{first.URL, second.URL},
		ScriptAccounts: []string{"same-account", "same-account"},
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
		t.Fatal("pollOnce returned no work; want same-account alternate to succeed after one 403")
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
		t.Fatal("timed out waiting for response from same-account alternate")
	}
	c.endpointMu.Lock()
	firstQuota := c.endpoints[0].quotaExhaustedUntil
	secondUnavailable := c.endpointUnavailableLocked(&c.endpoints[1], time.Now())
	c.endpointMu.Unlock()
	if !firstQuota.IsZero() {
		t.Fatalf("first endpoint quotaExhaustedUntil = %v, want zero for ambiguous bare 403", firstQuota)
	}
	if secondUnavailable {
		t.Fatal("same-account alternate should remain available after ambiguous bare 403")
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

func TestCarrier_PollOnceRetriesAlternateAfterNoContentOrEmptyBody(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   []byte
	}{
		{name: "no content", status: http.StatusNoContent},
		{name: "empty ok", status: http.StatusOK, body: nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			aead, err := frame.NewCryptoFromHexKey(testKeyHex)
			if err != nil {
				t.Fatalf("crypto: %v", err)
			}
			var firstHits, secondHits int
			first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				firstHits++
				w.WriteHeader(tc.status)
				if len(tc.body) > 0 {
					_, _ = w.Write(tc.body)
				}
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
					t.Fatalf("second got frames=%d, want preserved hello payload", len(in))
				}
				resp, err := frame.EncodeBatch(aead, clientID, []*frame.Frame{{
					SessionID: in[0].SessionID,
					Seq:       0,
					Payload:   []byte("ok"),
				}})
				if err != nil {
					t.Fatalf("second encode: %v", err)
				}
				_, _ = w.Write(resp)
			}))
			defer second.Close()

			c, err := New(Config{
				ScriptURLs:     []string{first.URL, second.URL},
				ScriptAccounts: []string{"bad", "good"},
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
				t.Fatal("pollOnce returned no work; want alternate endpoint to succeed")
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
				t.Fatal("timed out waiting for response from alternate endpoint")
			}
		})
	}
}

func TestCarrier_NonOKQuotaBodyMarksAccountQuotaExhausted(t *testing.T) {
	aead, err := frame.NewCryptoFromHexKey(testKeyHex)
	if err != nil {
		t.Fatalf("crypto: %v", err)
	}
	var secondHits int
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("<html>Exception: Service invoked too many times for one day: urlfetch.</html>"))
	}))
	defer first.Close()
	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		secondHits++
		body, _ := io.ReadAll(r.Body)
		clientID, in, err := frame.DecodeBatch(aead, body)
		if err != nil {
			t.Fatalf("second decode: %v", err)
		}
		resp, err := frame.EncodeBatch(aead, clientID, []*frame.Frame{{
			SessionID: in[0].SessionID,
			Payload:   []byte("should-not-be-used"),
		}})
		if err != nil {
			t.Fatalf("second encode: %v", err)
		}
		_, _ = w.Write(resp)
	}))
	defer second.Close()

	c, err := New(Config{
		ScriptURLs:     []string{first.URL, second.URL},
		ScriptAccounts: []string{"acct", "acct"},
		AESKeyHex:      testKeyHex,
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	s := c.NewSession("example.com:443")
	if err := s.EnqueueTx([]byte("hello")); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	_ = c.pollOnce(context.Background())

	c.endpointMu.Lock()
	firstQuota := c.endpoints[0].quotaExhaustedUntil
	secondQuota := c.endpoints[1].quotaExhaustedUntil
	quotaReasons := c.endpoints[0].failureReasons[endpointFailureQuota]
	c.endpointMu.Unlock()

	if firstQuota.IsZero() || secondQuota.IsZero() {
		t.Fatalf("quota body did not mark same-account deployments exhausted: first=%v second=%v", firstQuota, secondQuota)
	}
	if quotaReasons == 0 {
		t.Fatal("quota body did not record quota failure reason")
	}
	if secondHits != 0 {
		t.Fatalf("same-account sibling was still hit after quota body; hits=%d", secondHits)
	}
}

func TestCarrier_PollOnceClassifiesEmptyNonOKByStatus(t *testing.T) {
	tests := []struct {
		name       string
		status     int
		wantReason string
	}{
		{name: "forbidden", status: http.StatusForbidden, wantReason: "http_error=1"},
		{name: "rate limit", status: http.StatusTooManyRequests, wantReason: "rate_limit=1"},
		{name: "bad gateway", status: http.StatusBadGateway, wantReason: "http_error=1"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
			}))
			defer srv.Close()

			c, err := New(Config{ScriptURLs: []string{srv.URL}, AESKeyHex: testKeyHex})
			if err != nil {
				t.Fatalf("new client: %v", err)
			}
			c.httpClients = []*http.Client{srv.Client()}

			_ = c.pollOnce(context.Background())
			line := c.endpointStatsLine()
			if !strings.Contains(line, tc.wantReason) {
				t.Fatalf("endpoint stats = %q, want %s", line, tc.wantReason)
			}
			if strings.Contains(line, "empty_204=1") {
				t.Fatalf("endpoint stats = %q, empty non-OK response was misclassified as empty_204", line)
			}
		})
	}
}

func TestCarrier_LocalNetworkFailureRollsBackDrainedTx(t *testing.T) {
	aead, err := frame.NewCryptoFromHexKey(testKeyHex)
	if err != nil {
		t.Fatalf("crypto: %v", err)
	}
	var echoHits int
	echo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		echoHits++
		body, _ := io.ReadAll(r.Body)
		clientID, in, err := frame.DecodeBatch(aead, body)
		if err != nil {
			t.Fatalf("echo decode: %v", err)
		}
		if len(in) != 1 || string(in[0].Payload) != "mobile-payload" {
			t.Fatalf("echo got frames=%d, want rolled-back mobile-payload", len(in))
		}
		resp, err := frame.EncodeBatch(aead, clientID, []*frame.Frame{{
			SessionID: in[0].SessionID,
			Seq:       0,
			Payload:   []byte("recovered"),
		}})
		if err != nil {
			t.Fatalf("echo encode: %v", err)
		}
		_, _ = w.Write(resp)
	}))
	defer echo.Close()

	c, err := New(Config{ScriptURLs: []string{echo.URL}, AESKeyHex: testKeyHex})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	c.httpClients = []*http.Client{{
		Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return nil, &net.OpError{Op: "dial", Err: syscall.ENETUNREACH}
		}),
	}}
	s := c.NewSession("example.com:443")
	if err := s.EnqueueTx([]byte("mobile-payload")); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	if didWork := c.pollOnce(context.Background()); didWork {
		t.Fatal("offline poll should not report work")
	}
	select {
	case _, ok := <-s.RxChan:
		if !ok {
			t.Fatal("local network failure should preserve, not abort, the session")
		}
	default:
	}

	c.resetLocalNetworkFailures()
	c.httpClients = []*http.Client{echo.Client()}
	if didWork := c.pollOnce(context.Background()); !didWork {
		t.Fatal("pollOnce after recovery returned no work; want rolled-back payload sent")
	}
	if echoHits != 1 {
		t.Fatalf("echo hits = %d, want 1", echoHits)
	}
	select {
	case got := <-s.RxChan:
		if string(got) != "recovered" {
			t.Fatalf("rx = %q, want recovered", got)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for recovered response")
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
		{name: "loop guard uppercase", in: []byte("RELAY_LOOP_DETECTED: RELAY_URLS must point to VPS"), want: true},
		{name: "apps script exception", in: []byte("Exception: Address unavailable"), want: true},
		{name: "upstream status", in: []byte("upstream status 502: bad gateway"), want: true},
		{name: "wrapped upstream status", in: []byte("Error: upstream status 502: bad gateway"), want: true},
		{name: "upstream fetch", in: []byte("upstream fetch error: Exception: Address unavailable"), want: true},
		{name: "wrapped upstream fetch", in: []byte("Error: upstream fetch error: Exception: Address unavailable"), want: true},
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

func TestClassifyRelayErrorBody_OfficialCodeGSSentinels(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		wantKind relayErrorKind
		wantText string
	}{
		{
			name:     "upstream status 204",
			body:     "upstream status 204: no content",
			wantKind: relayErrorHard,
			wantText: "tunnel_key",
		},
		{
			name:     "wrapped upstream status 204",
			body:     "<html>Exception: upstream status 204: no content</html>",
			wantKind: relayErrorHard,
			wantText: "tunnel_key",
		},
		{
			name:     "upstream status 502",
			body:     "upstream status 502: bad gateway",
			wantKind: relayErrorSoft,
			wantText: "VPS returned HTTP 502",
		},
		{
			name:     "upstream fetch error",
			body:     "upstream fetch error: Exception: Address unavailable",
			wantKind: relayErrorSoft,
			wantText: "could not reach your VPS",
		},
		{
			name:     "wrapped upstream fetch error",
			body:     "<html>Error: upstream fetch error: Exception: Address unavailable</html>",
			wantKind: relayErrorSoft,
			wantText: "could not reach your VPS",
		},
		{
			name:     "bare exception fallback",
			body:     "Exception: Address unavailable",
			wantKind: relayErrorSoft,
			wantText: "could not reach your VPS",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			reason, kind := classifyRelayErrorBodyKind([]byte(tc.body))
			if kind != tc.wantKind {
				t.Fatalf("kind = %v, want %v (reason %q)", kind, tc.wantKind, reason)
			}
			if !strings.Contains(reason, tc.wantText) {
				t.Fatalf("reason = %q, want substring %q", reason, tc.wantText)
			}
		})
	}
}

func TestClassifyRelayErrorBodyKind_SeparatesQuotaRateLimitAndAdmin(t *testing.T) {
	tests := []struct {
		name string
		body string
		want relayErrorKind
	}{
		{
			name: "daily quota",
			body: "<html>Exception: Service invoked too many times for one day: urlfetch.</html>",
			want: relayErrorDailyQuota,
		},
		{
			name: "daily quota inside official fetch sentinel",
			body: "upstream fetch error: Exception: Service invoked too many times for one day: urlfetch.",
			want: relayErrorDailyQuota,
		},
		{
			name: "official generic daily service quota",
			body: "<html>Exception: Service invoked too many times: UrlFetch.</html>",
			want: relayErrorDailyQuota,
		},
		{
			name: "official daily compute quota",
			body: "<html>Exception: Service using too much computer time for one day.</html>",
			want: relayErrorDailyQuota,
		},
		{
			name: "short rate limit",
			body: "<html>Exception: Service invoked too many times in a short time: UrlFetch. Try Utilities.sleep(1000) between calls.</html>",
			want: relayErrorRateLimit,
		},
		{
			name: "official too many times per second",
			body: "<html>Script invoked too many times per second for this Google user account.</html>",
			want: relayErrorRateLimit,
		},
		{
			name: "official too many scripts running",
			body: "<html>There are too many scripts running simultaneously for this Google user account.</html>",
			want: relayErrorRateLimit,
		},
		{
			name: "http 429 style body",
			body: "<html>Too many requests, rate limit exceeded.</html>",
			want: relayErrorRateLimit,
		},
		{
			name: "admin urlfetch policy",
			body: "<html>UrlFetch calls to https://example.com are not permitted by your admin.</html>",
			want: relayErrorHard,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, got := classifyRelayErrorBodyKind([]byte(tc.body))
			if got != tc.want {
				t.Fatalf("kind = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestCarrier_DirectBinarySkipsTextErrorHeuristic(t *testing.T) {
	aead, err := frame.NewCryptoFromHexKey(testKeyHex)
	if err != nil {
		t.Fatalf("crypto: %v", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		clientID, _, err := frame.DecodeBatchBinary(aead, body)
		if err != nil {
			t.Fatalf("DecodeBatchBinary: %v", err)
		}
		response, err := frame.EncodeBatchBinary(aead, clientID, nil)
		if err != nil {
			t.Fatalf("EncodeBatchBinary: %v", err)
		}
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

func TestCarrier_PollOnceRecordsEmptyAndUsefulPolls(t *testing.T) {
	aead, err := frame.NewCryptoFromHexKey(testKeyHex)
	if err != nil {
		t.Fatalf("crypto: %v", err)
	}
	var requestCount int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		body, _ := io.ReadAll(r.Body)
		clientID, in, err := frame.DecodeBatch(aead, body)
		if err != nil {
			t.Fatalf("decode request %d: %v", requestCount, err)
		}
		var out []*frame.Frame
		if len(in) > 0 {
			out = append(out, &frame.Frame{
				SessionID: in[0].SessionID,
				Seq:       0,
				Payload:   []byte("reply"),
			})
		}
		resp, err := frame.EncodeBatch(aead, clientID, out)
		if err != nil {
			t.Fatalf("encode response %d: %v", requestCount, err)
		}
		_, _ = w.Write(resp)
	}))
	defer srv.Close()

	c, err := New(Config{ScriptURLs: []string{srv.URL}, AESKeyHex: testKeyHex})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	c.httpClients = []*http.Client{srv.Client()}

	if didWork := c.pollOnce(context.Background()); didWork {
		t.Fatal("empty idle poll reported work")
	}
	if got := c.stats.idlePolls.Load(); got != 1 {
		t.Fatalf("idlePolls = %d, want 1", got)
	}
	if got := c.stats.emptyPolls.Load(); got != 1 {
		t.Fatalf("emptyPolls = %d, want 1", got)
	}
	if got := c.stats.usefulPolls.Load(); got != 0 {
		t.Fatalf("usefulPolls = %d, want 0 before useful response", got)
	}

	sess := c.NewSession("example.com:443")
	if err := sess.EnqueueTx([]byte("hello")); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	if didWork := c.pollOnce(context.Background()); !didWork {
		t.Fatal("useful poll reported no work")
	}
	if got := c.stats.emptyPolls.Load(); got != 1 {
		t.Fatalf("emptyPolls = %d, want still 1", got)
	}
	if got := c.stats.usefulPolls.Load(); got != 1 {
		t.Fatalf("usefulPolls = %d, want 1", got)
	}
	select {
	case got := <-sess.RxChan:
		if string(got) != "reply" {
			t.Fatalf("rx = %q, want reply", got)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for useful response")
	}
}

func TestCarrier_NewUsesConfiguredPollTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	c, err := New(Config{
		ScriptURLs:  []string{srv.URL},
		AESKeyHex:   testKeyHex,
		PollTimeout: 300 * time.Second,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if len(c.httpClients) == 0 {
		t.Fatal("no HTTP clients configured")
	}
	if got := c.httpClients[0].Timeout; got != 300*time.Second {
		t.Fatalf("HTTP client timeout = %s, want 300s", got)
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
// bandwidth by the worker count. The cap in pure-download mode is now derived
// from account/URL buckets, with a floor of 2 for single-endpoint configs.
// This fixes both the upload amplification of #41 and the throughput collapse
// in multi-endpoint configs after initial SYNs completed (issue #73).
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
		reqBody, _ := io.ReadAll(r.Body)
		clientID, _, err := frame.DecodeBatch(aead, reqBody)
		if err != nil {
			t.Errorf("decode request: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		body, _ := frame.EncodeBatch(aead, clientID, nil)
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	// Four endpoints labeled under four distinct accounts -> bucketCount = 4,
	// numWorkers = workersPerEndpoint × 4 = 12. Pre-fix idleCap would have been
	// numWorkers-1 = 11; new cap is max(pureDownloadIdleCap, bucketCount) = 4.
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

		reqBody, _ := io.ReadAll(r.Body)
		clientID, _, err := frame.DecodeBatch(aead, reqBody)
		if err != nil {
			t.Errorf("decode request: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		body, _ := frame.EncodeBatch(aead, clientID, nil)
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	// 4 endpoints, 2 distinct accounts (A,A,B,B), IdleSlotsPerBucket=2:
	//   bucketCount=2, idleCap=bucketCount×IdleSlotsPerBucket=4,
	//   numWorkers=workersPerEndpoint×endpointCount=12.
	// Default IdleSlotsPerBucket=1 would cap at 2 idle slots.
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

func TestCarrier_UnlabeledEndpointsUseImplicitBucketsAndEndpointWorkerScaling(t *testing.T) {
	c, err := New(Config{
		ScriptURLs: []string{
			"http://a.example/exec",
			"http://b.example/exec",
			"http://c.example/exec",
			"http://d.example/exec",
			"http://e.example/exec",
		},
		AESKeyHex: testKeyHex,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if c.bucketCount != 5 {
		t.Fatalf("bucketCount = %d, want one implicit bucket per unlabeled endpoint", c.bucketCount)
	}
	if c.numWorkers != workersPerEndpoint*5 {
		t.Fatalf("numWorkers = %d, want workersPerEndpoint × endpoint count = %d", c.numWorkers, workersPerEndpoint*5)
	}
}

func TestCarrier_IdleEndpointReservationCapsPerBucket(t *testing.T) {
	c, err := New(Config{
		ScriptURLs: []string{
			"http://a1.example/exec",
			"http://a2.example/exec",
			"http://b1.example/exec",
			"http://b2.example/exec",
		},
		ScriptAccounts:     []string{"account-a", "account-a", "account-b", "account-b"},
		AESKeyHex:          testKeyHex,
		IdlePollMode:       "always",
		IdleSlotsPerBucket: 1,
		IdlePollMaxBuckets: 2,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	firstIdx, _, firstBucket := c.pickRelayEndpointForIdlePoll(true)
	secondIdx, _, secondBucket := c.pickRelayEndpointForIdlePoll(true)
	thirdIdx, _, _ := c.pickRelayEndpointForIdlePoll(true)
	if firstIdx < 0 || secondIdx < 0 {
		t.Fatalf("first two idle picks failed: first=%d second=%d", firstIdx, secondIdx)
	}
	if firstBucket == secondBucket {
		t.Fatalf("first two picks used same bucket %q despite one idle slot per bucket", firstBucket)
	}
	if thirdIdx != -1 {
		t.Fatalf("third idle pick = %d, want no endpoint after both allowed buckets are reserved", thirdIdx)
	}
	c.releaseIdleBucketSlot(firstBucket)
	fourthIdx, _, fourthBucket := c.pickRelayEndpointForIdlePoll(true)
	if fourthIdx < 0 || fourthBucket != firstBucket {
		t.Fatalf("after releasing %q picked idx=%d bucket=%q", firstBucket, fourthIdx, fourthBucket)
	}
	c.releaseIdleBucketSlot(secondBucket)
	c.releaseIdleBucketSlot(fourthBucket)
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
	step := 100 * time.Millisecond
	max := 250 * time.Millisecond
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
		ticker := time.NewTicker(step / 10)
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
	if elapsed < max-25*time.Millisecond {
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

func TestCarrier_AdaptiveNoSessionBackoffSchedule(t *testing.T) {
	c, err := New(Config{
		ScriptURLs:   []string{"http://a.example/exec"},
		AESKeyHex:    testKeyHex,
		IdlePollMode: "adaptive",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	c.mu.Lock()
	c.noSessionSince = time.Now().Add(-31 * time.Second)
	c.mu.Unlock()

	cases := []struct {
		n    int
		want time.Duration
	}{
		{1, time.Second},
		{3, 2 * time.Second},
		{6, 5 * time.Second},
		{20, 15 * time.Second},
	}
	for _, tc := range cases {
		if got := c.idleBackoff(tc.n); got != tc.want {
			t.Errorf("adaptive idleBackoff(%d) = %v, want %v", tc.n, got, tc.want)
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

	if c.numWorkers != 6 {
		t.Fatalf("numWorkers = %d, want workers_per_endpoint × endpoint count = 6", c.numWorkers)
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

func TestEndpointBlacklistTTLWithBoundsIncludesFifteenMinuteTier(t *testing.T) {
	base := 3 * time.Second
	max := time.Hour
	cases := []struct {
		failCount int
		want      time.Duration
	}{
		{1, 3 * time.Second},
		{2, 6 * time.Second},
		{3, 12 * time.Second},
		{4, 24 * time.Second},
		{5, 48 * time.Second},
		{6, 5 * time.Minute},
		{7, 15 * time.Minute},
		{8, 30 * time.Minute},
		{9, time.Hour},
	}
	for _, tc := range cases {
		if got := endpointBlacklistTTLWithBounds(tc.failCount, base, max); got != tc.want {
			t.Fatalf("endpointBlacklistTTLWithBounds(%d) = %v, want %v", tc.failCount, got, tc.want)
		}
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

func TestCarrier_PickRelayEndpointPrefersRecentlyUsefulEndpoint(t *testing.T) {
	c, err := New(Config{
		ScriptURLs: []string{
			"http://useful.example/exec",
			"http://idle.example/exec",
		},
		AESKeyHex: testKeyHex,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	c.markEndpointSuccessWithRTT(0, 140*time.Millisecond, true)
	c.markEndpointSuccessWithRTT(1, 100*time.Millisecond, false)

	idx, url := c.pickRelayEndpoint()
	if idx != 0 || url != "http://useful.example/exec" {
		t.Fatalf("picked idx=%d url=%q, want recently useful endpoint", idx, url)
	}
}

func TestCarrier_PickRelayEndpointPenalizesSlowSuccessfulEndpoint(t *testing.T) {
	c, err := New(Config{
		ScriptURLs: []string{
			"http://slow-success.example/exec",
			"http://steady.example/exec",
		},
		AESKeyHex: testKeyHex,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	c.markEndpointSuccessWithRTT(0, 90*time.Millisecond, false)
	c.markEndpointSuccessWithRTT(1, 150*time.Millisecond, false)
	c.markEndpointSuccessWithRTT(0, 3*time.Second, false)

	idx, url := c.pickRelayEndpoint()
	if idx != 1 || url != "http://steady.example/exec" {
		t.Fatalf("picked idx=%d url=%q, want steady endpoint after slow success", idx, url)
	}
	if c.endpoints[0].blacklistedTill.After(time.Now()) {
		t.Fatalf("slow successful endpoint should be penalized, not blacklisted")
	}
}

func TestCarrier_SlowSuccessfulEndpointPenaltyExpires(t *testing.T) {
	c, err := New(Config{
		ScriptURLs: []string{
			"http://recovered.example/exec",
			"http://steady.example/exec",
		},
		AESKeyHex: testKeyHex,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	c.markEndpointSuccessWithRTT(0, 90*time.Millisecond, false)
	c.markEndpointSuccessWithRTT(1, 150*time.Millisecond, false)
	c.markEndpointSuccessWithRTT(0, 3*time.Second, false)
	c.endpointMu.Lock()
	c.endpoints[0].lastSlowAt = time.Now().Add(-endpointSlowWindow - time.Second)
	c.endpointMu.Unlock()

	idx, url := c.pickRelayEndpoint()
	if idx != 0 || url != "http://recovered.example/exec" {
		t.Fatalf("picked idx=%d url=%q, want recovered lower-RTT endpoint after slow penalty expires", idx, url)
	}
}

func TestCarrier_SlowSuccessDoesNotPoisonEmptyRTTEWMA(t *testing.T) {
	c, err := New(Config{
		ScriptURLs: []string{
			"http://slow-once.example/exec",
			"http://steady.example/exec",
		},
		AESKeyHex: testKeyHex,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	c.markEndpointSuccessWithRTT(0, 3*time.Second, false)
	c.markEndpointSuccessWithRTT(1, 150*time.Millisecond, false)
	c.endpointMu.Lock()
	c.endpoints[0].lastSlowAt = time.Now().Add(-endpointSlowWindow - time.Second)
	c.endpointMu.Unlock()

	idx, url := c.pickRelayEndpoint()
	if idx != 0 || url != "http://slow-once.example/exec" {
		t.Fatalf("picked idx=%d url=%q, want endpoint recovered after first slow outlier expires", idx, url)
	}
}

func TestCarrier_ExpiredSlowSuccessCountDoesNotAccumulate(t *testing.T) {
	c, err := New(Config{
		ScriptURLs: []string{
			"http://slow-again.example/exec",
			"http://steady.example/exec",
		},
		AESKeyHex: testKeyHex,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	c.markEndpointSuccessWithRTT(0, 3*time.Second, false)
	c.endpointMu.Lock()
	c.endpoints[0].slowSuccesses = 9
	c.endpoints[0].lastSlowAt = time.Now().Add(-endpointSlowWindow - time.Second)
	c.endpointMu.Unlock()
	c.markEndpointSuccessWithRTT(0, 3*time.Second, false)

	c.endpointMu.Lock()
	defer c.endpointMu.Unlock()
	if c.endpoints[0].slowSuccesses != 1 {
		t.Fatalf("slowSuccesses = %d, want expired count reset before new slow sample", c.endpoints[0].slowSuccesses)
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

func TestCarrier_AdaptiveIdlePollCapsQuietNoSessionToOneSlot(t *testing.T) {
	c, err := New(Config{
		ScriptURLs: []string{
			"http://a.example/exec",
			"http://b.example/exec",
			"http://c.example/exec",
			"http://d.example/exec",
		},
		ScriptAccounts:     []string{"account-a", "account-b", "account-c", "account-d"},
		AESKeyHex:          testKeyHex,
		IdleSlotsPerBucket: 2,
		IdlePollMode:       "adaptive",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	now := time.Now()
	c.mu.Lock()
	c.noSessionSince = now.Add(-31 * time.Second)
	c.mu.Unlock()

	if got := c.idlePollCap(now, true, 4, true); got != 1 {
		t.Fatalf("idlePollCap after quiet no-session period = %d, want 1", got)
	}
}

func TestCarrier_IdlePollAlwaysCapsNoSessionToConfiguredBucketLimit(t *testing.T) {
	c, err := New(Config{
		ScriptURLs: []string{
			"http://a.example/exec",
			"http://b.example/exec",
			"http://c.example/exec",
			"http://d.example/exec",
		},
		ScriptAccounts:     []string{"account-a", "account-b", "account-c", "account-d"},
		AESKeyHex:          testKeyHex,
		IdleSlotsPerBucket: 2,
		IdlePollMode:       "always",
		IdlePollMaxBuckets: 2,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if got := c.idlePollCap(time.Now(), true, 4, true); got != 4 {
		t.Fatalf("idlePollCap always/no-session = %d, want 2 buckets × 2 slots", got)
	}
}

func TestCarrier_ACKOnlySlotCapDoesNotUsePureDownloadFloor(t *testing.T) {
	c, err := New(Config{
		ScriptURLs:         []string{"http://a.example/exec"},
		AESKeyHex:          testKeyHex,
		IdleSlotsPerBucket: 1,
		IdlePollMode:       "always",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got := c.idlePollCap(time.Now(), true, 1, false); got != 1 {
		t.Fatalf("ACK-only idlePollCap = %d, want exact configured one-slot account cap", got)
	}
}

func TestCarrier_IdlePollAlwaysUsesAllBucketsWithActiveSession(t *testing.T) {
	c, err := New(Config{
		ScriptURLs: []string{
			"http://a.example/exec",
			"http://b.example/exec",
			"http://c.example/exec",
			"http://d.example/exec",
		},
		ScriptAccounts:     []string{"account-a", "account-b", "account-c", "account-d"},
		AESKeyHex:          testKeyHex,
		IdleSlotsPerBucket: 2,
		IdlePollMode:       "always",
		IdlePollMaxBuckets: 2,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_ = c.NewSession("example.com:443")

	if got := c.idlePollCap(time.Now(), true, 4, true); got != 8 {
		t.Fatalf("idlePollCap always/active = %d, want all 4 buckets × 2 slots", got)
	}
}

func TestCarrier_IdleEndpointSelectionUsesAtMostConfiguredBucketLimit(t *testing.T) {
	c, err := New(Config{
		ScriptURLs: []string{
			"http://a.example/exec",
			"http://b.example/exec",
			"http://c.example/exec",
			"http://d.example/exec",
		},
		ScriptAccounts:           []string{"account-a", "account-b", "account-c", "account-d"},
		AESKeyHex:                testKeyHex,
		IdlePollMode:             "always",
		IdlePollMaxBuckets:       2,
		IdleSlotsPerBucket:       1,
		WorkersPerEndpoint:       4,
		PollIdleSleep:            time.Millisecond,
		EndpointOutageGrace:      time.Second,
		MaxRequestBytesPreEncode: 512 * 1024,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	for i := 0; i < 12; i++ {
		idx, url := c.pickRelayEndpointForPoll(true)
		if idx < 0 {
			t.Fatalf("pickRelayEndpointForPoll returned no endpoint on iteration %d", i)
		}
		if url != "http://a.example/exec" && url != "http://b.example/exec" {
			t.Fatalf("idle pick used %q, want only first two idle account buckets", url)
		}
	}
}

func TestCarrier_AdaptiveIdlePollStopsAfterLongNoSessionSleep(t *testing.T) {
	c, err := New(Config{
		ScriptURLs: []string{
			"http://a.example/exec",
			"http://b.example/exec",
		},
		ScriptAccounts:     []string{"account-a", "account-b"},
		AESKeyHex:          testKeyHex,
		IdleSlotsPerBucket: 2,
		IdlePollMode:       "adaptive",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	now := time.Now()
	c.mu.Lock()
	c.noSessionSince = now.Add(-6 * time.Minute)
	c.mu.Unlock()

	if got := c.idlePollCap(now, true, 2, true); got != 0 {
		t.Fatalf("idlePollCap after long no-session sleep = %d, want 0", got)
	}
}

func TestCarrier_AdaptiveIdlePollUsesFullCapacityWithActiveSession(t *testing.T) {
	c, err := New(Config{
		ScriptURLs: []string{
			"http://a.example/exec",
			"http://b.example/exec",
			"http://c.example/exec",
			"http://d.example/exec",
		},
		ScriptAccounts:     []string{"account-a", "account-b", "account-c", "account-d"},
		AESKeyHex:          testKeyHex,
		IdleSlotsPerBucket: 2,
		IdlePollMode:       "adaptive",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_ = c.NewSession("example.com:443")

	if got := c.idlePollCap(time.Now(), true, 4, true); got != 8 {
		t.Fatalf("idlePollCap with active session = %d, want all 4 buckets × 2 slots", got)
	}
}

func TestCarrier_IdlePollOffStopsOnlyWhenNoSessions(t *testing.T) {
	c, err := New(Config{
		ScriptURLs: []string{
			"http://a.example/exec",
			"http://b.example/exec",
		},
		ScriptAccounts:     []string{"account-a", "account-b"},
		AESKeyHex:          testKeyHex,
		IdleSlotsPerBucket: 2,
		IdlePollMode:       "off",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got := c.idlePollCap(time.Now(), true, 2, true); got != 0 {
		t.Fatalf("idlePollCap off with no sessions = %d, want 0", got)
	}

	_ = c.NewSession("example.com:443")
	if got := c.idlePollCap(time.Now(), true, 2, true); got != 4 {
		t.Fatalf("idlePollCap off with active session = %d, want all 2 buckets × 2 slots", got)
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

func TestCarrier_QuotaStatePersistsAccountQuarantine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "quota-state.json")
	c, err := New(Config{
		ScriptURLs:     []string{"http://quota-a.example/exec", "http://quota-b.example/exec", "http://healthy.example/exec"},
		ScriptAccounts: []string{"quota-account", "quota-account", "healthy-account"},
		AESKeyHex:      testKeyHex,
		QuotaStatePath: path,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	c.markEndpointQuotaExhausted(0)

	next, err := New(Config{
		ScriptURLs:     []string{"http://quota-a.example/exec", "http://quota-b.example/exec", "http://healthy.example/exec"},
		ScriptAccounts: []string{"quota-account", "quota-account", "healthy-account"},
		AESKeyHex:      testKeyHex,
		QuotaStatePath: path,
	})
	if err != nil {
		t.Fatalf("New with quota state: %v", err)
	}
	if next.endpoints[0].quotaExhaustedUntil.IsZero() || next.endpoints[1].quotaExhaustedUntil.IsZero() {
		t.Fatalf("quota account quarantine was not restored: %#v %#v", next.endpoints[0], next.endpoints[1])
	}
	if !next.endpoints[2].quotaExhaustedUntil.IsZero() {
		t.Fatal("healthy account inherited quota state from another account")
	}
}

func TestCarrier_ActivePollSlotsAreCappedPerBucket(t *testing.T) {
	c, err := New(Config{
		ScriptURLs: []string{
			"http://a1.example/exec",
			"http://a2.example/exec",
			"http://b1.example/exec",
		},
		ScriptAccounts:   []string{"account-a", "account-a", "account-b"},
		AESKeyHex:        testKeyHex,
		TxSlotsPerBucket: 1,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	idxA, _, bucketA := c.pickRelayEndpointForActivePoll()
	if idxA < 0 || bucketA != "acct:account-a" {
		t.Fatalf("first active pick idx=%d bucket=%q, want account-a", idxA, bucketA)
	}
	idxB, _, bucketB := c.pickRelayEndpointForActivePoll()
	if idxB < 0 || bucketB != "acct:account-b" {
		t.Fatalf("second active pick idx=%d bucket=%q, want account-b because account-a slot is busy", idxB, bucketB)
	}
	idxBlocked, urlBlocked, bucketBlocked := c.pickRelayEndpointForActivePoll()
	if idxBlocked != -1 || urlBlocked != "" || bucketBlocked != "" {
		t.Fatalf("third active pick = idx=%d url=%q bucket=%q, want blocked", idxBlocked, urlBlocked, bucketBlocked)
	}
	c.releaseActiveBucketSlot(bucketA)
	idxAgain, _, bucketAgain := c.pickRelayEndpointForActivePoll()
	if idxAgain < 0 || bucketAgain != "acct:account-a" {
		t.Fatalf("active pick after release idx=%d bucket=%q, want account-a", idxAgain, bucketAgain)
	}
	c.releaseActiveBucketSlot(bucketB)
	c.releaseActiveBucketSlot(bucketAgain)
}

func TestCarrier_SameAccountSuccessDoesNotClearDailyQuotaQuarantine(t *testing.T) {
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
	c.markEndpointSuccess(1)

	c.endpointMu.Lock()
	defer c.endpointMu.Unlock()
	for i := range c.endpoints {
		if c.endpoints[i].quotaExhaustedUntil.IsZero() {
			t.Fatalf("endpoint %d quotaExhaustedUntil was cleared by a late success", i)
		}
		if c.endpoints[i].blacklistedTill.IsZero() {
			t.Fatalf("endpoint %d blacklistedTill was cleared by a late success", i)
		}
	}
}

func TestCarrier_UpdateEndpointsAppliesAccountQuotaToReplacementURL(t *testing.T) {
	c, err := New(Config{
		ScriptURLs: []string{
			"http://old-a.example/exec",
			"http://b.example/exec",
		},
		ScriptAccounts: []string{"account-a", "account-b"},
		AESKeyHex:      testKeyHex,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	c.markEndpointQuotaExhausted(0)

	c.UpdateEndpoints(
		[]string{"http://new-a.example/exec", "http://b.example/exec"},
		[]string{"account-a", "account-b"},
	)

	c.endpointMu.Lock()
	defer c.endpointMu.Unlock()
	if got := c.endpoints[0].url; got != "http://new-a.example/exec" {
		t.Fatalf("endpoint[0] url = %q", got)
	}
	if c.endpoints[0].quotaExhaustedUntil.IsZero() {
		t.Fatal("replacement URL for quota-exhausted account did not inherit account quarantine")
	}
	if !c.endpoints[1].quotaExhaustedUntil.IsZero() {
		t.Fatal("unrelated account inherited account-a quota quarantine")
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

func TestCarrier_QuotaExhaustionWithoutAccountOnlySkipsFailingEndpoint(t *testing.T) {
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
	c.markEndpointQuotaExhausted(0)

	idx, url := c.pickRelayEndpoint()
	if idx != 1 || url != "http://b.example/exec" {
		t.Fatalf("picked idx=%d url=%q, want unlabeled non-failing endpoint", idx, url)
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
	pressure := c.accountQuotaPressureLocked(now)["acct:account-a"]
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

func TestCarrier_PollOnceContextCancelRollsBackDrainedTX(t *testing.T) {
	c, err := New(Config{
		TransportMode: "direct_post",
		ScriptURLs:    []string{"http://a.example/exec"},
		AESKeyHex:     testKeyHex,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	started := make(chan struct{})
	var once sync.Once
	c.httpClients = []*http.Client{{
		Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			once.Do(func() { close(started) })
			<-r.Context().Done()
			return nil, r.Context().Err()
		}),
	}}
	s := c.NewSession("example.com:443")
	if err := s.EnqueueTx([]byte("hello")); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan bool, 1)
	go func() { done <- c.pollOnce(ctx) }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("poll did not start request")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("poll did not return after context cancel")
	}
	if !s.HasPendingTx() {
		t.Fatal("context-canceled POST lost drained TX instead of rolling it back")
	}
}

func TestCarrier_DirectPostTextHTTPStatusAbortsDrainedBatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("direct relay failed"))
	}))
	defer srv.Close()

	c, err := New(Config{
		TransportMode: "direct_post",
		ScriptURLs:    []string{srv.URL},
		AESKeyHex:     testKeyHex,
		UseFronting:   false,
		BinaryDirect:  false,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	s := c.NewSession("example.com:443")

	_ = c.pollOnce(context.Background())

	select {
	case _, ok := <-s.RxChan:
		if ok {
			t.Fatal("direct POST HTTP error left session RxChan open")
		}
	case <-time.After(time.Second):
		t.Fatal("direct POST HTTP error did not abort drained session")
	}
	c.mu.Lock()
	_, alive := c.sessions[s.ID]
	c.mu.Unlock()
	if alive {
		t.Fatal("direct POST HTTP error restored drained session instead of aborting it")
	}
}

func TestCarrier_AppsScriptHardSentinelAbortsDrainedBatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("<html>Exception: upstream status 204: no content</html>"))
	}))
	defer srv.Close()

	c, err := New(Config{ScriptURLs: []string{srv.URL}, AESKeyHex: testKeyHex})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	c.httpClients = []*http.Client{srv.Client()}
	c.useFronting = true

	s := c.NewSession("example.com:443")
	if err := s.EnqueueTx([]byte("hello")); err != nil {
		t.Fatalf("EnqueueTx: %v", err)
	}

	_ = c.pollOnce(context.Background())

	select {
	case _, ok := <-s.RxChan:
		if ok {
			t.Fatal("hard Apps Script sentinel left session RxChan open")
		}
	case <-time.After(time.Second):
		t.Fatal("hard Apps Script sentinel did not abort drained session")
	}
	c.mu.Lock()
	_, alive := c.sessions[s.ID]
	c.mu.Unlock()
	if alive {
		t.Fatal("hard Apps Script sentinel restored drained session instead of aborting it")
	}
}

func TestCarrier_SafeLogErrorRedactsURL(t *testing.T) {
	err := &url.Error{
		Op:  "Post",
		URL: "https://user:secret@example.com/macros/s/AKfycbSensitiveDeployment/exec?token=abc",
		Err: context.DeadlineExceeded,
	}
	got := safeLogError(err)
	for _, leak := range []string{"user", "secret", "AKfycbSensitiveDeployment", "token=abc", "/macros/"} {
		if strings.Contains(got, leak) {
			t.Fatalf("safeLogError leaked %q in %q", leak, got)
		}
	}
	if !strings.Contains(got, "Post") || !strings.Contains(got, "context deadline exceeded") {
		t.Fatalf("safeLogError = %q, want operation and underlying error", got)
	}
}

func TestCarrier_IsLocalNetworkOfflineRecognizesWrappedDialFailures(t *testing.T) {
	wrapped := &url.Error{
		Op:  "Post",
		URL: "https://script.google.com/macros/s/test/exec",
		Err: &net.OpError{
			Op:  "dial",
			Net: "tcp",
			Err: &os.SyscallError{Syscall: "connect", Err: syscall.ENETUNREACH},
		},
	}
	if !isLocalNetworkOffline(wrapped) {
		t.Fatal("expected wrapped ENETUNREACH dial error to be classified as local offline")
	}
	dialTimeout := &url.Error{
		Op:  "Post",
		URL: "https://script.google.com/macros/s/test/exec",
		Err: &net.OpError{Op: "dial", Net: "tcp", Err: context.DeadlineExceeded},
	}
	if !isLocalNetworkOffline(dialTimeout) {
		t.Fatal("expected dial timeout to be classified as local offline")
	}
	dnsTemporary := &net.DNSError{Err: "temporary failure in name resolution", Name: "google.com", IsTemporary: true}
	if !isLocalNetworkOffline(dnsTemporary) {
		t.Fatal("expected temporary DNS failure to be classified as local offline")
	}
	if isLocalNetworkOffline(context.DeadlineExceeded) {
		t.Fatal("generic context deadline should not be classified as local offline")
	}
	if isLocalNetworkOffline(errors.New("relay returned HTTP 500")) {
		t.Fatal("generic server error should not be classified as local offline")
	}
	for _, msg := range []string{
		"net/http: TLS handshake timeout",
		"http2: client connection lost",
		"read tcp 192.168.9.208:14660->216.239.38.120:443: wsarecv: A connection attempt failed because the connected party did not properly respond after a period of time, or established connection failed because connected host has failed to respond.",
	} {
		if !isLocalNetworkOffline(errors.New(msg)) {
			t.Fatalf("expected fronting/local transport error %q to be classified as local offline", msg)
		}
	}
}

func TestCarrier_LocalNetworkFailureUsesShortBackoffWithoutEscalatingFailCount(t *testing.T) {
	c, err := New(Config{
		ScriptURLs: []string{"http://a.example/exec"},
		AESKeyHex:  testKeyHex,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	for i := 0; i < 20; i++ {
		c.markEndpointLocalNetworkFailure(0)
	}
	c.endpointMu.Lock()
	ep := c.endpoints[0]
	c.endpointMu.Unlock()
	if ep.failCount != 0 {
		t.Fatalf("failCount = %d, want 0 for local offline failures", ep.failCount)
	}
	if !ep.localNetworkOffline {
		t.Fatal("localNetworkOffline flag not set")
	}
	remaining := time.Until(ep.blacklistedTill)
	if remaining <= 0 || remaining > localNetworkOfflineBlacklistTTL+2*time.Second {
		t.Fatalf("local offline blacklist remaining = %v, want short cap around %v", remaining, localNetworkOfflineBlacklistTTL)
	}
}

func TestCarrier_ResetLocalNetworkFailuresPreservesQuotaExhaustedEndpoints(t *testing.T) {
	resetAt := time.Now().Add(time.Hour)
	c := &Client{endpoints: []relayEndpoint{
		{
			url:                 "http://offline.example/exec",
			blacklistedTill:     time.Now().Add(time.Hour),
			failCount:           9,
			localNetworkOffline: true,
		},
		{
			url:                 "http://quota.example/exec",
			blacklistedTill:     resetAt,
			quotaExhaustedUntil: resetAt,
			failCount:           9,
			localNetworkOffline: true,
		},
	}}

	if cleared := c.resetLocalNetworkFailures(); cleared != 1 {
		t.Fatalf("cleared = %d, want 1", cleared)
	}
	if !c.endpoints[0].blacklistedTill.IsZero() || c.endpoints[0].failCount != 0 || c.endpoints[0].localNetworkOffline {
		t.Fatalf("transient local offline endpoint was not reset: %+v", c.endpoints[0])
	}
	if !c.endpoints[1].quotaExhaustedUntil.Equal(resetAt) {
		t.Fatal("quotaExhaustedUntil was cleared; quota endpoints must remain unavailable")
	}
	if c.endpoints[1].blacklistedTill.IsZero() || !c.endpoints[1].localNetworkOffline {
		t.Fatal("quota endpoint should not be reset by local network recovery")
	}
}

func TestCarrier_ShouldRunLocalNetworkRecoveryProbeOnlyForLocalOfflineOutage(t *testing.T) {
	now := time.Now()
	c := &Client{endpoints: []relayEndpoint{
		{url: "http://a.example/exec", blacklistedTill: now.Add(time.Minute), localNetworkOffline: true},
		{url: "http://b.example/exec", blacklistedTill: now.Add(time.Minute)},
	}}
	if !c.shouldRunLocalNetworkRecoveryProbe() {
		t.Fatal("expected recovery probe while all endpoints are unavailable and at least one failed due local offline")
	}
	c.endpoints[1].blacklistedTill = time.Time{}
	if c.shouldRunLocalNetworkRecoveryProbe() {
		t.Fatal("should not probe while at least one endpoint is available")
	}
	c.endpoints[0].blacklistedTill = now.Add(time.Minute)
	c.endpoints[0].localNetworkOffline = false
	c.endpoints[1].blacklistedTill = now.Add(time.Minute)
	if c.shouldRunLocalNetworkRecoveryProbe() {
		t.Fatal("should not probe for non-local endpoint failures")
	}
}

func TestCarrier_RecoveryProbeClearsLocalNetworkFailures(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	accepted := make(chan struct{})
	go func() {
		conn, err := ln.Accept()
		if err == nil {
			_ = conn.Close()
		}
		close(accepted)
	}()

	c := &Client{
		recoveryProbeAddr: ln.Addr().String(),
		endpoints: []relayEndpoint{{
			url:                 "http://offline.example/exec",
			blacklistedTill:     time.Now().Add(time.Hour),
			failCount:           5,
			localNetworkOffline: true,
		}},
	}
	if !c.runEndpointRecoveryProbeOnce(context.Background()) {
		t.Fatal("expected successful recovery probe")
	}
	select {
	case <-accepted:
	case <-time.After(time.Second):
		t.Fatal("probe did not connect to listener")
	}
	if !c.endpoints[0].blacklistedTill.IsZero() || c.endpoints[0].failCount != 0 || c.endpoints[0].localNetworkOffline {
		t.Fatalf("local offline endpoint was not reset after probe: %+v", c.endpoints[0])
	}
}

func TestCarrier_PollOnceMarksDoErrorsAsLocalNetworkFailuresOnly(t *testing.T) {
	c, err := New(Config{
		ScriptURLs: []string{"http://a.example/exec"},
		AESKeyHex:  testKeyHex,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	c.httpClients = []*http.Client{{
		Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return nil, &net.OpError{
				Op:  "dial",
				Net: "tcp",
				Err: &os.SyscallError{Syscall: "connect", Err: syscall.ENETUNREACH},
			}
		}),
	}}
	s := c.NewSession("example.com:443")
	if err := s.EnqueueTx([]byte("hello")); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	c.pollOnce(context.Background())

	c.endpointMu.Lock()
	ep := c.endpoints[0]
	c.endpointMu.Unlock()
	if ep.failCount != 0 || !ep.localNetworkOffline {
		t.Fatalf("endpoint = %+v, want local offline failure without failCount escalation", ep)
	}
}

type errReadCloser struct {
	err error
}

func (e errReadCloser) Read([]byte) (int, error) { return 0, e.err }
func (e errReadCloser) Close() error             { return nil }

func TestCarrier_PollOnceMarksResponseReadTransportErrorsAsLocalNetworkFailures(t *testing.T) {
	c, err := New(Config{
		ScriptURLs: []string{"http://a.example/exec"},
		AESKeyHex:  testKeyHex,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	c.httpClients = []*http.Client{{
		Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode:    http.StatusOK,
				Header:        make(http.Header),
				ContentLength: -1,
				Body:          errReadCloser{err: errors.New("http2: client connection lost")},
			}, nil
		}),
	}}
	s := c.NewSession("example.com:443")
	if err := s.EnqueueTx([]byte("hello")); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	c.pollOnce(context.Background())

	c.endpointMu.Lock()
	ep := c.endpoints[0]
	c.endpointMu.Unlock()
	if ep.failCount != 0 || !ep.localNetworkOffline {
		t.Fatalf("endpoint = %+v, want response read transport failure without failCount escalation", ep)
	}
	select {
	case _, ok := <-s.RxChan:
		if !ok {
			t.Fatal("local response read outage should preserve, not abort, the session")
		}
	default:
	}
	if !s.HasPendingTx() {
		t.Fatal("local response read outage should roll drained payload back into the session")
	}
}

func TestCarrier_AllEndpointsBlacklistedDoesNotCloseSessionsWhileStreamActive(t *testing.T) {
	c, err := New(Config{
		TransportMode:       "auto",
		ScriptURLs:          []string{"http://a.example/exec"},
		DirectStreamURLs:    []string{"ws://127.0.0.1:1/stream"},
		AESKeyHex:           testKeyHex,
		EndpointOutageGrace: time.Millisecond,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	s := c.NewSession("example.com:443")
	c.markEndpointHardFailure(0)
	c.streamActive.Store(true)
	c.endpointOutageStarted = time.Now().Add(-time.Second)

	if closed := c.closeSessionsIfAllEndpointsBlacklisted("test"); closed {
		t.Fatal("closeSessionsIfAllEndpointsBlacklisted closed sessions while stream is active")
	}
	select {
	case _, ok := <-s.RxChan:
		if !ok {
			t.Fatal("session was aborted while stream is active")
		}
	default:
	}
}
