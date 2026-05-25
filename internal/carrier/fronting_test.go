package carrier

import (
	"context"
	"errors"
	"io"
	"net/http"
	"testing"
	"time"
)

func TestNewDirectClientsUsesConfiguredWorkerPoolSize(t *testing.T) {
	clients := NewDirectClients(time.Second, 7)
	if len(clients) != 1 {
		t.Fatalf("clients = %d, want 1", len(clients))
	}
	tr, ok := clients[0].Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport type = %T, want *http.Transport", clients[0].Transport)
	}
	if tr.MaxIdleConnsPerHost != 28 {
		t.Fatalf("MaxIdleConnsPerHost = %d, want 28", tr.MaxIdleConnsPerHost)
	}
	if tr.ExpectContinueTimeout != 0 {
		t.Fatalf("ExpectContinueTimeout = %v, want 0", tr.ExpectContinueTimeout)
	}
}

func TestNewFrontedClientUsesConfiguredWorkerPoolSize(t *testing.T) {
	client := newFrontedClient("", "www.google.com", time.Second, nil, "h1", 9)
	tr, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport type = %T, want *http.Transport", client.Transport)
	}
	if tr.MaxIdleConnsPerHost != 18 {
		t.Fatalf("MaxIdleConnsPerHost = %d, want 18", tr.MaxIdleConnsPerHost)
	}
	if tr.MaxIdleConns < tr.MaxIdleConnsPerHost {
		t.Fatalf("MaxIdleConns = %d, want at least MaxIdleConnsPerHost %d", tr.MaxIdleConns, tr.MaxIdleConnsPerHost)
	}
}

func TestSelectFrontedClientIndexesDropsFailedAndSlowHosts(t *testing.T) {
	results := []frontedProbeResult{
		{index: 0, host: "www.google.com", client: &http.Client{}, samples: []time.Duration{90 * time.Millisecond, 100 * time.Millisecond}},
		{index: 1, host: "mail.google.com", client: &http.Client{}, samples: []time.Duration{110 * time.Millisecond, 120 * time.Millisecond}},
		{index: 2, host: "accounts.google.com", client: &http.Client{}, samples: []time.Duration{390 * time.Millisecond, 420 * time.Millisecond}},
		{index: 3, host: "drive.google.com", client: &http.Client{}, err: context.DeadlineExceeded},
	}

	got := selectFrontedClientIndexes(results)
	if len(got) != 2 || got[0] != 0 || got[1] != 1 {
		t.Fatalf("got %v want [0 1]", got)
	}
}

func TestSelectFrontedClientIndexesKeepsTwoSuccessfulHosts(t *testing.T) {
	results := []frontedProbeResult{
		{index: 0, host: "www.google.com", client: &http.Client{}, samples: []time.Duration{100 * time.Millisecond, 100 * time.Millisecond}},
		{index: 1, host: "mail.google.com", client: &http.Client{}, samples: []time.Duration{450 * time.Millisecond, 460 * time.Millisecond}},
		{index: 2, host: "accounts.google.com", client: &http.Client{}, err: context.DeadlineExceeded},
	}

	got := selectFrontedClientIndexes(results)
	if len(got) != 2 || got[0] != 0 || got[1] != 1 {
		t.Fatalf("got %v want [0 1]", got)
	}
}

func TestSelectFrontedClientIndexesFallsBackWhenAllFail(t *testing.T) {
	results := []frontedProbeResult{
		{index: 0, host: "www.google.com", client: &http.Client{}, err: context.DeadlineExceeded},
		{index: 1, host: "mail.google.com", client: &http.Client{}, err: context.DeadlineExceeded},
	}

	got := selectFrontedClientIndexes(results)
	if len(got) != 2 || got[0] != 0 || got[1] != 1 {
		t.Fatalf("got %v want [0 1]", got)
	}
}

func TestSelectFrontedClientIndexesUsesSingleHealthyHostWhenNeeded(t *testing.T) {
	results := []frontedProbeResult{
		{index: 0, host: "www.google.com", client: &http.Client{}, samples: []time.Duration{95 * time.Millisecond, 105 * time.Millisecond}},
		{index: 1, host: "mail.google.com", client: &http.Client{}, err: context.DeadlineExceeded},
		{index: 2, host: "accounts.google.com", client: &http.Client{}, err: context.DeadlineExceeded},
	}

	got := selectFrontedClientIndexes(results)
	if len(got) != 1 || got[0] != 0 {
		t.Fatalf("got %v want [0]", got)
	}
}

func TestValidateFrontedProbeResponse(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		body       []byte
		wantErr    bool
	}{
		{name: "ok", statusCode: http.StatusOK, body: []byte(frontedProbeOKBody), wantErr: false},
		{name: "ok trimmed", statusCode: http.StatusOK, body: []byte("  " + frontedProbeOKBody + "\n"), wantErr: false},
		{name: "ok json", statusCode: http.StatusOK, body: []byte(`{"ok":true,"version":1,"protocol":1}`), wantErr: false},
		{name: "json protocol mismatch", statusCode: http.StatusOK, body: []byte(`{"ok":true,"version":1,"protocol":999}`), wantErr: true},
		{name: "quota page", statusCode: http.StatusOK, body: []byte("<html>quota exceeded</html>"), wantErr: true},
		{name: "status fail", statusCode: http.StatusTooManyRequests, body: []byte(frontedProbeOKBody), wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateFrontedProbeResponse(tc.statusCode, tc.body)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err=%v wantErr=%v", err, tc.wantErr)
			}
		})
	}
}

func TestReadFrontedProbeBodyRejectsOversizedBody(t *testing.T) {
	_, err := readFrontedProbeBody(io.NopCloser(&endlessReader{}))
	if err == nil {
		t.Fatal("readFrontedProbeBody succeeded on oversized body")
	}
}

type endlessReader struct{}

func (r *endlessReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'x'
	}
	return len(p), nil
}

func (r *endlessReader) Close() error {
	return nil
}

func TestReadFrontedProbeBodyPropagatesReadError(t *testing.T) {
	want := errors.New("boom")
	_, err := readFrontedProbeBody(io.NopCloser(errReader{err: want}))
	if !errors.Is(err, want) {
		t.Fatalf("err=%v, want %v", err, want)
	}
}

type errReader struct {
	err error
}

func (r errReader) Read([]byte) (int, error) {
	return 0, r.err
}

func TestConfigureFrontedHTTP2UsesFastBlackholeDetection(t *testing.T) {
	h2t, err := configureFrontedHTTP2(&http.Transport{})
	if err != nil {
		t.Fatalf("configureFrontedHTTP2: %v", err)
	}
	if h2t.ReadIdleTimeout != 12*time.Second {
		t.Fatalf("ReadIdleTimeout = %v, want 12s", h2t.ReadIdleTimeout)
	}
	if h2t.PingTimeout != 8*time.Second {
		t.Fatalf("PingTimeout = %v, want 8s", h2t.PingTimeout)
	}
	if h2t.MaxReadFrameSize != 1<<20 {
		t.Fatalf("MaxReadFrameSize = %d, want 1MiB", h2t.MaxReadFrameSize)
	}
}

func TestNewFrontedClientHTTPVersionToggle(t *testing.T) {
	tests := []struct {
		name          string
		mode          string
		wantForceH2   bool
		wantNextProto []string
	}{
		{name: "default auto", mode: "", wantForceH2: true, wantNextProto: []string{"h2", "http/1.1"}},
		{name: "auto", mode: "auto", wantForceH2: true, wantNextProto: []string{"h2", "http/1.1"}},
		{name: "h1", mode: "h1", wantForceH2: false, wantNextProto: []string{"http/1.1"}},
		{name: "h2", mode: "h2", wantForceH2: true, wantNextProto: []string{"h2"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			client := newFrontedClient("", "www.google.com", time.Second, nil, tc.mode, workersPerEndpoint)
			tr, ok := client.Transport.(*http.Transport)
			if !ok {
				t.Fatalf("transport type = %T, want *http.Transport", client.Transport)
			}
			if tr.ForceAttemptHTTP2 != tc.wantForceH2 {
				t.Fatalf("ForceAttemptHTTP2 = %v, want %v", tr.ForceAttemptHTTP2, tc.wantForceH2)
			}
			if got := tr.TLSClientConfig.NextProtos; len(got) != len(tc.wantNextProto) {
				t.Fatalf("NextProtos = %v, want %v", got, tc.wantNextProto)
			} else {
				for i := range got {
					if got[i] != tc.wantNextProto[i] {
						t.Fatalf("NextProtos = %v, want %v", got, tc.wantNextProto)
					}
				}
			}
		})
	}
}
