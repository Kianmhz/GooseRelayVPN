package carrier

import (
	"context"
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
