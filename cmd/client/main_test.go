package main

import (
	"strings"
	"testing"

	"github.com/kianmhz/GooseRelayVPN/internal/config"
)

func TestHotReloadRestartReasonAllowsEndpointOnlyChanges(t *testing.T) {
	current := &config.Client{
		AESKeyHex:     strings.Repeat("a", 64),
		UseFronting:   true,
		GoogleIP:      "142.250.1.1:443",
		SNIHosts:      []string{"www.google.com"},
		ScriptURLs:    []string{"https://script.google.com/macros/s/old/exec"},
		SocksUser:     "u",
		SocksPass:     "p",
		DebugTiming:   true,
		ListenAddr:    "127.0.0.1:1080",
		CoalesceMaxMs: 25,
	}
	next := *current
	next.ScriptURLs = []string{"https://script.google.com/macros/s/new/exec"}
	next.ScriptAccounts = []string{"account-b"}

	if reason := hotReloadRestartReason(current, &next); reason != "" {
		t.Fatalf("endpoint-only reload should be allowed, got restart reason %q", reason)
	}
}

func TestHotReloadRestartReasonRejectsWorkerPlanChanges(t *testing.T) {
	current := &config.Client{
		AESKeyHex:          strings.Repeat("a", 64),
		TransportMode:      "apps_script",
		UseFronting:        true,
		GoogleIP:           "142.250.1.1:443",
		SNIHosts:           []string{"www.google.com"},
		ScriptURLs:         []string{"https://script.google.com/macros/s/a/exec"},
		ScriptAccounts:     []string{"account-a"},
		WorkersPerEndpoint: 4,
		IdleSlotsPerBucket: 1,
	}
	next := *current
	next.ScriptURLs = []string{
		"https://script.google.com/macros/s/a/exec",
		"https://script.google.com/macros/s/b/exec",
	}
	next.ScriptAccounts = []string{"account-a", "account-b"}

	reason := hotReloadRestartReason(current, &next)
	if !strings.Contains(reason, "worker count") {
		t.Fatalf("reason = %q, want worker count restart", reason)
	}
}

func TestHotReloadRestartReasonRejectsTransportAndKeyChanges(t *testing.T) {
	current := &config.Client{
		AESKeyHex:   strings.Repeat("a", 64),
		UseFronting: true,
		GoogleIP:    "142.250.1.1:443",
		SNIHosts:    []string{"www.google.com"},
	}

	cases := []struct {
		name   string
		mutate func(*config.Client)
		want   string
	}{
		{
			name: "key",
			mutate: func(c *config.Client) {
				c.AESKeyHex = strings.Repeat("b", 64)
			},
			want: "tunnel_key",
		},
		{
			name: "mode",
			mutate: func(c *config.Client) {
				c.UseFronting = false
			},
			want: "relay mode",
		},
		{
			name: "fronting host",
			mutate: func(c *config.Client) {
				c.GoogleIP = "142.250.2.2:443"
			},
			want: "google_host",
		},
		{
			name: "sni",
			mutate: func(c *config.Client) {
				c.SNIHosts = []string{"mail.google.com"}
			},
			want: "sni",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			next := *current
			next.SNIHosts = append([]string(nil), current.SNIHosts...)
			tc.mutate(&next)
			reason := hotReloadRestartReason(current, &next)
			if !strings.Contains(reason, tc.want) {
				t.Fatalf("reason = %q, want it to mention %q", reason, tc.want)
			}
		})
	}
}

func TestHotReloadRestartReasonRejectsRuntimeOnlyChanges(t *testing.T) {
	current := &config.Client{
		AESKeyHex:                strings.Repeat("a", 64),
		TransportMode:            "apps_script",
		UseFronting:              true,
		GoogleIP:                 "142.250.1.1:443",
		SNIHosts:                 []string{"www.google.com"},
		ScriptURLs:               []string{"https://script.google.com/macros/s/a/exec"},
		ScriptAccounts:           []string{"account-a"},
		ListenAddr:               "127.0.0.1:1080",
		PollIdleSleepMs:          10,
		EndpointBlacklistBaseMs:  3000,
		EndpointBlacklistMaxMs:   60000,
		MaxRequestBytesPreEncode: 8 << 20,
		StreamConnectTimeoutMs:   5000,
		StreamPingIntervalMs:     20000,
		StreamReconnectBackoffMs: 1000,
	}
	cases := []struct {
		name   string
		mutate func(*config.Client)
		want   string
	}{
		{name: "listen", mutate: func(c *config.Client) { c.ListenAddr = "127.0.0.1:1081" }, want: "SOCKS listen"},
		{name: "auth", mutate: func(c *config.Client) { c.SocksUser, c.SocksPass = "u", "p" }, want: "SOCKS auth"},
		{name: "poll", mutate: func(c *config.Client) { c.PollIdleSleepMs = 5 }, want: "poll_idle_sleep_ms"},
		{name: "blacklist", mutate: func(c *config.Client) { c.EndpointBlacklistBaseMs = 1000 }, want: "blacklist"},
		{name: "request budget", mutate: func(c *config.Client) { c.MaxRequestBytesPreEncode = 16 << 20 }, want: "max_request_bytes_pre_encode"},
		{name: "stream timeout", mutate: func(c *config.Client) { c.StreamReconnectBackoffMs = 2000 }, want: "direct stream timeout"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			next := *current
			next.SNIHosts = append([]string(nil), current.SNIHosts...)
			next.ScriptURLs = append([]string(nil), current.ScriptURLs...)
			next.ScriptAccounts = append([]string(nil), current.ScriptAccounts...)
			tc.mutate(&next)
			reason := hotReloadRestartReason(current, &next)
			if !strings.Contains(reason, tc.want) {
				t.Fatalf("reason = %q, want it to mention %q", reason, tc.want)
			}
		})
	}
}
