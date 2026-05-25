package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/kianmhz/GooseRelayVPN/internal/config"
)

func TestConfigureCertificateBundleUsesTermuxPrefix(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Termux CA fallback only runs on linux builds")
	}
	t.Setenv("SSL_CERT_FILE", "")
	dir := t.TempDir()
	certPath := filepath.Join(dir, "etc", "tls", "cert.pem")
	if err := os.MkdirAll(filepath.Dir(certPath), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(certPath, []byte("test cert"), 0o644); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	t.Setenv("PREFIX", dir)

	got, ok := configureCertificateBundle()
	if !ok || got != certPath {
		t.Fatalf("configureCertificateBundle = %q, %v; want %q, true", got, ok, certPath)
	}
	if env := os.Getenv("SSL_CERT_FILE"); env != certPath {
		t.Fatalf("SSL_CERT_FILE = %q, want %q", env, certPath)
	}
}

func TestConfigureCertificateBundleDoesNotOverrideExplicitEnv(t *testing.T) {
	t.Setenv("SSL_CERT_FILE", "/custom/cert.pem")
	t.Setenv("PREFIX", t.TempDir())
	if got, ok := configureCertificateBundle(); ok || got != "" {
		t.Fatalf("configureCertificateBundle = %q, %v; want no override", got, ok)
	}
	if env := os.Getenv("SSL_CERT_FILE"); env != "/custom/cert.pem" {
		t.Fatalf("SSL_CERT_FILE = %q, want explicit value preserved", env)
	}
}

func TestClientLogWriterWritesPlainCopyToFile(t *testing.T) {
	var terminal bytes.Buffer
	var saved bytes.Buffer
	w := &clientLogWriter{out: &terminal, file: &saved, useColor: true}

	n, err := w.Write([]byte("[client] saved for debugging\n"))
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if n != len("[client] saved for debugging\n") {
		t.Fatalf("Write returned %d bytes, want original input length", n)
	}
	if !strings.Contains(terminal.String(), "\x1b[") {
		t.Fatalf("terminal output should preserve color when enabled, got %q", terminal.String())
	}
	if strings.Contains(saved.String(), "\x1b[") {
		t.Fatalf("saved log must not include ANSI color escapes, got %q", saved.String())
	}
	if !strings.Contains(saved.String(), "CLIENT  INFO") || !strings.Contains(saved.String(), "saved for debugging") {
		t.Fatalf("saved log did not receive formatted line, got %q", saved.String())
	}
}

func TestShortScriptKeyRedactsDirectURLUserinfoAndQuery(t *testing.T) {
	got := shortScriptKey("https://user:secret@example.com:8443/s/private/token/path?token=abc123")
	if got != "example.com:8443" {
		t.Fatalf("shortScriptKey = %q, want only host:port", got)
	}
	if strings.Contains(got, "secret") || strings.Contains(got, "token") || strings.Contains(got, "private") {
		t.Fatalf("shortScriptKey leaked URL credentials/query: %q", got)
	}
}

func TestShouldIgnoreServeErrorAllowsContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if !shouldIgnoreServeError(ctx, context.Canceled) {
		t.Fatal("context.Canceled during shutdown should be ignored")
	}
	if shouldIgnoreServeError(context.Background(), errors.New("bind failed")) {
		t.Fatal("ordinary SOCKS serve errors must not be ignored")
	}
}

func TestClientShutdownTimeoutUsesLongerAppsScriptGrace(t *testing.T) {
	cases := []struct {
		name string
		cfg  *config.Client
		want time.Duration
	}{
		{name: "nil config", want: 5 * time.Second},
		{name: "apps script", cfg: &config.Client{TransportMode: "apps_script", ScriptURLs: []string{"https://script.google.com/macros/s/x/exec"}}, want: 15 * time.Second},
		{name: "auto with scripts", cfg: &config.Client{TransportMode: "auto", ScriptURLs: []string{"https://script.google.com/macros/s/x/exec"}}, want: 15 * time.Second},
		{name: "direct stream", cfg: &config.Client{TransportMode: "direct_stream"}, want: 5 * time.Second},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := clientShutdownTimeout(tc.cfg); got != tc.want {
				t.Fatalf("clientShutdownTimeout = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestSocksListenNeedsAuthWarning(t *testing.T) {
	cases := []struct {
		name       string
		listenAddr string
		user       string
		pass       string
		want       bool
	}{
		{name: "loopback IPv4", listenAddr: "127.0.0.1:1080"},
		{name: "localhost", listenAddr: "localhost:1080"},
		{name: "wildcard IPv4 without auth", listenAddr: "0.0.0.0:1080", want: true},
		{name: "wildcard IPv6 without auth", listenAddr: "[::]:1080", want: true},
		{name: "LAN IPv4 without auth", listenAddr: "192.168.1.20:1080", want: true},
		{name: "LAN IPv4 with auth", listenAddr: "192.168.1.20:1080", user: "u", pass: "p"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := socksListenNeedsAuthWarning(tc.listenAddr, tc.user, tc.pass); got != tc.want {
				t.Fatalf("socksListenNeedsAuthWarning(%q, %q, pass-set=%v) = %v, want %v", tc.listenAddr, tc.user, tc.pass != "", got, tc.want)
			}
		})
	}
}

func TestEnsureClientInstanceIDCreatesAndReusesStableID(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "client_config.json")
	cfg := &config.Client{FreshStartReset: true}

	first, err := ensureClientInstanceID(configPath, cfg)
	if err != nil {
		t.Fatalf("ensureClientInstanceID first: %v", err)
	}
	if len(first) != 32 {
		t.Fatalf("generated instance id length = %d, want 32 hex chars", len(first))
	}
	if _, err := os.Stat(filepath.Join(dir, ".goose-client-instance")); err != nil {
		t.Fatalf("instance file was not created beside config: %v", err)
	}

	second, err := ensureClientInstanceID(configPath, &config.Client{FreshStartReset: true})
	if err != nil {
		t.Fatalf("ensureClientInstanceID second: %v", err)
	}
	if second != first {
		t.Fatalf("second instance id = %q, want stable %q", second, first)
	}
}

func TestEnsureClientInstanceIDFallsBackWhenDefaultFileCannotPersist(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, ".goose-client-instance"), 0o755); err != nil {
		t.Fatalf("mkdir instance path: %v", err)
	}
	got, err := ensureClientInstanceID(filepath.Join(dir, "client_config.json"), &config.Client{
		FreshStartReset: true,
	})
	if err != nil {
		t.Fatalf("ensureClientInstanceID should not fail when only the default generated file is unusable: %v", err)
	}
	if len(got) != 32 {
		t.Fatalf("fallback instance id length = %d, want 32", len(got))
	}
}

func TestEnsureClientInstanceIDUsesExplicitIDWithoutFile(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "client_config.json")
	got, err := ensureClientInstanceID(configPath, &config.Client{
		FreshStartReset:  true,
		ClientInstanceID: "phone-main",
	})
	if err != nil {
		t.Fatalf("ensureClientInstanceID: %v", err)
	}
	if got != "phone-main" {
		t.Fatalf("instance id = %q", got)
	}
	if _, err := os.Stat(filepath.Join(dir, ".goose-client-instance")); !os.IsNotExist(err) {
		t.Fatalf("explicit id should not create default state file; stat err=%v", err)
	}
}

func TestEnsureClientInstanceIDDisabled(t *testing.T) {
	got, err := ensureClientInstanceID(filepath.Join(t.TempDir(), "client_config.json"), &config.Client{})
	if err != nil {
		t.Fatalf("ensureClientInstanceID: %v", err)
	}
	if got != "" {
		t.Fatalf("disabled instance id = %q, want empty", got)
	}
}

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

func TestLogUnknownFieldsForReload(t *testing.T) {
	var buf bytes.Buffer
	logUnknownFieldsForReload(&config.Client{UnknownFields: []string{"typo_field"}}, &buf)
	if got := buf.String(); !strings.Contains(got, "typo_field") {
		t.Fatalf("reload warning = %q, want unknown field name", got)
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
	next.ScriptAccounts = []string{"account-a", "account-a"}

	reason := hotReloadRestartReason(current, &next)
	if !strings.Contains(reason, "worker count") {
		t.Fatalf("reason = %q, want worker count restart", reason)
	}
}

func TestHotReloadRestartReasonRejectsUnlabeledEndpointCountChanges(t *testing.T) {
	current := &config.Client{
		AESKeyHex:          strings.Repeat("a", 64),
		TransportMode:      "apps_script",
		UseFronting:        true,
		GoogleIP:           "142.250.1.1:443",
		SNIHosts:           []string{"www.google.com"},
		ScriptURLs:         []string{"https://script.google.com/macros/s/a/exec"},
		WorkersPerEndpoint: 3,
	}
	next := *current
	next.ScriptURLs = []string{
		"https://script.google.com/macros/s/a/exec",
		"https://script.google.com/macros/s/b/exec",
	}

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

func TestHotReloadRestartReasonRejectsFreshStartIdentityChanges(t *testing.T) {
	current := &config.Client{
		AESKeyHex:            strings.Repeat("a", 64),
		FreshStartReset:      true,
		ClientInstanceID:     "phone-a",
		ClientInstanceIDFile: ".goose-client-instance",
	}

	cases := []struct {
		name   string
		mutate func(*config.Client)
		want   string
	}{
		{
			name: "fresh reset",
			mutate: func(c *config.Client) {
				c.FreshStartReset = false
			},
			want: "fresh_start_reset",
		},
		{
			name: "instance id",
			mutate: func(c *config.Client) {
				c.ClientInstanceID = "phone-b"
			},
			want: "client_instance_id",
		},
		{
			name: "instance file",
			mutate: func(c *config.Client) {
				c.ClientInstanceIDFile = "other-instance"
			},
			want: "client_instance_id_file",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			next := *current
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
		EndpointOutageGraceMs:    60000,
		EndpointBlacklistBaseMs:  3000,
		EndpointBlacklistMaxMs:   60000,
		MaxRequestBytesPreEncode: 8 << 20,
		TxBufferBudgetBytes:      64 << 20,
		StreamConnectTimeoutMs:   5000,
		StreamPingIntervalMs:     20000,
		StreamReconnectBackoffMs: 1000,
		FrontingHTTPVersion:      "auto",
	}
	cases := []struct {
		name   string
		mutate func(*config.Client)
		want   string
	}{
		{name: "listen", mutate: func(c *config.Client) { c.ListenAddr = "127.0.0.1:1081" }, want: "SOCKS listen"},
		{name: "auth", mutate: func(c *config.Client) { c.SocksUser, c.SocksPass = "u", "p" }, want: "SOCKS auth"},
		{name: "poll", mutate: func(c *config.Client) { c.PollIdleSleepMs = 5 }, want: "poll_idle_sleep_ms"},
		{name: "idle slots", mutate: func(c *config.Client) { c.IdleSlotsPerBucket = 2 }, want: "idle_slots_per_bucket"},
		{name: "endpoint outage grace", mutate: func(c *config.Client) { c.EndpointOutageGraceMs = 300000 }, want: "endpoint_outage_grace_ms"},
		{name: "blacklist", mutate: func(c *config.Client) { c.EndpointBlacklistBaseMs = 1000 }, want: "blacklist"},
		{name: "request budget", mutate: func(c *config.Client) { c.MaxRequestBytesPreEncode = 16 << 20 }, want: "max_request_bytes_pre_encode"},
		{name: "tx budget", mutate: func(c *config.Client) { c.TxBufferBudgetBytes = 32 << 20 }, want: "tx_buffer_budget_bytes"},
		{name: "stream timeout", mutate: func(c *config.Client) { c.StreamReconnectBackoffMs = 2000 }, want: "direct stream timeout"},
		{name: "fronting http version", mutate: func(c *config.Client) { c.FrontingHTTPVersion = "h1" }, want: "fronting_http_version"},
		{name: "stats json", mutate: func(c *config.Client) { c.StatsJSON = true }, want: "stats_json"},
		{name: "pprof", mutate: func(c *config.Client) { c.DebugPprofAddr = "127.0.0.1:6060" }, want: "debug_pprof_addr"},
		{name: "startup diagnostics", mutate: func(c *config.Client) { c.WriteStartupDiagnostics = true }, want: "write_startup_diagnostics"},
		{name: "local session cap", mutate: func(c *config.Client) { c.MaxLocalSessions = 512 }, want: "max_local_sessions"},
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
