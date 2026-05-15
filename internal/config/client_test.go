package config

import (
	"os"
	"path/filepath"
	"testing"
)

const configTestKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func writeClientConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "client.json")
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

func TestLoadClient_PerformanceModeLatencyAppliesFastDefaults(t *testing.T) {
	path := writeClientConfig(t, `{
		"script_keys": ["AKfycbabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz1234567890"],
		"tunnel_key": "`+configTestKey+`",
		"performance_mode": "latency"
	}`)

	cfg, err := LoadClient(path)
	if err != nil {
		t.Fatalf("LoadClient: %v", err)
	}

	if cfg.PerformanceMode != "latency" {
		t.Fatalf("PerformanceMode = %q, want latency", cfg.PerformanceMode)
	}
	if cfg.CoalesceStepMs != 0 || cfg.CoalesceMaxMs != 0 {
		t.Fatalf("latency mode coalescing = step %d max %d, want 0/0", cfg.CoalesceStepMs, cfg.CoalesceMaxMs)
	}
	if cfg.IdleSlotsPerBucket != 1 {
		t.Fatalf("IdleSlotsPerBucket = %d, want 1", cfg.IdleSlotsPerBucket)
	}
	if cfg.WorkersPerEndpoint != 4 {
		t.Fatalf("WorkersPerEndpoint = %d, want 4", cfg.WorkersPerEndpoint)
	}
	if cfg.PollIdleSleepMs != 5 {
		t.Fatalf("PollIdleSleepMs = %d, want 5", cfg.PollIdleSleepMs)
	}
	if got, want := cfg.SNIHosts, []string{"www.google.com", "mail.google.com", "accounts.google.com"}; len(got) != len(want) || got[0] != want[0] || got[1] != want[1] || got[2] != want[2] {
		t.Fatalf("SNIHosts = %v, want %v", got, want)
	}
	if cfg.EndpointOutageGraceMs != 60000 {
		t.Fatalf("EndpointOutageGraceMs = %d, want 60000", cfg.EndpointOutageGraceMs)
	}
	if cfg.MaxRequestBytesPreEncode != 8*1024*1024 {
		t.Fatalf("MaxRequestBytesPreEncode = %d, want 8MiB", cfg.MaxRequestBytesPreEncode)
	}
}

func TestParseSNIHosts_MalformedFallsBackToMultiDefault(t *testing.T) {
	got := parseSNIHosts([]byte(`{"not":"a valid sni shape"}`))
	want := []string{"www.google.com", "mail.google.com", "accounts.google.com"}
	if len(got) != len(want) {
		t.Fatalf("parseSNIHosts length = %d (%v), want %d (%v)", len(got), got, len(want), want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("parseSNIHosts = %v, want %v", got, want)
		}
	}
}

func TestLoadClient_PerformanceModeThroughputAppliesBatchingDefaults(t *testing.T) {
	path := writeClientConfig(t, `{
		"relay_urls": ["http://127.0.0.1:8443/tunnel"],
		"tunnel_key": "`+configTestKey+`",
		"performance_mode": "throughput"
	}`)

	cfg, err := LoadClient(path)
	if err != nil {
		t.Fatalf("LoadClient: %v", err)
	}

	if cfg.CoalesceStepMs != 25 {
		t.Fatalf("CoalesceStepMs = %d, want 25", cfg.CoalesceStepMs)
	}
	if cfg.IdleSlotsPerBucket != 2 {
		t.Fatalf("IdleSlotsPerBucket = %d, want 2", cfg.IdleSlotsPerBucket)
	}
}

func TestLoadClient_ExplicitPerformanceKnobsOverrideProfile(t *testing.T) {
	path := writeClientConfig(t, `{
		"relay_urls": ["http://127.0.0.1:8443/tunnel"],
		"tunnel_key": "`+configTestKey+`",
		"performance_mode": "throughput",
		"coalesce_step_ms": 7,
		"idle_slots_per_bucket": 3,
		"workers_per_endpoint": 6,
		"poll_idle_sleep_ms": 12,
		"max_request_bytes_pre_encode": 1048576
	}`)

	cfg, err := LoadClient(path)
	if err != nil {
		t.Fatalf("LoadClient: %v", err)
	}

	if cfg.CoalesceStepMs != 7 {
		t.Fatalf("CoalesceStepMs = %d, want explicit 7", cfg.CoalesceStepMs)
	}
	if cfg.IdleSlotsPerBucket != 3 {
		t.Fatalf("IdleSlotsPerBucket = %d, want explicit 3", cfg.IdleSlotsPerBucket)
	}
	if cfg.WorkersPerEndpoint != 6 {
		t.Fatalf("WorkersPerEndpoint = %d, want explicit 6", cfg.WorkersPerEndpoint)
	}
	if cfg.PollIdleSleepMs != 12 {
		t.Fatalf("PollIdleSleepMs = %d, want explicit 12", cfg.PollIdleSleepMs)
	}
	if cfg.MaxRequestBytesPreEncode != 1048576 {
		t.Fatalf("MaxRequestBytesPreEncode = %d, want explicit 1048576", cfg.MaxRequestBytesPreEncode)
	}
}

func TestLoadClient_RejectsUnknownPerformanceMode(t *testing.T) {
	path := writeClientConfig(t, `{
		"relay_urls": ["http://127.0.0.1:8443/tunnel"],
		"tunnel_key": "`+configTestKey+`",
		"performance_mode": "warp-speed"
	}`)

	if _, err := LoadClient(path); err == nil {
		t.Fatal("LoadClient succeeded with unknown performance_mode")
	}
}

func TestLoadClient_AutoTransportAllowsDirectStreamOnly(t *testing.T) {
	path := writeClientConfig(t, `{
		"direct_stream_urls": ["http://127.0.0.1:8443/tunnel"],
		"tunnel_key": "`+configTestKey+`"
	}`)

	cfg, err := LoadClient(path)
	if err != nil {
		t.Fatalf("LoadClient: %v", err)
	}
	if cfg.TransportMode != "auto" {
		t.Fatalf("TransportMode = %q, want auto", cfg.TransportMode)
	}
	if cfg.UseFronting {
		t.Fatal("UseFronting = true, want false when only direct_stream_urls are configured")
	}
	if len(cfg.ScriptURLs) != 0 {
		t.Fatalf("ScriptURLs = %v, want none for stream-only config", cfg.ScriptURLs)
	}
	if got, want := cfg.DirectStreamURLs, []string{"ws://127.0.0.1:8443/stream"}; len(got) != len(want) || got[0] != want[0] {
		t.Fatalf("DirectStreamURLs = %v, want %v", got, want)
	}
	if cfg.StreamConnectTimeoutMs <= 0 || cfg.StreamPingIntervalMs <= 0 || cfg.StreamReconnectBackoffMs <= 0 {
		t.Fatalf("stream timeouts should resolve to positive defaults: connect=%d ping=%d backoff=%d",
			cfg.StreamConnectTimeoutMs, cfg.StreamPingIntervalMs, cfg.StreamReconnectBackoffMs)
	}
}

func TestLoadClient_RejectsDirectStreamModeWithoutStreamURLs(t *testing.T) {
	path := writeClientConfig(t, `{
		"transport_mode": "direct_stream",
		"relay_urls": ["http://127.0.0.1:8443/tunnel"],
		"tunnel_key": "`+configTestKey+`"
	}`)

	if _, err := LoadClient(path); err == nil {
		t.Fatal("LoadClient succeeded with direct_stream mode but no direct_stream_urls")
	}
}

func TestLoadClient_DirectPostModeRequiresRelayURLs(t *testing.T) {
	path := writeClientConfig(t, `{
		"transport_mode": "direct_post",
		"direct_stream_urls": ["ws://127.0.0.1:8443/stream"],
		"tunnel_key": "`+configTestKey+`"
	}`)

	if _, err := LoadClient(path); err == nil {
		t.Fatal("LoadClient succeeded with direct_post mode but no relay_urls")
	}
}
