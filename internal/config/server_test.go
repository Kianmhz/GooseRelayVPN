package config

import (
	"os"
	"path/filepath"
	"testing"
)

func writeServerConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "server.json")
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

func TestLoadServer_PerformanceModeLatencyAppliesFastDefaults(t *testing.T) {
	path := writeServerConfig(t, `{
		"tunnel_key": "`+configTestKey+`",
		"performance_mode": "latency",
		"auto_tune": true
	}`)

	cfg, err := LoadServer(path)
	if err != nil {
		t.Fatalf("LoadServer: %v", err)
	}

	if cfg.PerformanceMode != "latency" {
		t.Fatalf("PerformanceMode = %q, want latency", cfg.PerformanceMode)
	}
	if !cfg.AutoTune {
		t.Fatal("AutoTune = false, want true")
	}
	if cfg.ActiveDrainWindowMs != 150 {
		t.Fatalf("ActiveDrainWindowMs = %d, want 150", cfg.ActiveDrainWindowMs)
	}
	if cfg.LongPollWindowMs != 6000 {
		t.Fatalf("LongPollWindowMs = %d, want 6000", cfg.LongPollWindowMs)
	}
	if cfg.UpstreamDialTimeoutMs != 8000 {
		t.Fatalf("UpstreamDialTimeoutMs = %d, want 8000", cfg.UpstreamDialTimeoutMs)
	}
	if cfg.CoalesceWindowMs != 0 || cfg.CoalesceWindowBusyMs != 0 {
		t.Fatalf("latency coalesce windows = %d/%d, want 0/0", cfg.CoalesceWindowMs, cfg.CoalesceWindowBusyMs)
	}
}

func TestLoadServer_ExplicitPerformanceKnobsOverrideProfile(t *testing.T) {
	path := writeServerConfig(t, `{
		"tunnel_key": "`+configTestKey+`",
		"performance_mode": "latency",
		"active_drain_window_ms": 275,
		"long_poll_window_ms": 6000,
		"upstream_dial_timeout_ms": 9000,
		"coalesce_window_ms": 11,
		"coalesce_window_busy_ms": 4,
		"max_sessions": 123,
		"max_request_body_bytes": 2097152,
		"max_response_bytes_pre_encode": 1048576
	}`)

	cfg, err := LoadServer(path)
	if err != nil {
		t.Fatalf("LoadServer: %v", err)
	}

	if cfg.ActiveDrainWindowMs != 275 {
		t.Fatalf("ActiveDrainWindowMs = %d, want explicit 275", cfg.ActiveDrainWindowMs)
	}
	if cfg.LongPollWindowMs != 6000 {
		t.Fatalf("LongPollWindowMs = %d, want explicit 6000", cfg.LongPollWindowMs)
	}
	if cfg.UpstreamDialTimeoutMs != 9000 {
		t.Fatalf("UpstreamDialTimeoutMs = %d, want explicit 9000", cfg.UpstreamDialTimeoutMs)
	}
	if cfg.CoalesceWindowMs != 11 {
		t.Fatalf("CoalesceWindowMs = %d, want explicit 11", cfg.CoalesceWindowMs)
	}
	if cfg.CoalesceWindowBusyMs != 4 {
		t.Fatalf("CoalesceWindowBusyMs = %d, want explicit 4", cfg.CoalesceWindowBusyMs)
	}
	if cfg.MaxSessions != 123 {
		t.Fatalf("MaxSessions = %d, want explicit 123", cfg.MaxSessions)
	}
	if cfg.MaxRequestBodyBytes != 2097152 {
		t.Fatalf("MaxRequestBodyBytes = %d, want explicit 2097152", cfg.MaxRequestBodyBytes)
	}
	if cfg.MaxResponseBytesPreEncode != 1048576 {
		t.Fatalf("MaxResponseBytesPreEncode = %d, want explicit 1048576", cfg.MaxResponseBytesPreEncode)
	}
}

func TestLoadServer_DefaultMaxSessions(t *testing.T) {
	path := writeServerConfig(t, `{
		"tunnel_key": "`+configTestKey+`"
	}`)

	cfg, err := LoadServer(path)
	if err != nil {
		t.Fatalf("LoadServer: %v", err)
	}
	if cfg.MaxSessions != 4096 {
		t.Fatalf("MaxSessions = %d, want default 4096", cfg.MaxSessions)
	}
}

func TestLoadServer_RejectsUnknownPerformanceMode(t *testing.T) {
	path := writeServerConfig(t, `{
		"tunnel_key": "`+configTestKey+`",
		"performance_mode": "warp-speed"
	}`)

	if _, err := LoadServer(path); err == nil {
		t.Fatal("LoadServer succeeded with unknown performance_mode")
	}
}
