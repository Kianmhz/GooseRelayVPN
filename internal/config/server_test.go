package config

import (
	"os"
	"path/filepath"
	"strings"
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
	if cfg.InitialResponseBytesPreEncode != 512*1024 {
		t.Fatalf("InitialResponseBytesPreEncode = %d, want 512KiB", cfg.InitialResponseBytesPreEncode)
	}
	if cfg.SecondResponseBytesPreEncode != 1024*1024 {
		t.Fatalf("SecondResponseBytesPreEncode = %d, want default 1MiB", cfg.SecondResponseBytesPreEncode)
	}
	if cfg.MaxResponseBytesPreEncode != 6*1024*1024 {
		t.Fatalf("MaxResponseBytesPreEncode = %d, want default 6MiB", cfg.MaxResponseBytesPreEncode)
	}
	if cfg.MaxRequestBodyBytes != 12*1024*1024 {
		t.Fatalf("MaxRequestBodyBytes = %d, want default 12MiB", cfg.MaxRequestBodyBytes)
	}
	if cfg.MaxDrainFramesPerSession != 8 {
		t.Fatalf("MaxDrainFramesPerSession = %d, want default 8", cfg.MaxDrainFramesPerSession)
	}
}

func TestLoadServer_AcceptsUTF8BOM(t *testing.T) {
	path := writeServerConfig(t, "\xef\xbb\xbf"+`{
		"tunnel_key": "`+configTestKey+`"
	}`)

	if _, err := LoadServer(path); err != nil {
		t.Fatalf("LoadServer with UTF-8 BOM: %v", err)
	}
}

func TestLoadServer_ParsesUpstreamProxyCredentials(t *testing.T) {
	path := writeServerConfig(t, `{
		"tunnel_key": "`+configTestKey+`",
		"upstream_proxy": "socks5://user:pass@127.0.0.1:40000"
	}`)

	cfg, err := LoadServer(path)
	if err != nil {
		t.Fatalf("LoadServer: %v", err)
	}
	if cfg.UpstreamProxy != "127.0.0.1:40000" {
		t.Fatalf("UpstreamProxy = %q, want host:port only", cfg.UpstreamProxy)
	}
	if cfg.UpstreamProxyUser != "user" || cfg.UpstreamProxyPass != "pass" {
		t.Fatalf("proxy auth = %q/%q, want user/pass", cfg.UpstreamProxyUser, cfg.UpstreamProxyPass)
	}
}

func TestLoadServer_RejectsMalformedUpstreamProxy(t *testing.T) {
	for name, raw := range map[string]string{
		"missing port":       "socks5://127.0.0.1",
		"bad port":           "socks5://127.0.0.1:notaport",
		"port too high":      "socks5://127.0.0.1:70000",
		"password no user":   "socks5://:pass@127.0.0.1:40000",
		"username too long":  "socks5://" + strings.Repeat("u", 256) + "@127.0.0.1:40000",
		"password too long":  "socks5://user:" + strings.Repeat("p", 256) + "@127.0.0.1:40000",
		"unsupported scheme": "http://127.0.0.1:40000",
		"missing host":       "socks5://",
	} {
		t.Run(name, func(t *testing.T) {
			path := writeServerConfig(t, `{
				"tunnel_key": "`+configTestKey+`",
				"upstream_proxy": "`+raw+`"
			}`)
			if _, err := LoadServer(path); err == nil {
				t.Fatalf("LoadServer accepted malformed upstream_proxy %q", raw)
			}
		})
	}
}

func TestLoadServer_InvalidUpstreamProxyDoesNotEchoSecret(t *testing.T) {
	path := writeServerConfig(t, `{
		"tunnel_key": "`+configTestKey+`",
		"upstream_proxy": "http://user:SECRET_PASS@proxy.example:40000"
	}`)

	_, err := LoadServer(path)
	if err == nil {
		t.Fatal("LoadServer accepted invalid upstream_proxy scheme")
	}
	if strings.Contains(err.Error(), "SECRET_PASS") || strings.Contains(err.Error(), "proxy.example") {
		t.Fatalf("error leaked raw upstream_proxy value: %v", err)
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
		"max_drain_frames_per_session": 16,
		"max_request_body_bytes": 2097152,
		"max_response_bytes_pre_encode": 1048576,
		"initial_response_bytes_pre_encode": 262144,
		"second_response_bytes_pre_encode": 524288
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
	if cfg.MaxDrainFramesPerSession != 16 {
		t.Fatalf("MaxDrainFramesPerSession = %d, want explicit 16", cfg.MaxDrainFramesPerSession)
	}
	if cfg.MaxRequestBodyBytes != 2097152 {
		t.Fatalf("MaxRequestBodyBytes = %d, want explicit 2097152", cfg.MaxRequestBodyBytes)
	}
	if cfg.MaxResponseBytesPreEncode != 1048576 {
		t.Fatalf("MaxResponseBytesPreEncode = %d, want explicit 1048576", cfg.MaxResponseBytesPreEncode)
	}
	if cfg.InitialResponseBytesPreEncode != 262144 {
		t.Fatalf("InitialResponseBytesPreEncode = %d, want explicit 262144", cfg.InitialResponseBytesPreEncode)
	}
	if cfg.SecondResponseBytesPreEncode != 524288 {
		t.Fatalf("SecondResponseBytesPreEncode = %d, want explicit 524288", cfg.SecondResponseBytesPreEncode)
	}
	if !cfg.InitialResponseCapEnabled {
		t.Fatal("InitialResponseCapEnabled = false, want default true")
	}
	if !cfg.SecondResponseCapEnabled {
		t.Fatal("SecondResponseCapEnabled = false, want default true")
	}
}

func TestLoadServer_ResponseRampCapsCanBeDisabledWithoutChangingByteValues(t *testing.T) {
	path := writeServerConfig(t, `{
		"tunnel_key": "`+configTestKey+`",
		"initial_response_cap_enabled": false,
		"initial_response_bytes_pre_encode": 524288,
		"second_response_cap_enabled": false,
		"second_response_bytes_pre_encode": 1048576
	}`)

	cfg, err := LoadServer(path)
	if err != nil {
		t.Fatalf("LoadServer: %v", err)
	}
	if cfg.InitialResponseCapEnabled {
		t.Fatal("InitialResponseCapEnabled = true, want false")
	}
	if cfg.InitialResponseBytesPreEncode != 524288 {
		t.Fatalf("InitialResponseBytesPreEncode = %d, want byte value preserved", cfg.InitialResponseBytesPreEncode)
	}
	if cfg.SecondResponseCapEnabled {
		t.Fatal("SecondResponseCapEnabled = true, want false")
	}
	if cfg.SecondResponseBytesPreEncode != 1048576 {
		t.Fatalf("SecondResponseBytesPreEncode = %d, want byte value preserved", cfg.SecondResponseBytesPreEncode)
	}
}

func TestLoadServer_RejectsTooSmallInitialResponseBytes(t *testing.T) {
	path := writeServerConfig(t, `{
		"tunnel_key": "`+configTestKey+`",
		"initial_response_bytes_pre_encode": 1024
	}`)

	if _, err := LoadServer(path); err == nil {
		t.Fatal("LoadServer succeeded with too-small initial_response_bytes_pre_encode")
	}
}

func TestLoadServer_DisabledInitialResponseCapIgnoresTooSmallByteValue(t *testing.T) {
	path := writeServerConfig(t, `{
		"tunnel_key": "`+configTestKey+`",
		"initial_response_cap_enabled": false,
		"initial_response_bytes_pre_encode": 1024
	}`)

	cfg, err := LoadServer(path)
	if err != nil {
		t.Fatalf("LoadServer: %v", err)
	}
	if cfg.InitialResponseCapEnabled {
		t.Fatal("InitialResponseCapEnabled = true, want false")
	}
	if cfg.InitialResponseBytesPreEncode != 1024 {
		t.Fatalf("InitialResponseBytesPreEncode = %d, want ignored/preserved 1024", cfg.InitialResponseBytesPreEncode)
	}
}

func TestLoadServer_RejectsTooSmallSecondResponseBytes(t *testing.T) {
	path := writeServerConfig(t, `{
		"tunnel_key": "`+configTestKey+`",
		"second_response_bytes_pre_encode": 1024
	}`)

	if _, err := LoadServer(path); err == nil {
		t.Fatal("LoadServer succeeded with too-small second_response_bytes_pre_encode")
	}
}

func TestLoadServer_DisabledSecondResponseCapIgnoresTooSmallByteValue(t *testing.T) {
	path := writeServerConfig(t, `{
		"tunnel_key": "`+configTestKey+`",
		"second_response_cap_enabled": false,
		"second_response_bytes_pre_encode": 1024
	}`)

	cfg, err := LoadServer(path)
	if err != nil {
		t.Fatalf("LoadServer: %v", err)
	}
	if cfg.SecondResponseCapEnabled {
		t.Fatal("SecondResponseCapEnabled = true, want false")
	}
	if cfg.SecondResponseBytesPreEncode != 1024 {
		t.Fatalf("SecondResponseBytesPreEncode = %d, want ignored/preserved 1024", cfg.SecondResponseBytesPreEncode)
	}
}

func TestLoadServer_ClampsSecondResponseBytesToMaxResponseBytes(t *testing.T) {
	path := writeServerConfig(t, `{
		"tunnel_key": "`+configTestKey+`",
		"max_response_bytes_pre_encode": 524288,
		"second_response_bytes_pre_encode": 1048576
	}`)

	cfg, err := LoadServer(path)
	if err != nil {
		t.Fatalf("LoadServer: %v", err)
	}
	if cfg.SecondResponseBytesPreEncode != 524288 {
		t.Fatalf("SecondResponseBytesPreEncode = %d, want clamped 524288", cfg.SecondResponseBytesPreEncode)
	}
}

func TestLoadServer_RejectsResponseBytesAboveProtocolCeiling(t *testing.T) {
	path := writeServerConfig(t, `{
		"tunnel_key": "`+configTestKey+`",
		"max_response_bytes_pre_encode": 25165824
	}`)

	if _, err := LoadServer(path); err == nil {
		t.Fatal("LoadServer succeeded with too-large max_response_bytes_pre_encode")
	}
}

func TestLoadServer_AcceptsExplicitResponseBytesAtProtocolCeiling(t *testing.T) {
	path := writeServerConfig(t, `{
		"tunnel_key": "`+configTestKey+`",
		"max_response_bytes_pre_encode": 23068672
	}`)

	cfg, err := LoadServer(path)
	if err != nil {
		t.Fatalf("LoadServer: %v", err)
	}
	if cfg.MaxResponseBytesPreEncode != 22*1024*1024 {
		t.Fatalf("MaxResponseBytesPreEncode = %d, want 22MiB", cfg.MaxResponseBytesPreEncode)
	}
}

func TestLoadServer_RejectsReplayResponseBytesAboveReplaySessionCap(t *testing.T) {
	path := writeServerConfig(t, `{
		"tunnel_key": "`+configTestKey+`",
		"downstream_replay_enabled": true,
		"max_response_bytes_pre_encode": 9437184
	}`)

	if _, err := LoadServer(path); err == nil {
		t.Fatal("LoadServer succeeded with replay response cap above replay session cap")
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

func TestLoadServer_RejectsTooLargeMaxDrainFramesPerSession(t *testing.T) {
	path := writeServerConfig(t, `{
		"tunnel_key": "`+configTestKey+`",
		"max_drain_frames_per_session": 65
	}`)

	if _, err := LoadServer(path); err == nil {
		t.Fatal("LoadServer succeeded with too-large max_drain_frames_per_session")
	}
}

func TestLoadServer_RejectsTooLargeMaxRequestBodyBytes(t *testing.T) {
	path := writeServerConfig(t, `{
		"tunnel_key": "`+configTestKey+`",
		"max_request_body_bytes": 12582913
	}`)

	if _, err := LoadServer(path); err == nil {
		t.Fatal("LoadServer succeeded with too-large max_request_body_bytes")
	}
}

func TestLoadServer_DiagnosticsConfig(t *testing.T) {
	path := writeServerConfig(t, `{
		"tunnel_key": "`+configTestKey+`",
		"stats_json": true,
		"debug_pprof_addr": "127.0.0.1:6061",
		"write_startup_diagnostics": true,
		"diagnostics_output_dir": "diag-out",
		"save_terminal_log": true,
		"terminal_log_file": "logs/server-field-test.log"
	}`)

	cfg, err := LoadServer(path)
	if err != nil {
		t.Fatalf("LoadServer: %v", err)
	}
	if !cfg.StatsJSON {
		t.Fatal("StatsJSON = false, want true")
	}
	if cfg.DebugPprofAddr != "127.0.0.1:6061" {
		t.Fatalf("DebugPprofAddr = %q, want 127.0.0.1:6061", cfg.DebugPprofAddr)
	}
	if !cfg.WriteStartupDiagnostics {
		t.Fatal("WriteStartupDiagnostics = false, want true")
	}
	if cfg.DiagnosticsOutputDir != "diag-out" {
		t.Fatalf("DiagnosticsOutputDir = %q, want diag-out", cfg.DiagnosticsOutputDir)
	}
	if !cfg.SaveTerminalLog {
		t.Fatal("SaveTerminalLog = false, want true")
	}
	if cfg.TerminalLogFile != "logs/server-field-test.log" {
		t.Fatalf("TerminalLogFile = %q, want logs/server-field-test.log", cfg.TerminalLogFile)
	}
}

func TestLoadServer_DownstreamReplayEnabled(t *testing.T) {
	path := writeServerConfig(t, `{
		"tunnel_key": "`+configTestKey+`",
		"downstream_replay_enabled": true
	}`)

	cfg, err := LoadServer(path)
	if err != nil {
		t.Fatalf("LoadServer: %v", err)
	}
	if !cfg.DownstreamReplayEnabled {
		t.Fatal("DownstreamReplayEnabled = false, want true")
	}
}

func TestLoadServer_ExampleEnablesDownstreamReplay(t *testing.T) {
	body, err := os.ReadFile(filepath.Join("..", "..", "server_config.example.json"))
	if err != nil {
		t.Fatalf("read example: %v", err)
	}
	text := strings.ReplaceAll(string(body), "SAME_VALUE_AS_CLIENT_tunnel_key", configTestKey)
	path := writeServerConfig(t, text)

	cfg, err := LoadServer(path)
	if err != nil {
		t.Fatalf("LoadServer example: %v", err)
	}
	if !cfg.DownstreamReplayEnabled {
		t.Fatal("example DownstreamReplayEnabled = false, want true")
	}
	if cfg.MaxResponseBytesPreEncode != 6*1024*1024 {
		t.Fatalf("example MaxResponseBytesPreEncode = %d, want 6MiB", cfg.MaxResponseBytesPreEncode)
	}
	if cfg.SecondResponseBytesPreEncode != 1024*1024 {
		t.Fatalf("example SecondResponseBytesPreEncode = %d, want 1MiB", cfg.SecondResponseBytesPreEncode)
	}
	if cfg.MaxDrainFramesPerSession != 8 {
		t.Fatalf("example MaxDrainFramesPerSession = %d, want 8", cfg.MaxDrainFramesPerSession)
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

func TestLoadServer_ReportsUnknownFields(t *testing.T) {
	path := writeServerConfig(t, `{
		"server_host": "127.0.0.1",
		"server_port": 8443,
		"tunnel_key": "`+configTestKey+`",
		"max_sesions": 99,
		"_comment_custom": "comments are ignored"
	}`)

	cfg, err := LoadServer(path)
	if err != nil {
		t.Fatalf("LoadServer: %v", err)
	}
	if len(cfg.UnknownFields) != 1 || cfg.UnknownFields[0] != "max_sesions" {
		t.Fatalf("UnknownFields = %v, want [max_sesions]", cfg.UnknownFields)
	}
}

func TestLoadServer_ExampleConfigParsesAfterReplacingPlaceholders(t *testing.T) {
	body, err := os.ReadFile(filepath.Join("..", "..", "server_config.example.json"))
	if err != nil {
		t.Fatalf("read example: %v", err)
	}
	text := strings.ReplaceAll(string(body), "SAME_VALUE_AS_CLIENT_tunnel_key", configTestKey)
	path := writeServerConfig(t, text)

	if _, err := LoadServer(path); err != nil {
		t.Fatalf("LoadServer example: %v", err)
	}
}
