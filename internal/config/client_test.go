package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kianmhz/GooseRelayVPN/internal/protocol"
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
	if cfg.WorkersPerEndpoint != 3 {
		t.Fatalf("WorkersPerEndpoint = %d, want 3", cfg.WorkersPerEndpoint)
	}
	if cfg.PollIdleSleepMs != 5 {
		t.Fatalf("PollIdleSleepMs = %d, want 5", cfg.PollIdleSleepMs)
	}
	if cfg.PollTimeoutMs != 300000 {
		t.Fatalf("PollTimeoutMs = %d, want 300000", cfg.PollTimeoutMs)
	}
	if got, want := cfg.SNIHosts, []string{"www.google.com", "mail.google.com", "accounts.google.com"}; len(got) != len(want) || got[0] != want[0] || got[1] != want[1] || got[2] != want[2] {
		t.Fatalf("SNIHosts = %v, want %v", got, want)
	}
	if cfg.EndpointOutageGraceMs != 300000 {
		t.Fatalf("EndpointOutageGraceMs = %d, want 300000", cfg.EndpointOutageGraceMs)
	}
	if cfg.MaxRequestBytesPreEncode != 8*1024*1024 {
		t.Fatalf("MaxRequestBytesPreEncode = %d, want 8MiB", cfg.MaxRequestBytesPreEncode)
	}
	if cfg.TxBufferBudgetBytes != 64*1024*1024 {
		t.Fatalf("TxBufferBudgetBytes = %d, want 64MiB", cfg.TxBufferBudgetBytes)
	}
	if cfg.IdlePollMode != "always" {
		t.Fatalf("IdlePollMode = %q, want always", cfg.IdlePollMode)
	}
	if cfg.IdlePollMaxBuckets != 2 {
		t.Fatalf("IdlePollMaxBuckets = %d, want 2", cfg.IdlePollMaxBuckets)
	}
	if cfg.DownstreamReplayMode != "auto" {
		t.Fatalf("DownstreamReplayMode = %q, want auto", cfg.DownstreamReplayMode)
	}
	if cfg.TransportMode != "apps_script" {
		t.Fatalf("TransportMode = %q, want default apps_script", cfg.TransportMode)
	}
}

func TestLoadClient_AcceptsUTF8BOM(t *testing.T) {
	path := writeClientConfig(t, "\xef\xbb\xbf"+`{
		"script_keys": ["AKfycbabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz1234567890"],
		"tunnel_key": "`+configTestKey+`"
	}`)

	if _, err := LoadClient(path); err != nil {
		t.Fatalf("LoadClient with UTF-8 BOM: %v", err)
	}
}

func TestLoadClient_IdlePollModeAdaptive(t *testing.T) {
	path := writeClientConfig(t, `{
		"script_keys": ["AKfycbabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz1234567890"],
		"tunnel_key": "`+configTestKey+`",
		"idle_poll_mode": "adaptive"
	}`)

	cfg, err := LoadClient(path)
	if err != nil {
		t.Fatalf("LoadClient: %v", err)
	}
	if cfg.IdlePollMode != "adaptive" {
		t.Fatalf("IdlePollMode = %q, want adaptive", cfg.IdlePollMode)
	}
}

func TestLoadClient_RejectsUnknownIdlePollMode(t *testing.T) {
	path := writeClientConfig(t, `{
		"script_keys": ["AKfycbabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz1234567890"],
		"tunnel_key": "`+configTestKey+`",
		"idle_poll_mode": "turbo-nap"
	}`)

	if _, err := LoadClient(path); err == nil {
		t.Fatal("LoadClient succeeded with unknown idle_poll_mode")
	}
}

func TestLoadClient_ReportsUnknownFields(t *testing.T) {
	path := writeClientConfig(t, `{
		"script_keys": ["AKfycbabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz1234567890"],
		"tunnel_key": "`+configTestKey+`",
		"worker_per_endpoint": 99,
		"_comment_custom": "comments are ignored"
	}`)

	cfg, err := LoadClient(path)
	if err != nil {
		t.Fatalf("LoadClient: %v", err)
	}
	if len(cfg.UnknownFields) != 1 || cfg.UnknownFields[0] != "worker_per_endpoint" {
		t.Fatalf("UnknownFields = %v, want [worker_per_endpoint]", cfg.UnknownFields)
	}
}

func TestLoadClient_ExampleConfigParsesAfterReplacingPlaceholders(t *testing.T) {
	body, err := os.ReadFile(filepath.Join("..", "..", "client_config.example.json"))
	if err != nil {
		t.Fatalf("read example: %v", err)
	}
	text := strings.ReplaceAll(string(body), "REPLACE_WITH_DEPLOYMENT_ID", "AKfycbabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz1234567890")
	text = strings.ReplaceAll(text, "REPLACE_WITH_64_HEX_CHARACTER_RANDOM_KEY", configTestKey)
	path := writeClientConfig(t, text)

	cfg, err := LoadClient(path)
	if err != nil {
		t.Fatalf("LoadClient example: %v", err)
	}
	if cfg.DownstreamReplayMode != "auto" {
		t.Fatalf("example DownstreamReplayMode = %q, want auto", cfg.DownstreamReplayMode)
	}
	if cfg.TransportMode != "apps_script" {
		t.Fatalf("example TransportMode = %q, want apps_script", cfg.TransportMode)
	}
}

func TestLoadClient_ExplicitIdlePollMaxBuckets(t *testing.T) {
	path := writeClientConfig(t, `{
		"script_keys": ["AKfycbabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz1234567890"],
		"tunnel_key": "`+configTestKey+`",
		"idle_poll_max_buckets": 1
	}`)

	cfg, err := LoadClient(path)
	if err != nil {
		t.Fatalf("LoadClient: %v", err)
	}
	if cfg.IdlePollMaxBuckets != 1 {
		t.Fatalf("IdlePollMaxBuckets = %d, want explicit 1", cfg.IdlePollMaxBuckets)
	}
}

func TestLoadClient_RejectsIdlePollMaxBucketsAboveTwo(t *testing.T) {
	path := writeClientConfig(t, `{
		"script_keys": ["AKfycbabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz1234567890"],
		"tunnel_key": "`+configTestKey+`",
		"idle_poll_max_buckets": 3
	}`)

	if _, err := LoadClient(path); err == nil {
		t.Fatal("LoadClient succeeded with idle_poll_max_buckets > 2")
	}
}

func TestLoadClient_RejectsUnknownScriptKeyObjectField(t *testing.T) {
	path := writeClientConfig(t, `{
		"script_keys": [{"id":"AKfycbabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz1234567890","acount":"acct-a"}],
		"tunnel_key": "`+configTestKey+`"
	}`)

	if _, err := LoadClient(path); err == nil {
		t.Fatal("LoadClient accepted script_keys object with misspelled account field")
	}
}

func TestLoadClient_RejectsMalformedSNIShape(t *testing.T) {
	path := writeClientConfig(t, `{
		"script_keys": ["AKfycbabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz1234567890"],
		"tunnel_key": "`+configTestKey+`",
		"sni": {"not":"a valid sni shape"}
	}`)

	if _, err := LoadClient(path); err == nil {
		t.Fatal("LoadClient accepted malformed non-empty sni")
	}
}

func TestLoadClient_PerformanceModeThroughputAppliesBatchingDefaults(t *testing.T) {
	path := writeClientConfig(t, `{
		"transport_mode": "direct_post",
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
		"transport_mode": "direct_post",
		"relay_urls": ["http://127.0.0.1:8443/tunnel"],
		"tunnel_key": "`+configTestKey+`",
		"performance_mode": "throughput",
		"coalesce_step_ms": 7,
		"idle_slots_per_bucket": 3,
		"workers_per_endpoint": 6,
		"poll_idle_sleep_ms": 12,
		"poll_timeout_ms": 123456,
		"max_request_bytes_pre_encode": 1048576,
		"tx_buffer_budget_bytes": 2097152
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
	if cfg.PollTimeoutMs != 123456 {
		t.Fatalf("PollTimeoutMs = %d, want explicit 123456", cfg.PollTimeoutMs)
	}
	if cfg.MaxRequestBytesPreEncode != 1048576 {
		t.Fatalf("MaxRequestBytesPreEncode = %d, want explicit 1048576", cfg.MaxRequestBytesPreEncode)
	}
	if cfg.TxBufferBudgetBytes != 2097152 {
		t.Fatalf("TxBufferBudgetBytes = %d, want explicit 2097152", cfg.TxBufferBudgetBytes)
	}
}

func TestLoadClient_MaxLocalSessionsDefaultAndExplicit(t *testing.T) {
	defaultPath := writeClientConfig(t, `{
		"transport_mode": "direct_post",
		"relay_urls": ["http://127.0.0.1:8443/tunnel"],
		"tunnel_key": "`+configTestKey+`"
	}`)
	defaultCfg, err := LoadClient(defaultPath)
	if err != nil {
		t.Fatalf("LoadClient default: %v", err)
	}
	if defaultCfg.MaxLocalSessions != 0 {
		t.Fatalf("MaxLocalSessions default = %d, want 0", defaultCfg.MaxLocalSessions)
	}

	explicitPath := writeClientConfig(t, `{
		"transport_mode": "direct_post",
		"relay_urls": ["http://127.0.0.1:8443/tunnel"],
		"tunnel_key": "`+configTestKey+`",
		"max_local_sessions": 512
	}`)
	explicitCfg, err := LoadClient(explicitPath)
	if err != nil {
		t.Fatalf("LoadClient explicit: %v", err)
	}
	if explicitCfg.MaxLocalSessions != 512 {
		t.Fatalf("MaxLocalSessions explicit = %d, want 512", explicitCfg.MaxLocalSessions)
	}
}

func TestLoadClient_RejectsNegativeMaxLocalSessions(t *testing.T) {
	path := writeClientConfig(t, `{
		"transport_mode": "direct_post",
		"relay_urls": ["http://127.0.0.1:8443/tunnel"],
		"tunnel_key": "`+configTestKey+`",
		"max_local_sessions": -1
	}`)

	if _, err := LoadClient(path); err == nil {
		t.Fatal("LoadClient succeeded with negative max_local_sessions")
	}
}

func TestLoadClient_RejectsTooSmallTxBufferBudget(t *testing.T) {
	path := writeClientConfig(t, `{
		"transport_mode": "direct_post",
		"relay_urls": ["http://127.0.0.1:8443/tunnel"],
		"tunnel_key": "`+configTestKey+`",
		"tx_buffer_budget_bytes": 1024
	}`)

	if _, err := LoadClient(path); err == nil {
		t.Fatal("LoadClient succeeded with too-small tx_buffer_budget_bytes")
	}
}

func TestLoadClient_RejectsTooLargeMaxRequestBytesPreEncode(t *testing.T) {
	path := writeClientConfig(t, `{
		"transport_mode": "direct_post",
		"relay_urls": ["http://127.0.0.1:8443/tunnel"],
		"tunnel_key": "`+configTestKey+`",
		"max_request_bytes_pre_encode": 8388609
	}`)

	if _, err := LoadClient(path); err == nil {
		t.Fatal("LoadClient succeeded with too-large max_request_bytes_pre_encode")
	}
}

func TestLoadClient_RejectsUnknownPerformanceMode(t *testing.T) {
	path := writeClientConfig(t, `{
		"transport_mode": "direct_post",
		"relay_urls": ["http://127.0.0.1:8443/tunnel"],
		"tunnel_key": "`+configTestKey+`",
		"performance_mode": "warp-speed"
	}`)

	if _, err := LoadClient(path); err == nil {
		t.Fatal("LoadClient succeeded with unknown performance_mode")
	}
}

func TestLoadClient_ExplicitAutoTransportAllowsDirectStreamOnly(t *testing.T) {
	path := writeClientConfig(t, `{
		"transport_mode": "auto",
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
	if cfg.FrontingHTTPVersion != "auto" {
		t.Fatalf("FrontingHTTPVersion = %q, want auto", cfg.FrontingHTTPVersion)
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

func TestLoadClient_DefaultAppsScriptRejectsDirectStreamURLsWithHelpfulError(t *testing.T) {
	path := writeClientConfig(t, `{
		"direct_stream_urls": ["ws://127.0.0.1:8443/stream"],
		"tunnel_key": "`+configTestKey+`"
	}`)

	_, err := LoadClient(path)
	if err == nil {
		t.Fatal("LoadClient succeeded with direct_stream_urls and default apps_script mode")
	}
	if !strings.Contains(err.Error(), "direct_stream_urls can only be used with transport_mode auto or direct_stream") {
		t.Fatalf("error = %v, want helpful direct_stream_urls transport_mode hint", err)
	}
}

func TestLoadClient_InvalidDirectURLDoesNotEchoSecret(t *testing.T) {
	path := writeClientConfig(t, `{
		"transport_mode": "auto",
		"direct_stream_urls": ["ftp://SECRET_HOST/stream"],
		"tunnel_key": "`+configTestKey+`"
	}`)

	_, err := LoadClient(path)
	if err == nil {
		t.Fatal("LoadClient accepted invalid direct_stream_urls scheme")
	}
	if strings.Contains(err.Error(), "SECRET_HOST") || strings.Contains(err.Error(), "ftp://") {
		t.Fatalf("error leaked raw direct_stream_urls value: %v", err)
	}
}

func TestLoadClient_FrontingHTTPVersion(t *testing.T) {
	path := writeClientConfig(t, `{
		"script_keys": ["AKfycbabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz1234567890"],
		"tunnel_key": "`+configTestKey+`",
		"fronting_http_version": "h1"
	}`)

	cfg, err := LoadClient(path)
	if err != nil {
		t.Fatalf("LoadClient: %v", err)
	}
	if cfg.FrontingHTTPVersion != "h1" {
		t.Fatalf("FrontingHTTPVersion = %q, want h1", cfg.FrontingHTTPVersion)
	}
}

func TestLoadClient_RejectsMalformedGoogleHost(t *testing.T) {
	tests := []string{
		`"https://www.google.com"`,
		`"216.239.38.120:443"`,
		`"www.google.com/path"`,
	}
	for _, googleHost := range tests {
		t.Run(googleHost, func(t *testing.T) {
			path := writeClientConfig(t, `{
				"script_keys": ["AKfycbabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz1234567890"],
				"tunnel_key": "`+configTestKey+`",
				"google_host": `+googleHost+`
			}`)
			if _, err := LoadClient(path); err == nil {
				t.Fatalf("LoadClient accepted malformed google_host %s", googleHost)
			}
		})
	}
}

func TestLoadClient_AcceptsPlainGoogleHost(t *testing.T) {
	path := writeClientConfig(t, `{
		"script_keys": ["AKfycbabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz1234567890"],
		"tunnel_key": "`+configTestKey+`",
		"google_host": "www.google.com"
	}`)

	cfg, err := LoadClient(path)
	if err != nil {
		t.Fatalf("LoadClient: %v", err)
	}
	if cfg.GoogleIP != "www.google.com:443" {
		t.Fatalf("GoogleIP = %q, want www.google.com:443", cfg.GoogleIP)
	}
}

func TestLoadClient_DiagnosticsConfig(t *testing.T) {
	path := writeClientConfig(t, `{
		"script_keys": ["AKfycbabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz1234567890"],
		"tunnel_key": "`+configTestKey+`",
		"stats_json": true,
		"debug_pprof_addr": "127.0.0.1:6060",
		"write_startup_diagnostics": true,
		"diagnostics_output_dir": "diag-out",
		"save_terminal_log": true,
		"terminal_log_file": "logs/client-field-test.log"
	}`)

	cfg, err := LoadClient(path)
	if err != nil {
		t.Fatalf("LoadClient: %v", err)
	}
	if !cfg.StatsJSON {
		t.Fatal("StatsJSON = false, want true")
	}
	if cfg.DebugPprofAddr != "127.0.0.1:6060" {
		t.Fatalf("DebugPprofAddr = %q, want 127.0.0.1:6060", cfg.DebugPprofAddr)
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
	if cfg.TerminalLogFile != "logs/client-field-test.log" {
		t.Fatalf("TerminalLogFile = %q, want logs/client-field-test.log", cfg.TerminalLogFile)
	}
}

func TestLoadClient_FreshStartResetConfig(t *testing.T) {
	path := writeClientConfig(t, `{
		"script_keys": ["AKfycbxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"],
		"tunnel_key": "`+strings.Repeat("a", 64)+`",
		"fresh_start_reset": false,
		"client_instance_id": "phone-main",
		"client_instance_id_file": "state/client-instance"
	}`)
	cfg, err := LoadClient(path)
	if err != nil {
		t.Fatalf("LoadClient: %v", err)
	}
	if cfg.FreshStartReset {
		t.Fatal("FreshStartReset = true, want explicit false")
	}
	if cfg.ClientInstanceID != "phone-main" {
		t.Fatalf("ClientInstanceID = %q", cfg.ClientInstanceID)
	}
	if cfg.ClientInstanceIDFile != "state/client-instance" {
		t.Fatalf("ClientInstanceIDFile = %q", cfg.ClientInstanceIDFile)
	}
}

func TestLoadClient_FreshStartResetDefaultsOn(t *testing.T) {
	path := writeClientConfig(t, `{
		"script_keys": ["AKfycbxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"],
		"tunnel_key": "`+strings.Repeat("a", 64)+`"
	}`)
	cfg, err := LoadClient(path)
	if err != nil {
		t.Fatalf("LoadClient: %v", err)
	}
	if !cfg.FreshStartReset {
		t.Fatal("FreshStartReset = false, want default true")
	}
	if filepath.Base(cfg.QuotaStatePath) != ".goose-quota-state.json" {
		t.Fatalf("QuotaStatePath = %q, want default .goose-quota-state.json", cfg.QuotaStatePath)
	}
}

func TestLoadClient_QuotaStatePathCanBeDisabled(t *testing.T) {
	path := writeClientConfig(t, `{
		"script_keys": ["AKfycbxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"],
		"tunnel_key": "`+strings.Repeat("a", 64)+`",
		"quota_state_path": ""
	}`)
	cfg, err := LoadClient(path)
	if err != nil {
		t.Fatalf("LoadClient: %v", err)
	}
	if cfg.QuotaStatePath != "" {
		t.Fatalf("QuotaStatePath = %q, want disabled empty path", cfg.QuotaStatePath)
	}
}

func TestLoadClient_TxSlotsPerBucketConfig(t *testing.T) {
	path := writeClientConfig(t, `{
		"script_keys": ["AKfycbxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"],
		"tunnel_key": "`+strings.Repeat("a", 64)+`",
		"tx_slots_per_bucket": 4
	}`)
	cfg, err := LoadClient(path)
	if err != nil {
		t.Fatalf("LoadClient: %v", err)
	}
	if cfg.TxSlotsPerBucket != 4 {
		t.Fatalf("TxSlotsPerBucket = %d, want 4", cfg.TxSlotsPerBucket)
	}
}

func TestLoadClient_TxSlotsPerBucketDefaultStaysFixedWhenWorkersRaised(t *testing.T) {
	path := writeClientConfig(t, `{
		"script_keys": ["AKfycbxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"],
		"tunnel_key": "`+strings.Repeat("a", 64)+`",
		"workers_per_endpoint": 6
	}`)
	cfg, err := LoadClient(path)
	if err != nil {
		t.Fatalf("LoadClient: %v", err)
	}
	if cfg.TxSlotsPerBucket != protocol.DefaultWorkersPerEndpoint {
		t.Fatalf("TxSlotsPerBucket = %d, want fixed default %d", cfg.TxSlotsPerBucket, protocol.DefaultWorkersPerEndpoint)
	}
}

func TestLoadClient_DownstreamReplayMode(t *testing.T) {
	path := writeClientConfig(t, `{
		"script_keys": ["AKfycbabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz1234567890"],
		"tunnel_key": "`+configTestKey+`",
		"downstream_replay_mode": "auto"
	}`)

	cfg, err := LoadClient(path)
	if err != nil {
		t.Fatalf("LoadClient: %v", err)
	}
	if cfg.DownstreamReplayMode != "auto" {
		t.Fatalf("DownstreamReplayMode = %q, want auto", cfg.DownstreamReplayMode)
	}
}

func TestLoadClient_RejectsUnknownDownstreamReplayMode(t *testing.T) {
	path := writeClientConfig(t, `{
		"script_keys": ["AKfycbabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz1234567890"],
		"tunnel_key": "`+configTestKey+`",
		"downstream_replay_mode": "always"
	}`)

	if _, err := LoadClient(path); err == nil {
		t.Fatal("LoadClient succeeded with unknown downstream_replay_mode")
	}
}

func TestLoadClient_RejectsUnknownFrontingHTTPVersion(t *testing.T) {
	path := writeClientConfig(t, `{
		"script_keys": ["AKfycbabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz1234567890"],
		"tunnel_key": "`+configTestKey+`",
		"fronting_http_version": "h3"
	}`)

	if _, err := LoadClient(path); err == nil {
		t.Fatal("LoadClient succeeded with unknown fronting_http_version")
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
