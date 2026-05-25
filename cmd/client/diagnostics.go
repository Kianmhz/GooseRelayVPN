package main

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"strings"
	"time"

	appconfig "github.com/kianmhz/GooseRelayVPN/internal/config"
)

func writeDiagnosticsZip(outPath, configPath, version string) (string, error) {
	if strings.TrimSpace(outPath) == "" {
		var err error
		outPath, err = startupDiagnosticsOutputPath("diagnostics", "goose-diagnostics")
		if err != nil {
			return "", err
		}
	}
	outPath = filepath.Clean(outPath)
	if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
		return "", err
	}

	f, err := os.OpenFile(outPath, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	if err != nil {
		return "", err
	}
	zw := zip.NewWriter(f)
	cleanup := true
	defer func() {
		if cleanup {
			_ = zw.Close()
			_ = f.Close()
		}
	}()

	addText := func(name, body string) error {
		w, err := zw.Create(name)
		if err != nil {
			return err
		}
		_, err = io.WriteString(w, body)
		return err
	}

	if err := addText("README.txt", diagnosticsReadme(configPath)); err != nil {
		return "", err
	}
	if err := addText("runtime.txt", diagnosticsRuntime(configPath, version)); err != nil {
		return "", err
	}
	if err := addDiagnosticsSummary(zw, configPath, version); err != nil {
		return "", err
	}
	if err := addProfile(zw, "goroutine.txt", "goroutine", 2); err != nil {
		return "", err
	}
	if err := addProfile(zw, "heap.txt", "heap", 1); err != nil {
		return "", err
	}
	if err := addRedactedConfig(zw, configPath); err != nil {
		return "", err
	}
	if err := zw.Close(); err != nil {
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	cleanup = false
	return outPath, nil
}

func startupDiagnosticsOutputPath(outputDir, prefix string) (string, error) {
	baseDir, err := executableDir()
	if err != nil {
		return "", err
	}
	return startupDiagnosticsOutputPathInBase(baseDir, outputDir, prefix)
}

func startupDiagnosticsOutputPathInBase(baseDir, outputDir, prefix string) (string, error) {
	baseDir = strings.TrimSpace(baseDir)
	if baseDir == "" {
		baseDir = "."
	}
	outputDir = strings.TrimSpace(outputDir)
	if outputDir == "" {
		outputDir = "diagnostics"
	}
	if !filepath.IsAbs(outputDir) {
		outputDir = filepath.Join(baseDir, outputDir)
	}
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return "", err
	}
	return uniqueDiagnosticsZipPath(outputDir, prefix)
}

func executableDir() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("resolve executable path: %w", err)
	}
	return filepath.Dir(exe), nil
}

func uniqueDiagnosticsZipPath(outputDir, prefix string) (string, error) {
	stamp := time.Now().Format("20060102-150405")
	for i := 0; i < 100; i++ {
		name := fmt.Sprintf("%s-%s.zip", prefix, stamp)
		if i > 0 {
			name = fmt.Sprintf("%s-%s-%02d.zip", prefix, stamp, i+1)
		}
		path := filepath.Join(outputDir, name)
		_, err := os.Stat(path)
		if errors.Is(err, os.ErrNotExist) {
			return path, nil
		}
		if err != nil {
			return "", err
		}
	}
	return "", fmt.Errorf("could not create a unique diagnostics zip path under %s for %s", outputDir, prefix)
}

func diagnosticsPathLabel(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	return filepath.Base(filepath.Clean(path))
}

func diagnosticsConfigReadError(configPath string, err error) string {
	reason := "read failed"
	switch {
	case errors.Is(err, os.ErrNotExist):
		reason = "file not found"
	case errors.Is(err, os.ErrPermission):
		reason = "permission denied"
	}
	return fmt.Sprintf("unable to read config %q: %s", diagnosticsPathLabel(configPath), reason)
}

func diagnosticsReadme(configPath string) string {
	return fmt.Sprintf(`GooseRelayVPN diagnostics bundle

This zip is designed to be shared for debugging.

Included:
- diagnostics.json: structured runtime and non-secret config summary.
- runtime.txt: OS/arch/Go runtime/process summary.
- goroutine.txt: current goroutine profile.
- heap.txt: heap profile summary.
- client_config.redacted.json: parsed client config with secrets and endpoint identifiers redacted.

Not included:
- raw tunnel keys, SOCKS passwords, Apps Script deployment IDs, or full relay URLs.
- packet captures or user browsing data.

Config source file: %s
Generated at: %s
`, diagnosticsPathLabel(configPath), time.Now().Format(time.RFC3339))
}

func diagnosticsRuntime(configPath, version string) string {
	cwd, _ := os.Getwd()
	exe, _ := os.Executable()
	return fmt.Sprintf(`version: %s
generated_at: %s
go_version: %s
goos: %s
goarch: %s
num_cpu: %d
gomaxprocs: %d
num_goroutine: %d
cwd_name: %s
executable_name: %s
config_name: %s
`, version, time.Now().Format(time.RFC3339), runtime.Version(), runtime.GOOS, runtime.GOARCH, runtime.NumCPU(), runtime.GOMAXPROCS(0), runtime.NumGoroutine(), diagnosticsPathLabel(cwd), diagnosticsPathLabel(exe), diagnosticsPathLabel(configPath))
}

func addDiagnosticsSummary(zw *zip.Writer, configPath, version string) error {
	w, err := zw.Create("diagnostics.json")
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(configPath)
	if err != nil {
		summary := map[string]any{
			"version":      version,
			"generated_at": time.Now().Format(time.RFC3339),
			"config_error": diagnosticsConfigReadError(configPath, err),
		}
		body, marshalErr := json.MarshalIndent(summary, "", "  ")
		if marshalErr != nil {
			return marshalErr
		}
		_, err = w.Write(body)
		return err
	}
	redacted, err := redactConfigJSON(raw)
	if err != nil {
		summary := map[string]any{
			"version":      version,
			"generated_at": time.Now().Format(time.RFC3339),
			"config_error": err.Error(),
		}
		body, marshalErr := json.MarshalIndent(summary, "", "  ")
		if marshalErr != nil {
			return marshalErr
		}
		_, err = w.Write(body)
		return err
	}

	var cfg map[string]any
	if err := json.Unmarshal(redacted, &cfg); err != nil {
		return err
	}
	summary := map[string]any{
		"version":      version,
		"generated_at": time.Now().Format(time.RFC3339),
		"go_version":   runtime.Version(),
		"goos":         runtime.GOOS,
		"goarch":       runtime.GOARCH,
		"config":       diagnosticsConfigSummary(cfg),
	}
	if effective, err := appconfig.LoadClient(configPath); err == nil {
		summary["effective_config"] = clientDiagnosticsEffectiveConfigSummary(*effective)
	} else {
		summary["effective_config_error"] = "config validation failed"
	}
	body, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		return err
	}
	_, err = w.Write(append(body, '\n'))
	return err
}

func diagnosticsConfigSummary(cfg map[string]any) map[string]any {
	out := make(map[string]any)
	for _, key := range []string{
		"socks_host",
		"socks_port",
		"google_host",
		"transport_mode",
		"fronting_http_version",
		"performance_mode",
		"downstream_replay_mode",
		"idle_poll_mode",
		"debug_timing",
		"stats_json",
		"debug_pprof_addr",
		"write_startup_diagnostics",
		"diagnostics_output_dir",
		"save_terminal_log",
		"terminal_log_file",
		"fresh_start_reset",
		"quota_state_path",
		"auto_tune",
		"coalesce_step_ms",
		"idle_slots_per_bucket",
		"idle_poll_max_buckets",
		"workers_per_endpoint",
		"tx_slots_per_bucket",
		"poll_idle_sleep_ms",
		"poll_timeout_ms",
		"endpoint_blacklist_base_ms",
		"endpoint_blacklist_max_ms",
		"endpoint_outage_grace_ms",
		"max_request_bytes_pre_encode",
		"tx_buffer_budget_bytes",
		"stream_connect_timeout_ms",
		"stream_ping_interval_ms",
		"stream_reconnect_backoff_ms",
	} {
		if v, ok := cfg[key]; ok {
			if s, ok := v.(string); ok && isPathConfigKey(key) {
				out[key] = redactPathString(s)
				continue
			}
			out[key] = v
		}
	}
	if v, ok := cfg["sni"].([]any); ok {
		out["sni_count"] = len(v)
	}
	if v, ok := cfg["script_keys"].([]any); ok {
		out["script_key_count"] = len(v)
	}
	if v, ok := cfg["relay_urls"].([]any); ok {
		out["relay_url_count"] = len(v)
	}
	if v, ok := cfg["direct_stream_urls"].([]any); ok {
		out["direct_stream_url_count"] = len(v)
	}
	return out
}

func clientDiagnosticsEffectiveConfigSummary(cfg appconfig.Client) map[string]any {
	return map[string]any{
		"listen_addr":                  cfg.ListenAddr,
		"google_ip":                    cfg.GoogleIP,
		"use_fronting":                 cfg.UseFronting,
		"sni_count":                    len(cfg.SNIHosts),
		"script_key_count":             clientDiagnosticsScriptKeyCount(cfg),
		"relay_endpoint_count":         len(cfg.ScriptURLs),
		"account_bucket_count":         clientDiagnosticsAccountBucketCount(cfg.ScriptAccounts),
		"direct_stream_url_count":      len(cfg.DirectStreamURLs),
		"transport_mode":               cfg.TransportMode,
		"fronting_http_version":        cfg.FrontingHTTPVersion,
		"performance_mode":             cfg.PerformanceMode,
		"downstream_replay_mode":       cfg.DownstreamReplayMode,
		"idle_poll_mode":               cfg.IdlePollMode,
		"debug_timing":                 cfg.DebugTiming,
		"stats_json":                   cfg.StatsJSON,
		"debug_pprof_addr":             cfg.DebugPprofAddr,
		"write_startup_diagnostics":    cfg.WriteStartupDiagnostics,
		"diagnostics_output_dir":       redactPathString(cfg.DiagnosticsOutputDir),
		"save_terminal_log":            cfg.SaveTerminalLog,
		"terminal_log_file":            redactPathString(cfg.TerminalLogFile),
		"fresh_start_reset":            cfg.FreshStartReset,
		"client_instance_id_set":       strings.TrimSpace(cfg.ClientInstanceID) != "",
		"client_instance_id_file":      redactPathString(cfg.ClientInstanceIDFile),
		"quota_state_path":             redactPathString(cfg.QuotaStatePath),
		"auto_tune":                    cfg.AutoTune,
		"socks_auth_enabled":           cfg.SocksUser != "" && cfg.SocksPass != "",
		"max_local_sessions":           cfg.MaxLocalSessions,
		"coalesce_step_ms":             cfg.CoalesceStepMs,
		"coalesce_max_ms":              cfg.CoalesceMaxMs,
		"idle_slots_per_bucket":        cfg.IdleSlotsPerBucket,
		"idle_poll_max_buckets":        cfg.IdlePollMaxBuckets,
		"tx_slots_per_bucket":          cfg.TxSlotsPerBucket,
		"workers_per_endpoint":         cfg.WorkersPerEndpoint,
		"poll_idle_sleep_ms":           cfg.PollIdleSleepMs,
		"poll_timeout_ms":              cfg.PollTimeoutMs,
		"endpoint_blacklist_base_ms":   cfg.EndpointBlacklistBaseMs,
		"endpoint_blacklist_max_ms":    cfg.EndpointBlacklistMaxMs,
		"endpoint_outage_grace_ms":     cfg.EndpointOutageGraceMs,
		"max_request_bytes_pre_encode": cfg.MaxRequestBytesPreEncode,
		"tx_buffer_budget_bytes":       cfg.TxBufferBudgetBytes,
		"stream_connect_timeout_ms":    cfg.StreamConnectTimeoutMs,
		"stream_ping_interval_ms":      cfg.StreamPingIntervalMs,
		"stream_reconnect_backoff_ms":  cfg.StreamReconnectBackoffMs,
		"unknown_field_count":          len(cfg.UnknownFields),
	}
}

func clientDiagnosticsScriptKeyCount(cfg appconfig.Client) int {
	if !cfg.UseFronting {
		return 0
	}
	return len(cfg.ScriptURLs)
}

func clientDiagnosticsAccountBucketCount(accounts []string) int {
	if len(accounts) == 0 {
		return 0
	}
	seen := map[string]struct{}{}
	for i, account := range accounts {
		account = strings.TrimSpace(account)
		if account == "" {
			account = fmt.Sprintf("unlabeled-%d", i)
		}
		seen[account] = struct{}{}
	}
	return len(seen)
}

func addProfile(zw *zip.Writer, name, profile string, debug int) error {
	w, err := zw.Create(name)
	if err != nil {
		return err
	}
	p := pprof.Lookup(profile)
	if p == nil {
		_, err = io.WriteString(w, "profile not available\n")
		return err
	}
	var buf bytes.Buffer
	if err := p.WriteTo(&buf, debug); err != nil {
		return err
	}
	_, err = io.WriteString(w, sanitizeDiagnosticsText(buf.String()))
	return err
}

func addRedactedConfig(zw *zip.Writer, configPath string) error {
	w, err := zw.Create("client_config.redacted.json")
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(configPath)
	if err != nil {
		_, writeErr := fmt.Fprintf(w, "%s\n", diagnosticsConfigReadError(configPath, err))
		return writeErr
	}
	redacted, err := redactConfigJSON(raw)
	if err != nil {
		_, writeErr := fmt.Fprintf(w, "unable to parse config as JSON; raw config omitted: %v\n", err)
		return writeErr
	}
	_, err = w.Write(redacted)
	return err
}

func redactConfigJSON(raw []byte) ([]byte, error) {
	raw = bytes.TrimPrefix(raw, []byte{0xef, 0xbb, 0xbf})
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	redacted := redactJSONValue("", v)
	return json.MarshalIndent(redacted, "", "  ")
}

func redactJSONValue(key string, v any) any {
	lowerKey := strings.ToLower(key)
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, child := range x {
			out[k] = redactJSONValue(k, child)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, child := range x {
			if lowerKey == "script_keys" {
				out[i] = redactScriptKeyEntry(child)
				continue
			}
			out[i] = redactJSONValue(lowerKey, child)
		}
		return out
	case string:
		switch {
		case lowerKey == "script_keys":
			return redactSecretString(x, "deployment")
		case lowerKey == "relay_urls" || lowerKey == "direct_stream_urls" || lowerKey == "upstream_proxy":
			return redactEndpoint(x)
		case isPathConfigKey(lowerKey):
			return redactPathString(x)
		case isSensitiveConfigKey(lowerKey):
			return redactSecretString(x, "secret")
		default:
			return x
		}
	default:
		return v
	}
}

func isPathConfigKey(key string) bool {
	switch strings.ToLower(key) {
	case "diagnostics_output_dir", "terminal_log_file", "quota_state_path":
		return true
	default:
		return false
	}
}

func redactPathString(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	if filepath.IsAbs(path) {
		return "<path redacted>"
	}
	return diagnosticsPathLabel(path)
}

func sanitizeDiagnosticsText(text string) string {
	replacements := make([]string, 0, 6)
	if cwd, err := os.Getwd(); err == nil {
		replacements = append(replacements, cwd)
	}
	if exe, err := os.Executable(); err == nil {
		replacements = append(replacements, exe, filepath.Dir(exe))
	}
	if home, err := os.UserHomeDir(); err == nil {
		replacements = append(replacements, home)
	}
	for _, path := range replacements {
		path = strings.TrimSpace(filepath.Clean(path))
		if path == "" || path == "." {
			continue
		}
		text = strings.ReplaceAll(text, path, "<path redacted>")
		text = strings.ReplaceAll(text, filepath.ToSlash(path), "<path redacted>")
	}
	return text
}

func redactScriptKeyEntry(v any) any {
	switch x := v.(type) {
	case string:
		return redactSecretString(x, "deployment")
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, child := range x {
			if strings.EqualFold(k, "id") {
				if s, ok := child.(string); ok {
					out[k] = redactSecretString(s, "deployment")
				} else {
					out[k] = "<redacted deployment>"
				}
				continue
			}
			out[k] = redactJSONValue(k, child)
		}
		return out
	default:
		return "<redacted deployment>"
	}
}

func isSensitiveConfigKey(key string) bool {
	if key == "" {
		return false
	}
	sensitiveParts := []string{
		"key",
		"secret",
		"password",
		"pass",
		"psk",
		"token",
		"credential",
	}
	for _, part := range sensitiveParts {
		if strings.Contains(key, part) {
			return true
		}
	}
	return false
}

func redactSecretString(s, label string) string {
	if s == "" {
		return ""
	}
	return fmt.Sprintf("<redacted %s len=%d>", label, len(s))
}

func redactEndpoint(s string) string {
	if s == "" {
		return ""
	}
	u, err := url.Parse(s)
	if err != nil || u.Scheme == "" {
		return "<redacted endpoint>"
	}
	return u.Scheme + "://<redacted>"
}
