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

	"github.com/kianmhz/GooseRelayVPN/internal/config"
)

func writeServerDiagnosticsZip(outPath, configPath, version string) (string, error) {
	if strings.TrimSpace(outPath) == "" {
		var err error
		outPath, err = startupDiagnosticsOutputPath("diagnostics", "goose-server-diagnostics")
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

	if err := addText("README.txt", serverDiagnosticsReadme(configPath)); err != nil {
		return "", err
	}
	if err := addText("runtime.txt", serverDiagnosticsRuntime(configPath, version)); err != nil {
		return "", err
	}
	if err := addServerDiagnosticsSummary(zw, configPath, version); err != nil {
		return "", err
	}
	if err := addServerProfile(zw, "goroutine.txt", "goroutine", 2); err != nil {
		return "", err
	}
	if err := addServerProfile(zw, "heap.txt", "heap", 1); err != nil {
		return "", err
	}
	if err := addServerRedactedConfig(zw, configPath); err != nil {
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

func serverDiagnosticsReadme(configPath string) string {
	return fmt.Sprintf(`GooseRelayVPN server diagnostics bundle

This zip is designed to be shared for debugging VPS-side problems.

Included:
- diagnostics.json: structured runtime and non-secret server config summary.
- runtime.txt: OS/arch/Go runtime/process summary.
- goroutine.txt: current goroutine profile.
- heap.txt: heap profile summary.
- server_config.redacted.json: parsed server config with secrets and endpoints redacted.

Not included:
- raw tunnel keys, upstream proxy credentials, or packet captures.
- user browsing data.

Config source file: %s
Generated at: %s
`, diagnosticsPathLabel(configPath), time.Now().Format(time.RFC3339))
}

func serverDiagnosticsRuntime(configPath, version string) string {
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

func addServerDiagnosticsSummary(zw *zip.Writer, configPath, version string) error {
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
	redacted, err := redactServerConfigJSON(raw)
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
		"config":       serverDiagnosticsConfigSummary(cfg),
	}
	if effective, err := config.LoadServer(configPath); err == nil {
		summary["effective_config"] = serverDiagnosticsEffectiveConfigSummary(*effective)
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

func serverDiagnosticsConfigSummary(cfg map[string]any) map[string]any {
	out := make(map[string]any)
	for _, key := range []string{
		"server_host",
		"server_port",
		"listen_addr",
		"debug_timing",
		"stats_json",
		"debug_pprof_addr",
		"write_startup_diagnostics",
		"diagnostics_output_dir",
		"save_terminal_log",
		"terminal_log_file",
		"auto_tune",
		"performance_mode",
		"active_drain_window_ms",
		"long_poll_window_ms",
		"upstream_dial_timeout_ms",
		"coalesce_window_ms",
		"coalesce_window_busy_ms",
		"max_sessions",
		"max_drain_frames_per_session",
		"max_request_body_bytes",
		"max_response_bytes_pre_encode",
		"initial_response_cap_enabled",
		"initial_response_bytes_pre_encode",
		"second_response_cap_enabled",
		"second_response_bytes_pre_encode",
		"downstream_replay_enabled",
	} {
		if v, ok := cfg[key]; ok {
			if s, ok := v.(string); ok && isPathConfigKey(key) {
				out[key] = redactPathString(s)
				continue
			}
			out[key] = v
		}
	}
	if v, ok := cfg["upstream_proxy"].(string); ok && strings.TrimSpace(v) != "" {
		out["upstream_proxy_configured"] = true
	}
	return out
}

func serverDiagnosticsEffectiveConfigSummary(cfg config.Server) map[string]any {
	out := map[string]any{
		"listen_addr":                       cfg.ListenAddr,
		"debug_timing":                      cfg.DebugTiming,
		"stats_json":                        cfg.StatsJSON,
		"debug_pprof_addr":                  cfg.DebugPprofAddr,
		"write_startup_diagnostics":         cfg.WriteStartupDiagnostics,
		"diagnostics_output_dir":            redactPathString(cfg.DiagnosticsOutputDir),
		"save_terminal_log":                 cfg.SaveTerminalLog,
		"terminal_log_file":                 redactPathString(cfg.TerminalLogFile),
		"auto_tune":                         cfg.AutoTune,
		"performance_mode":                  cfg.PerformanceMode,
		"active_drain_window_ms":            cfg.ActiveDrainWindowMs,
		"long_poll_window_ms":               cfg.LongPollWindowMs,
		"upstream_dial_timeout_ms":          cfg.UpstreamDialTimeoutMs,
		"coalesce_window_ms":                cfg.CoalesceWindowMs,
		"coalesce_window_busy_ms":           cfg.CoalesceWindowBusyMs,
		"max_sessions":                      cfg.MaxSessions,
		"max_drain_frames_per_session":      cfg.MaxDrainFramesPerSession,
		"max_request_body_bytes":            cfg.MaxRequestBodyBytes,
		"max_response_bytes_pre_encode":     cfg.MaxResponseBytesPreEncode,
		"initial_response_cap_enabled":      cfg.InitialResponseCapEnabled,
		"initial_response_bytes_pre_encode": cfg.InitialResponseBytesPreEncode,
		"second_response_cap_enabled":       cfg.SecondResponseCapEnabled,
		"second_response_bytes_pre_encode":  cfg.SecondResponseBytesPreEncode,
		"downstream_replay_enabled":         cfg.DownstreamReplayEnabled,
	}
	if strings.TrimSpace(cfg.UpstreamProxy) != "" {
		out["upstream_proxy_configured"] = true
	}
	if len(cfg.UnknownFields) > 0 {
		out["unknown_fields"] = append([]string(nil), cfg.UnknownFields...)
	}
	return out
}

func addServerProfile(zw *zip.Writer, name, profile string, debug int) error {
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

func addServerRedactedConfig(zw *zip.Writer, configPath string) error {
	w, err := zw.Create("server_config.redacted.json")
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(configPath)
	if err != nil {
		_, writeErr := fmt.Fprintf(w, "%s\n", diagnosticsConfigReadError(configPath, err))
		return writeErr
	}
	redacted, err := redactServerConfigJSON(raw)
	if err != nil {
		_, writeErr := fmt.Fprintf(w, "unable to parse config as JSON; raw config omitted: %v\n", err)
		return writeErr
	}
	_, err = w.Write(redacted)
	return err
}

func redactServerConfigJSON(raw []byte) ([]byte, error) {
	raw = bytes.TrimPrefix(raw, []byte{0xef, 0xbb, 0xbf})
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	redacted := redactServerJSONValue("", v)
	return json.MarshalIndent(redacted, "", "  ")
}

func redactServerJSONValue(key string, v any) any {
	lowerKey := strings.ToLower(key)
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, child := range x {
			out[k] = redactServerJSONValue(k, child)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, child := range x {
			out[i] = redactServerJSONValue(lowerKey, child)
		}
		return out
	case string:
		switch {
		case lowerKey == "upstream_proxy":
			return redactServerEndpoint(x)
		case isPathConfigKey(lowerKey):
			return redactPathString(x)
		case isServerSensitiveConfigKey(lowerKey):
			return redactServerSecretString(x, "secret")
		default:
			return x
		}
	default:
		return v
	}
}

func isServerSensitiveConfigKey(key string) bool {
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

func redactServerSecretString(s, label string) string {
	if s == "" {
		return ""
	}
	return fmt.Sprintf("<redacted %s len=%d>", label, len(s))
}

func redactServerEndpoint(s string) string {
	if s == "" {
		return ""
	}
	u, err := url.Parse(s)
	if err != nil || u.Scheme == "" {
		return "<redacted endpoint>"
	}
	return u.Scheme + "://<redacted>"
}
