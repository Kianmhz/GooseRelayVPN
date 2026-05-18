package main

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"strings"
	"time"
)

func writeDiagnosticsZip(outPath, configPath, version string) (string, error) {
	if strings.TrimSpace(outPath) == "" {
		outPath = fmt.Sprintf("goose-diagnostics-%s.zip", time.Now().Format("20060102-150405"))
	}
	outPath = filepath.Clean(outPath)

	f, err := os.Create(outPath)
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

Config source: %s
Generated at: %s
`, configPath, time.Now().Format(time.RFC3339))
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
cwd: %s
executable: %s
config_path: %s
`, version, time.Now().Format(time.RFC3339), runtime.Version(), runtime.GOOS, runtime.GOARCH, runtime.NumCPU(), runtime.GOMAXPROCS(0), runtime.NumGoroutine(), cwd, exe, configPath)
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
			"config_error": err.Error(),
		}
		body, marshalErr := json.MarshalIndent(summary, "", "  ")
		if marshalErr != nil {
			return marshalErr
		}
		_, err = w.Write(append(body, '\n'))
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
		_, err = w.Write(append(body, '\n'))
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
		"debug_timing",
		"socks_host",
		"socks_port",
		"google_host",
		"coalesce_step_ms",
		"idle_slots_per_bucket",
	} {
		if v, ok := cfg[key]; ok {
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
	return out
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
	return p.WriteTo(w, debug)
}

func addRedactedConfig(zw *zip.Writer, configPath string) error {
	w, err := zw.Create("client_config.redacted.json")
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(configPath)
	if err != nil {
		_, writeErr := fmt.Fprintf(w, "unable to read config %q: %v\n", configPath, err)
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
		case lowerKey == "relay_urls" || lowerKey == "upstream_proxy":
			return redactEndpoint(x)
		case isSensitiveConfigKey(lowerKey):
			return redactSecretString(x, "secret")
		default:
			return x
		}
	default:
		return v
	}
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
