package main

import (
	"archive/zip"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kianmhz/GooseRelayVPN/internal/config"
)

func TestRedactServerConfigJSONRedactsSecrets(t *testing.T) {
	raw := []byte(`{
		"server_host": "0.0.0.0",
		"server_port": 8443,
		"tunnel_key": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		"upstream_proxy": "socks5://user:pass@127.0.0.1:40000",
		"debug_timing": true
	}`)

	out, err := redactServerConfigJSON(raw)
	if err != nil {
		t.Fatalf("redactServerConfigJSON: %v", err)
	}
	text := string(out)
	for _, secret := range []string{
		"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		"user:pass",
		"127.0.0.1",
	} {
		if strings.Contains(text, secret) {
			t.Fatalf("redacted server config leaked %q in:\n%s", secret, text)
		}
	}
	if !strings.Contains(text, `"debug_timing": true`) {
		t.Fatalf("redacted server config should preserve non-secret tuning fields, got:\n%s", text)
	}
}

func TestWriteServerDiagnosticsZipRedactsConfig(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "server_config.json")
	secretKey := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	raw := `{
		"server_host": "0.0.0.0",
		"server_port": 8443,
		"tunnel_key": "` + secretKey + `",
		"upstream_proxy": "socks5://127.0.0.1:40000"
	}`
	if err := os.WriteFile(configPath, []byte(raw), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	zipPath := filepath.Join(dir, "diag.zip")
	out, err := writeServerDiagnosticsZip(zipPath, configPath, "test-version")
	if err != nil {
		t.Fatalf("writeServerDiagnosticsZip: %v", err)
	}
	if out != zipPath {
		t.Fatalf("output path = %q, want %q", out, zipPath)
	}

	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		t.Fatalf("open zip: %v", err)
	}
	defer zr.Close()

	var sawConfig bool
	var sawSummary bool
	var sawRuntime bool
	var sawReadme bool
	for _, f := range zr.File {
		if f.Name == "README.txt" {
			sawReadme = true
			text := readServerZipFile(t, f)
			if strings.Contains(text, dir) || strings.Contains(text, configPath) {
				t.Fatalf("README leaked absolute path:\n%s", text)
			}
			if !strings.Contains(text, "server_config.json") {
				t.Fatalf("README missing config basename:\n%s", text)
			}
		}
		if f.Name == "runtime.txt" {
			sawRuntime = true
			text := readServerZipFile(t, f)
			if strings.Contains(text, dir) || strings.Contains(text, configPath) {
				t.Fatalf("runtime leaked absolute path:\n%s", text)
			}
			if strings.Contains(text, "cwd:") || strings.Contains(text, "executable:") || strings.Contains(text, "config_path:") {
				t.Fatalf("runtime should expose basename-only path fields:\n%s", text)
			}
		}
		if f.Name == "server_config.redacted.json" {
			sawConfig = true
			text := readServerZipFile(t, f)
			if strings.Contains(text, secretKey) || strings.Contains(text, "127.0.0.1") {
				t.Fatalf("redacted server config leaked secret:\n%s", text)
			}
		}
		if f.Name == "diagnostics.json" {
			sawSummary = true
			text := readServerZipFile(t, f)
			if !strings.Contains(text, `"version": "test-version"`) {
				t.Fatalf("diagnostics summary missing version:\n%s", text)
			}
			if strings.Contains(text, secretKey) || strings.Contains(text, "127.0.0.1") {
				t.Fatalf("diagnostics summary leaked secret:\n%s", text)
			}
			if !strings.Contains(text, `"max_drain_frames_per_session": 8`) {
				t.Fatalf("diagnostics summary missing effective default max_drain_frames_per_session:\n%s", text)
			}
		}
	}
	if !sawConfig {
		t.Fatalf("diagnostics zip did not include server_config.redacted.json")
	}
	if !sawSummary {
		t.Fatalf("diagnostics zip did not include diagnostics.json")
	}
	if !sawRuntime {
		t.Fatalf("diagnostics zip did not include runtime.txt")
	}
	if !sawReadme {
		t.Fatalf("diagnostics zip did not include README.txt")
	}
}

func TestWriteServerDiagnosticsZipRefusesExistingOutput(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "server_config.json")
	secretKey := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	raw := `{
		"tunnel_key": "` + secretKey + `"
	}`
	if err := os.WriteFile(configPath, []byte(raw), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	zipPath := filepath.Join(dir, "diag.zip")
	if err := os.WriteFile(zipPath, []byte("existing"), 0o600); err != nil {
		t.Fatalf("write existing zip: %v", err)
	}
	if _, err := writeServerDiagnosticsZip(zipPath, configPath, "test-version"); err == nil {
		t.Fatal("writeServerDiagnosticsZip overwrote an existing explicit output path")
	}
	got, err := os.ReadFile(zipPath)
	if err != nil {
		t.Fatalf("read existing zip: %v", err)
	}
	if string(got) != "existing" {
		t.Fatalf("existing output changed to %q", got)
	}
}

func TestWriteServerDiagnosticsZipAcceptsUTF8BOMConfig(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "server_config.json")
	secretKey := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	raw := "\xef\xbb\xbf" + `{
		"server_host": "127.0.0.1",
		"server_port": 8443,
		"tunnel_key": "` + secretKey + `"
	}`
	if err := os.WriteFile(configPath, []byte(raw), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	zipPath := filepath.Join(dir, "diag.zip")
	if _, err := writeServerDiagnosticsZip(zipPath, configPath, "test-version"); err != nil {
		t.Fatalf("writeServerDiagnosticsZip: %v", err)
	}

	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		t.Fatalf("open zip: %v", err)
	}
	defer zr.Close()
	for _, f := range zr.File {
		if f.Name != "diagnostics.json" && f.Name != "server_config.redacted.json" {
			continue
		}
		text := readServerZipFile(t, f)
		if strings.Contains(text, "config_error") || strings.Contains(text, "unable to parse") {
			t.Fatalf("%s should parse UTF-8 BOM config, got:\n%s", f.Name, text)
		}
		if strings.Contains(text, secretKey) {
			t.Fatalf("%s leaked secret:\n%s", f.Name, text)
		}
	}
}

func TestServerDiagnosticsConfigSummaryOnlyMarksNonEmptyUpstreamProxy(t *testing.T) {
	empty := serverDiagnosticsConfigSummary(map[string]any{
		"upstream_proxy": "",
	})
	if _, ok := empty["upstream_proxy_configured"]; ok {
		t.Fatalf("empty upstream_proxy should not be marked configured: %#v", empty)
	}

	configured := serverDiagnosticsConfigSummary(map[string]any{
		"upstream_proxy": "socks5://<redacted>",
	})
	if configured["upstream_proxy_configured"] != true {
		t.Fatalf("non-empty upstream_proxy should be marked configured: %#v", configured)
	}
}

func TestServerDiagnosticsPathFieldsAreSanitized(t *testing.T) {
	dir := t.TempDir()
	absDiag := filepath.Join(dir, "diagnostics")
	absLog := filepath.Join(dir, "logs", "goose-server.log")

	summary := serverDiagnosticsConfigSummary(map[string]any{
		"diagnostics_output_dir": absDiag,
		"terminal_log_file":      absLog,
	})
	for _, key := range []string{"diagnostics_output_dir", "terminal_log_file"} {
		if summary[key] != "<path redacted>" {
			t.Fatalf("%s summary = %#v, want path redacted", key, summary[key])
		}
	}

	effective := serverDiagnosticsEffectiveConfigSummary(config.Server{
		DiagnosticsOutputDir: absDiag,
		TerminalLogFile:      absLog,
	})
	for _, key := range []string{"diagnostics_output_dir", "terminal_log_file"} {
		if effective[key] != "<path redacted>" {
			t.Fatalf("%s effective summary = %#v, want path redacted", key, effective[key])
		}
	}

	raw, err := json.Marshal(map[string]any{
		"diagnostics_output_dir": absDiag,
		"terminal_log_file":      absLog,
	})
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	redacted, err := redactServerConfigJSON(raw)
	if err != nil {
		t.Fatalf("redactServerConfigJSON: %v", err)
	}
	text := string(redacted)
	if strings.Contains(text, dir) || strings.Contains(text, filepath.ToSlash(dir)) {
		t.Fatalf("redacted config leaked absolute path:\n%s", text)
	}
	var got map[string]string
	if err := json.Unmarshal(redacted, &got); err != nil {
		t.Fatalf("unmarshal redacted config: %v", err)
	}
	for _, key := range []string{"diagnostics_output_dir", "terminal_log_file"} {
		if got[key] != "<path redacted>" {
			t.Fatalf("%s redacted value = %q, want path redacted", key, got[key])
		}
	}

	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("get cwd: %v", err)
	}
	sanitized := sanitizeDiagnosticsText("cwd=" + cwd + "\nslash=" + filepath.ToSlash(cwd))
	if strings.Contains(sanitized, cwd) || strings.Contains(sanitized, filepath.ToSlash(cwd)) {
		t.Fatalf("sanitized diagnostics text leaked cwd:\n%s", sanitized)
	}
}

func TestServerDiagnosticsConfigReadErrorDoesNotLeakAbsolutePath(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "missing-server-config.json")
	_, err := os.ReadFile(missing)
	if err == nil {
		t.Fatal("expected missing config read to fail")
	}
	got := diagnosticsConfigReadError(missing, err)
	if strings.Contains(got, dir) || strings.Contains(got, filepath.ToSlash(dir)) {
		t.Fatalf("config read error leaked absolute path: %q", got)
	}
	if !strings.Contains(got, "missing-server-config.json") {
		t.Fatalf("config read error should keep basename, got %q", got)
	}
}

func TestServerStartupDiagnosticsOutputPath(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "diag")
	got, err := startupDiagnosticsOutputPathInBase(t.TempDir(), dir, "goose-server-diagnostics")
	if err != nil {
		t.Fatalf("startupDiagnosticsOutputPathInBase: %v", err)
	}
	if filepath.Dir(got) != dir {
		t.Fatalf("output dir = %q, want %q", filepath.Dir(got), dir)
	}
	if !strings.HasPrefix(filepath.Base(got), "goose-server-diagnostics-") || !strings.HasSuffix(got, ".zip") {
		t.Fatalf("output path = %q, want timestamped server diagnostics zip", got)
	}
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("diagnostics dir was not created: %v", err)
	}
}

func TestServerStartupDiagnosticsOutputPathDefaultUsesDiagnosticsDirBesideBinary(t *testing.T) {
	base := t.TempDir()
	got, err := startupDiagnosticsOutputPathInBase(base, "", "goose-server-diagnostics")
	if err != nil {
		t.Fatalf("startupDiagnosticsOutputPathInBase: %v", err)
	}
	wantDir := filepath.Join(base, "diagnostics")
	if filepath.Dir(got) != wantDir {
		t.Fatalf("default output dir = %q, want %q", filepath.Dir(got), wantDir)
	}
	if !strings.HasPrefix(filepath.Base(got), "goose-server-diagnostics-") || !strings.HasSuffix(got, ".zip") {
		t.Fatalf("output path = %q, want timestamped server diagnostics zip", got)
	}
	if _, err := os.Stat(wantDir); err != nil {
		t.Fatalf("diagnostics dir was not created: %v", err)
	}
}

func TestServerStartupDiagnosticsOutputPathDoesNotReuseExistingFile(t *testing.T) {
	base := t.TempDir()
	first, err := startupDiagnosticsOutputPathInBase(base, "", "goose-server-diagnostics")
	if err != nil {
		t.Fatalf("first startupDiagnosticsOutputPathInBase: %v", err)
	}
	if err := os.WriteFile(first, []byte("old"), 0o600); err != nil {
		t.Fatalf("write first diagnostics placeholder: %v", err)
	}
	second, err := startupDiagnosticsOutputPathInBase(base, "", "goose-server-diagnostics")
	if err != nil {
		t.Fatalf("second startupDiagnosticsOutputPathInBase: %v", err)
	}
	if second == first {
		t.Fatalf("second diagnostics path reused %q; want a fresh path", first)
	}
}

func readServerZipFile(t *testing.T, f *zip.File) string {
	t.Helper()
	rc, err := f.Open()
	if err != nil {
		t.Fatalf("open %s: %v", f.Name, err)
	}
	defer rc.Close()
	data, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("read %s: %v", f.Name, err)
	}
	return string(data)
}
