package main

import (
	"archive/zip"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRedactConfigJSONRedactsSecretsAndKeepsUsefulLabels(t *testing.T) {
	raw := []byte(`{
		"script_keys": [
			{"id": "AKfycbabcdefghijklmnopqrstuvwxyz", "account": "acct-a"},
			"AKfycbyabcdefghijklmnopqrstuvwxyz"
		],
		"relay_urls": ["https://script.google.com/macros/s/SECRET_DEPLOYMENT/exec"],
		"direct_stream_urls": ["wss://vps.example.com:8443/stream"],
		"tunnel_key": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		"socks_user": "user",
		"socks_pass": "pass"
	}`)

	out, err := redactConfigJSON(raw)
	if err != nil {
		t.Fatalf("redactConfigJSON: %v", err)
	}
	text := string(out)
	for _, secret := range []string{
		"AKfycbabcdefghijklmnopqrstuvwxyz",
		"AKfycbyabcdefghijklmnopqrstuvwxyz",
		"SECRET_DEPLOYMENT",
		"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		`"pass"`,
		"vps.example.com",
	} {
		if strings.Contains(text, secret) {
			t.Fatalf("redacted config leaked %q in:\n%s", secret, text)
		}
	}
	if !strings.Contains(text, `"account": "acct-a"`) {
		t.Fatalf("redacted config should preserve account labels, got:\n%s", text)
	}
	if !strings.Contains(text, `"socks_user": "user"`) {
		t.Fatalf("redacted config should preserve non-secret SOCKS username, got:\n%s", text)
	}
}

func TestWriteDiagnosticsZipRedactsConfig(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "client_config.json")
	secretKey := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	deploymentID := "AKfycb" + strings.Repeat("a", 64)
	raw := `{
		"script_keys": [{"id": "` + deploymentID + `", "account": "acct-a"}],
		"tunnel_key": "` + secretKey + `",
		"transport_mode": "apps_script",
		"debug_timing": true,
		"tx_slots_per_bucket": 2
	}`
	if err := os.WriteFile(configPath, []byte(raw), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	zipPath := filepath.Join(dir, "diag.zip")
	out, err := writeDiagnosticsZip(zipPath, configPath, "test-version")
	if err != nil {
		t.Fatalf("writeDiagnosticsZip: %v", err)
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
			text := readZipFile(t, f)
			if strings.Contains(text, dir) || strings.Contains(text, configPath) {
				t.Fatalf("README leaked absolute path:\n%s", text)
			}
			if !strings.Contains(text, "client_config.json") {
				t.Fatalf("README missing config basename:\n%s", text)
			}
		}
		if f.Name == "runtime.txt" {
			sawRuntime = true
			text := readZipFile(t, f)
			if strings.Contains(text, dir) || strings.Contains(text, configPath) {
				t.Fatalf("runtime leaked absolute path:\n%s", text)
			}
			if strings.Contains(text, "cwd:") || strings.Contains(text, "executable:") || strings.Contains(text, "config_path:") {
				t.Fatalf("runtime should expose basename-only path fields:\n%s", text)
			}
		}
		if f.Name == "client_config.redacted.json" {
			sawConfig = true
			text := readZipFile(t, f)
			if strings.Contains(text, secretKey) || strings.Contains(text, deploymentID) {
				t.Fatalf("redacted config leaked secret:\n%s", text)
			}
			if !strings.Contains(text, "acct-a") {
				t.Fatalf("redacted config should preserve account label:\n%s", text)
			}
		}
		if f.Name == "diagnostics.json" {
			sawSummary = true
			text := readZipFile(t, f)
			if !strings.Contains(text, `"version": "test-version"`) {
				t.Fatalf("diagnostics summary missing version:\n%s", text)
			}
			if strings.Contains(text, secretKey) || strings.Contains(text, deploymentID) {
				t.Fatalf("diagnostics summary leaked secret:\n%s", text)
			}
			var summary map[string]any
			if err := json.Unmarshal([]byte(text), &summary); err != nil {
				t.Fatalf("unmarshal diagnostics summary: %v\n%s", err, text)
			}
			effective, ok := summary["effective_config"].(map[string]any)
			if !ok {
				t.Fatalf("diagnostics summary missing effective_config:\n%s", text)
			}
			if effective["transport_mode"] != "apps_script" || effective["debug_timing"] != true {
				t.Fatalf("effective_config missing resolved client fields: %#v", effective)
			}
			if effective["script_key_count"] != float64(1) || effective["tx_slots_per_bucket"] != float64(2) {
				t.Fatalf("effective_config has wrong counts/slots: %#v", effective)
			}
		}
	}
	if !sawConfig {
		t.Fatalf("diagnostics zip did not include client_config.redacted.json")
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

func TestWriteDiagnosticsZipRefusesExistingOutput(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "client_config.json")
	secretKey := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	raw := `{
		"script_keys": [{"id": "AKfycbabcdefghijklmnopqrstuvwxyz"}],
		"tunnel_key": "` + secretKey + `"
	}`
	if err := os.WriteFile(configPath, []byte(raw), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	zipPath := filepath.Join(dir, "diag.zip")
	if err := os.WriteFile(zipPath, []byte("existing"), 0o600); err != nil {
		t.Fatalf("write existing zip: %v", err)
	}
	if _, err := writeDiagnosticsZip(zipPath, configPath, "test-version"); err == nil {
		t.Fatal("writeDiagnosticsZip overwrote an existing explicit output path")
	}
	got, err := os.ReadFile(zipPath)
	if err != nil {
		t.Fatalf("read existing zip: %v", err)
	}
	if string(got) != "existing" {
		t.Fatalf("existing output changed to %q", got)
	}
}

func TestWriteDiagnosticsZipAcceptsUTF8BOMConfig(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "client_config.json")
	secretKey := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	deploymentID := "AKfycb" + strings.Repeat("b", 64)
	raw := "\xef\xbb\xbf" + `{
		"script_keys": [{"id": "` + deploymentID + `", "account": "acct-a"}],
		"tunnel_key": "` + secretKey + `",
		"transport_mode": "apps_script"
	}`
	if err := os.WriteFile(configPath, []byte(raw), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	zipPath := filepath.Join(dir, "diag.zip")
	if _, err := writeDiagnosticsZip(zipPath, configPath, "test-version"); err != nil {
		t.Fatalf("writeDiagnosticsZip: %v", err)
	}

	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		t.Fatalf("open zip: %v", err)
	}
	defer zr.Close()
	for _, f := range zr.File {
		if f.Name != "diagnostics.json" && f.Name != "client_config.redacted.json" {
			continue
		}
		text := readZipFile(t, f)
		if strings.Contains(text, "config_error") || strings.Contains(text, "unable to parse") {
			t.Fatalf("%s should parse UTF-8 BOM config, got:\n%s", f.Name, text)
		}
		if strings.Contains(text, secretKey) || strings.Contains(text, deploymentID) {
			t.Fatalf("%s leaked secret:\n%s", f.Name, text)
		}
	}
}

func TestStartupDiagnosticsOutputPath(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "diag")
	got, err := startupDiagnosticsOutputPathInBase(t.TempDir(), dir, "goose-diagnostics")
	if err != nil {
		t.Fatalf("startupDiagnosticsOutputPathInBase: %v", err)
	}
	if filepath.Dir(got) != dir {
		t.Fatalf("output dir = %q, want %q", filepath.Dir(got), dir)
	}
	if !strings.HasPrefix(filepath.Base(got), "goose-diagnostics-") || !strings.HasSuffix(got, ".zip") {
		t.Fatalf("output path = %q, want timestamped goose diagnostics zip", got)
	}
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("diagnostics dir was not created: %v", err)
	}
}

func TestStartupDiagnosticsOutputPathDefaultUsesDiagnosticsDirBesideBinary(t *testing.T) {
	base := t.TempDir()
	got, err := startupDiagnosticsOutputPathInBase(base, "", "goose-diagnostics")
	if err != nil {
		t.Fatalf("startupDiagnosticsOutputPathInBase: %v", err)
	}
	wantDir := filepath.Join(base, "diagnostics")
	if filepath.Dir(got) != wantDir {
		t.Fatalf("default output dir = %q, want %q", filepath.Dir(got), wantDir)
	}
	if !strings.HasPrefix(filepath.Base(got), "goose-diagnostics-") || !strings.HasSuffix(got, ".zip") {
		t.Fatalf("output path = %q, want timestamped goose diagnostics zip", got)
	}
	if _, err := os.Stat(wantDir); err != nil {
		t.Fatalf("diagnostics dir was not created: %v", err)
	}
}

func TestStartupDiagnosticsOutputPathDoesNotReuseExistingFile(t *testing.T) {
	base := t.TempDir()
	first, err := startupDiagnosticsOutputPathInBase(base, "", "goose-diagnostics")
	if err != nil {
		t.Fatalf("first startupDiagnosticsOutputPathInBase: %v", err)
	}
	if err := os.WriteFile(first, []byte("old"), 0o600); err != nil {
		t.Fatalf("write first diagnostics placeholder: %v", err)
	}
	second, err := startupDiagnosticsOutputPathInBase(base, "", "goose-diagnostics")
	if err != nil {
		t.Fatalf("second startupDiagnosticsOutputPathInBase: %v", err)
	}
	if second == first {
		t.Fatalf("second diagnostics path reused %q; want a fresh path", first)
	}
}

func TestDiagnosticsConfigSummaryKeepsConnectionFields(t *testing.T) {
	summary := diagnosticsConfigSummary(map[string]any{
		"socks_host":          "0.0.0.0",
		"socks_port":          float64(47115),
		"google_host":         "216.239.38.120",
		"fresh_start_reset":   true,
		"quota_state_path":    ".goose-quota-state.json",
		"tx_slots_per_bucket": float64(3),
		"tunnel_key":          "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	})
	for _, key := range []string{"socks_host", "socks_port", "google_host", "fresh_start_reset", "quota_state_path", "tx_slots_per_bucket"} {
		if _, ok := summary[key]; !ok {
			t.Fatalf("summary missing %s: %#v", key, summary)
		}
	}
	if _, ok := summary["tunnel_key"]; ok {
		t.Fatalf("summary leaked tunnel_key: %#v", summary)
	}
}

func TestDiagnosticsPathFieldsAreSanitized(t *testing.T) {
	dir := t.TempDir()
	absDiag := filepath.Join(dir, "diagnostics")
	absLog := filepath.Join(dir, "logs", "goose-client.log")
	absQuota := filepath.Join(dir, "quota.json")

	summary := diagnosticsConfigSummary(map[string]any{
		"diagnostics_output_dir": absDiag,
		"terminal_log_file":      absLog,
		"quota_state_path":       absQuota,
	})
	for _, key := range []string{"diagnostics_output_dir", "terminal_log_file", "quota_state_path"} {
		if summary[key] != "<path redacted>" {
			t.Fatalf("%s summary = %#v, want path redacted", key, summary[key])
		}
	}

	raw, err := json.Marshal(map[string]any{
		"diagnostics_output_dir": absDiag,
		"terminal_log_file":      absLog,
		"quota_state_path":       absQuota,
	})
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	redacted, err := redactConfigJSON(raw)
	if err != nil {
		t.Fatalf("redactConfigJSON: %v", err)
	}
	text := string(redacted)
	if strings.Contains(text, dir) || strings.Contains(text, filepath.ToSlash(dir)) {
		t.Fatalf("redacted config leaked absolute path:\n%s", text)
	}
	var got map[string]string
	if err := json.Unmarshal(redacted, &got); err != nil {
		t.Fatalf("unmarshal redacted config: %v", err)
	}
	for _, key := range []string{"diagnostics_output_dir", "terminal_log_file", "quota_state_path"} {
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

func TestDiagnosticsConfigReadErrorDoesNotLeakAbsolutePath(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "missing-client-config.json")
	_, err := os.ReadFile(missing)
	if err == nil {
		t.Fatal("expected missing config read to fail")
	}
	got := diagnosticsConfigReadError(missing, err)
	if strings.Contains(got, dir) || strings.Contains(got, filepath.ToSlash(dir)) {
		t.Fatalf("config read error leaked absolute path: %q", got)
	}
	if !strings.Contains(got, "missing-client-config.json") {
		t.Fatalf("config read error should keep basename, got %q", got)
	}
}

func readZipFile(t *testing.T, f *zip.File) string {
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
