package main

import (
	"archive/zip"
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
	raw := `{
		"script_keys": [{"id": "AKfycbabcdefghijklmnopqrstuvwxyz", "account": "acct-a"}],
		"tunnel_key": "` + secretKey + `"
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
	for _, f := range zr.File {
		switch f.Name {
		case "client_config.redacted.json":
			sawConfig = true
			text := readZipFile(t, f)
			if strings.Contains(text, secretKey) || strings.Contains(text, "AKfycbabcdefghijklmnopqrstuvwxyz") {
				t.Fatalf("redacted config leaked secret:\n%s", text)
			}
			if !strings.Contains(text, "acct-a") {
				t.Fatalf("redacted config should preserve account label:\n%s", text)
			}
		case "diagnostics.json":
			sawSummary = true
			text := readZipFile(t, f)
			if !strings.Contains(text, `"version": "test-version"`) {
				t.Fatalf("diagnostics summary missing version:\n%s", text)
			}
			if strings.Contains(text, secretKey) || strings.Contains(text, "AKfycbabcdefghijklmnopqrstuvwxyz") {
				t.Fatalf("diagnostics summary leaked secret:\n%s", text)
			}
		}
	}
	if !sawConfig {
		t.Fatalf("diagnostics zip did not include client_config.redacted.json")
	}
	if !sawSummary {
		t.Fatalf("diagnostics zip did not include diagnostics.json")
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
