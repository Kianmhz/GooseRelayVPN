package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadClient_QuotaStatePathDefaultsBesideConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "client_config.json")
	key := strings.Repeat("a", 64)
	deploymentID := "AKfycb" + strings.Repeat("x", 60)
	body := `{
  "script_keys": [{"id": "` + deploymentID + `", "account": "acct-a"}],
  "tunnel_key": "` + key + `"
}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadClient(path)
	if err != nil {
		t.Fatalf("LoadClient: %v", err)
	}
	want := filepath.Join(dir, ".goose-quota-state.json")
	if cfg.QuotaStatePath != want {
		t.Fatalf("QuotaStatePath = %q, want %q", cfg.QuotaStatePath, want)
	}
}

func TestLoadClient_QuotaStatePathCanBeDisabled(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "client_config.json")
	key := strings.Repeat("b", 64)
	deploymentID := "AKfycb" + strings.Repeat("y", 60)
	body := `{
  "script_keys": [{"id": "` + deploymentID + `", "account": "acct-a"}],
  "quota_state_path": "",
  "tunnel_key": "` + key + `"
}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadClient(path)
	if err != nil {
		t.Fatalf("LoadClient: %v", err)
	}
	if cfg.QuotaStatePath != "" {
		t.Fatalf("QuotaStatePath = %q, want disabled empty path", cfg.QuotaStatePath)
	}
}
