package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testServerKeyHex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestLoadServerInitialResponseBytesPreEncode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server.json")
	body := `{
		"server_host": "127.0.0.1",
		"server_port": 8443,
		"tunnel_key": "` + testServerKeyHex + `",
		"initial_response_bytes_pre_encode": 131072
	}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cfg, err := LoadServer(path)
	if err != nil {
		t.Fatalf("LoadServer: %v", err)
	}
	if cfg.InitialResponseBytesPreEncode != 131072 {
		t.Fatalf("InitialResponseBytesPreEncode = %d, want 131072", cfg.InitialResponseBytesPreEncode)
	}
}

func TestLoadServerRejectsNegativeInitialResponseBytes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server.json")
	body := `{
		"server_host": "127.0.0.1",
		"server_port": 8443,
		"tunnel_key": "` + testServerKeyHex + `",
		"initial_response_bytes_pre_encode": -1
	}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	_, err := LoadServer(path)
	if err == nil {
		t.Fatal("LoadServer succeeded with negative initial_response_bytes_pre_encode")
	}
	if !strings.Contains(err.Error(), "initial_response_bytes_pre_encode") {
		t.Fatalf("LoadServer err = %v, want initial_response_bytes_pre_encode validation", err)
	}
}
