package config

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
)

// Server is the VPS exit server config.
type Server struct {
	ListenAddr                    string
	AESKeyHex                     string
	DebugTiming                   bool
	UpstreamProxy                 string // optional socks5://host:port; when set, all outbound dials go through this proxy
	InitialResponseBytesPreEncode int
}

type serverFile struct {
	// New user-friendly keys.
	ServerHost string `json:"server_host"`
	ServerPort int    `json:"server_port"`
	TunnelKey  string `json:"tunnel_key"`

	// Optional: when true, log per-session dial breakdown (DNS, TCP, first
	// upstream read) so an operator can pinpoint where latency is going.
	DebugTiming bool `json:"debug_timing"`

	// Optional: route all outbound connections through a local SOCKS5 proxy
	// (e.g. Cloudflare WARP on socks5://127.0.0.1:40000). Useful when the VPS
	// datacenter IP is blocked by certain sites.
	UpstreamProxy string `json:"upstream_proxy"`

	// Optional: cap the first downstream response for a newly opened session.
	// 0 uses the server default.
	InitialResponseBytesPreEncode int `json:"initial_response_bytes_pre_encode"`

	// Legacy keys kept as fallback for existing deployments.
	ListenAddr string `json:"listen_addr"`
	AESKeyHex  string `json:"aes_key_hex"`
}

func parseLegacyListenAddr(addr string) (string, int) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return "", 0
	}
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return "", 0
	}
	return strings.TrimSpace(host), port
}

// LoadServer reads and validates a server config file.
func LoadServer(path string) (*Server, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("config file %q not found.\n  Fix: copy the example and edit it:\n      cp server_config.example.json %s", path, path)
		}
		return nil, fmt.Errorf("cannot read config %q: %w", path, err)
	}
	var f serverFile
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("config %q is not valid JSON: %v\n  Common causes: missing comma between fields, trailing comma after the last field, unclosed quote, or a typo in a field name", path, err)
	}

	legacyHost, legacyPort := parseLegacyListenAddr(f.ListenAddr)
	listenHost := firstNonEmpty(f.ServerHost, legacyHost, "0.0.0.0")
	listenPort := firstPositive(f.ServerPort, legacyPort)
	if listenPort == 0 {
		listenPort = 8443
	}
	if listenPort < 1 || listenPort > 65535 {
		return nil, fmt.Errorf("server_port %d is out of range (must be 1-65535)", listenPort)
	}

	key := strings.TrimSpace(firstNonEmpty(f.TunnelKey, f.AESKeyHex))
	if key == "" || key == "SAME_VALUE_AS_CLIENT_tunnel_key" {
		return nil, fmt.Errorf("tunnel_key is empty or still the placeholder text in %s.\n  Fix: paste the 64-character key from your client_config.json into the tunnel_key field. Both files must contain the SAME value", path)
	}
	if len(key) != 64 {
		return nil, fmt.Errorf("tunnel_key must be exactly 64 hex characters (got %d) in %s.\n  Fix: paste the SAME tunnel_key from client_config.json — both files must contain byte-identical values", len(key), path)
	}
	raw, err := hex.DecodeString(key)
	if err != nil || len(raw) != 32 {
		return nil, fmt.Errorf("tunnel_key in %s contains non-hex characters.\n  Valid characters are 0-9 and a-f. Copy the value from client_config.json carefully — no spaces, quotes, or extra newlines", path)
	}

	var upstreamProxy string
	if raw := strings.TrimSpace(f.UpstreamProxy); raw != "" {
		u, err := url.Parse(raw)
		if err != nil || u.Scheme != "socks5" {
			return nil, fmt.Errorf("upstream_proxy must be a socks5:// URL (e.g. socks5://127.0.0.1:40000), got %q", raw)
		}
		if u.Host == "" {
			return nil, fmt.Errorf("upstream_proxy is missing host:port (e.g. socks5://127.0.0.1:40000)")
		}
		upstreamProxy = u.Host
	}
	if f.InitialResponseBytesPreEncode < 0 {
		return nil, fmt.Errorf("initial_response_bytes_pre_encode must be >= 0")
	}

	c := Server{
		ListenAddr:                    net.JoinHostPort(listenHost, strconv.Itoa(listenPort)),
		AESKeyHex:                     key,
		DebugTiming:                   f.DebugTiming,
		UpstreamProxy:                 upstreamProxy,
		InitialResponseBytesPreEncode: f.InitialResponseBytesPreEncode,
	}
	return &c, nil
}
