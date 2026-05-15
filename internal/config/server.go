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

	"github.com/kianmhz/GooseRelayVPN/internal/protocol"
)

// Server is the VPS exit server config.
type Server struct {
	ListenAddr                string
	AESKeyHex                 string
	DebugTiming               bool
	AutoTune                  bool
	UpstreamProxy             string // optional socks5://host:port; when set, all outbound dials go through this proxy
	PerformanceMode           string
	ActiveDrainWindowMs       int
	LongPollWindowMs          int
	UpstreamDialTimeoutMs     int
	CoalesceWindowMs          int
	CoalesceWindowBusyMs      int
	MaxSessions               int
	MaxRequestBodyBytes       int
	MaxResponseBytesPreEncode int
}

type serverFile struct {
	// New user-friendly keys.
	ServerHost string `json:"server_host"`
	ServerPort int    `json:"server_port"`
	TunnelKey  string `json:"tunnel_key"`

	// Optional: when true, log per-session dial breakdown (DNS, TCP, first
	// upstream read) so an operator can pinpoint where latency is going.
	DebugTiming bool `json:"debug_timing"`
	AutoTune    bool `json:"auto_tune"`

	// Optional: route all outbound connections through a local SOCKS5 proxy
	// (e.g. Cloudflare WARP on socks5://127.0.0.1:40000). Useful when the VPS
	// datacenter IP is blocked by certain sites.
	UpstreamProxy string `json:"upstream_proxy"`

	PerformanceMode           string `json:"performance_mode"`
	ActiveDrainWindowMs       int    `json:"active_drain_window_ms"`
	LongPollWindowMs          int    `json:"long_poll_window_ms"`
	UpstreamDialTimeoutMs     int    `json:"upstream_dial_timeout_ms"`
	CoalesceWindowMs          int    `json:"coalesce_window_ms"`
	CoalesceWindowBusyMs      int    `json:"coalesce_window_busy_ms"`
	MaxSessions               int    `json:"max_sessions"`
	MaxRequestBodyBytes       int    `json:"max_request_body_bytes"`
	MaxResponseBytesPreEncode int    `json:"max_response_bytes_pre_encode"`

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

	performanceMode, err := normalizePerformanceMode(f.PerformanceMode)
	if err != nil {
		return nil, err
	}
	activeDrainWindowMs := f.ActiveDrainWindowMs
	longPollWindowMs := f.LongPollWindowMs
	upstreamDialTimeoutMs := f.UpstreamDialTimeoutMs
	coalesceWindowMs := f.CoalesceWindowMs
	coalesceWindowBusyMs := f.CoalesceWindowBusyMs
	maxSessions := f.MaxSessions
	maxRequestBodyBytes := f.MaxRequestBodyBytes
	maxResponseBytesPreEncode := f.MaxResponseBytesPreEncode
	switch performanceMode {
	case "latency":
		if activeDrainWindowMs == 0 {
			activeDrainWindowMs = protocol.LatencyActiveDrainWindowMs
		}
		if longPollWindowMs == 0 {
			longPollWindowMs = protocol.LatencyLongPollWindowMs
		}
		if upstreamDialTimeoutMs == 0 {
			upstreamDialTimeoutMs = protocol.LatencyUpstreamDialTimeoutMs
		}
	case "throughput":
		if coalesceWindowMs == 0 {
			coalesceWindowMs = protocol.ThroughputCoalesceWindowMs
		}
		if coalesceWindowBusyMs == 0 {
			coalesceWindowBusyMs = protocol.ThroughputCoalesceWindowBusyMs
		}
	}
	if activeDrainWindowMs == 0 {
		activeDrainWindowMs = protocol.DefaultActiveDrainWindowMs
	}
	if longPollWindowMs == 0 {
		longPollWindowMs = protocol.DefaultLongPollWindowMs
	}
	if upstreamDialTimeoutMs == 0 {
		upstreamDialTimeoutMs = protocol.DefaultUpstreamDialTimeoutMs
	}
	if performanceMode != "latency" {
		if coalesceWindowMs == 0 {
			coalesceWindowMs = protocol.DefaultCoalesceWindowMs
		}
		if coalesceWindowBusyMs == 0 {
			coalesceWindowBusyMs = protocol.DefaultCoalesceWindowBusyMs
		}
	}
	if maxResponseBytesPreEncode == 0 {
		maxResponseBytesPreEncode = protocol.MaxResponseBytesPreEncode
	}
	if maxRequestBodyBytes == 0 {
		maxRequestBodyBytes = protocol.MaxRequestBodyBytes
	}
	if maxSessions == 0 {
		maxSessions = protocol.DefaultMaxServerSessions
	}
	if activeDrainWindowMs < 1 || longPollWindowMs < 1 || upstreamDialTimeoutMs < 1 || coalesceWindowMs < 0 || coalesceWindowBusyMs < 0 {
		return nil, fmt.Errorf("performance timing values must be positive durations, except coalesce windows may be 0 in %s", path)
	}
	if maxResponseBytesPreEncode < protocol.MaxFramePayload {
		return nil, fmt.Errorf("max_response_bytes_pre_encode must be at least %d in %s", protocol.MaxFramePayload, path)
	}
	if maxRequestBodyBytes < protocol.MaxFramePayload {
		return nil, fmt.Errorf("max_request_body_bytes must be at least %d in %s", protocol.MaxFramePayload, path)
	}
	if maxSessions < 1 {
		return nil, fmt.Errorf("max_sessions must be at least 1 in %s", path)
	}

	c := Server{
		ListenAddr:                net.JoinHostPort(listenHost, strconv.Itoa(listenPort)),
		AESKeyHex:                 key,
		DebugTiming:               f.DebugTiming,
		AutoTune:                  f.AutoTune,
		UpstreamProxy:             upstreamProxy,
		PerformanceMode:           performanceMode,
		ActiveDrainWindowMs:       activeDrainWindowMs,
		LongPollWindowMs:          longPollWindowMs,
		UpstreamDialTimeoutMs:     upstreamDialTimeoutMs,
		CoalesceWindowMs:          coalesceWindowMs,
		CoalesceWindowBusyMs:      coalesceWindowBusyMs,
		MaxSessions:               maxSessions,
		MaxRequestBodyBytes:       maxRequestBodyBytes,
		MaxResponseBytesPreEncode: maxResponseBytesPreEncode,
	}
	return &c, nil
}
