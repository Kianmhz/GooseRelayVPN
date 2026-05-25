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
	ListenAddr                    string
	AESKeyHex                     string
	DebugTiming                   bool
	StatsJSON                     bool
	DebugPprofAddr                string
	WriteStartupDiagnostics       bool
	DiagnosticsOutputDir          string
	SaveTerminalLog               bool
	TerminalLogFile               string
	AutoTune                      bool
	UpstreamProxy                 string // optional host:port; when set, all outbound dials go through this proxy
	UpstreamProxyUser             string
	UpstreamProxyPass             string
	PerformanceMode               string
	ActiveDrainWindowMs           int
	LongPollWindowMs              int
	UpstreamDialTimeoutMs         int
	CoalesceWindowMs              int
	CoalesceWindowBusyMs          int
	MaxSessions                   int
	MaxDrainFramesPerSession      int
	MaxRequestBodyBytes           int
	MaxResponseBytesPreEncode     int
	InitialResponseBytesPreEncode int
	SecondResponseBytesPreEncode  int
	InitialResponseCapEnabled     bool
	SecondResponseCapEnabled      bool
	DownstreamReplayEnabled       bool
	UnknownFields                 []string
}

type serverFile struct {
	// New user-friendly keys.
	ServerHost string `json:"server_host"`
	ServerPort int    `json:"server_port"`
	TunnelKey  string `json:"tunnel_key"`

	// Optional: when true, log per-session dial breakdown (DNS, TCP, first
	// upstream read) so an operator can pinpoint where latency is going.
	DebugTiming             bool   `json:"debug_timing"`
	StatsJSON               bool   `json:"stats_json"`
	DebugPprofAddr          string `json:"debug_pprof_addr"`
	WriteStartupDiagnostics bool   `json:"write_startup_diagnostics"`
	DiagnosticsOutputDir    string `json:"diagnostics_output_dir"`
	SaveTerminalLog         bool   `json:"save_terminal_log"`
	TerminalLogFile         string `json:"terminal_log_file"`
	AutoTune                bool   `json:"auto_tune"`

	// Optional: route all outbound connections through a local SOCKS5 proxy
	// (e.g. Cloudflare WARP on socks5://127.0.0.1:40000). Useful when the VPS
	// datacenter IP is blocked by certain sites.
	UpstreamProxy string `json:"upstream_proxy"`

	PerformanceMode               string `json:"performance_mode"`
	ActiveDrainWindowMs           int    `json:"active_drain_window_ms"`
	LongPollWindowMs              int    `json:"long_poll_window_ms"`
	UpstreamDialTimeoutMs         int    `json:"upstream_dial_timeout_ms"`
	CoalesceWindowMs              int    `json:"coalesce_window_ms"`
	CoalesceWindowBusyMs          int    `json:"coalesce_window_busy_ms"`
	MaxSessions                   int    `json:"max_sessions"`
	MaxDrainFramesPerSession      int    `json:"max_drain_frames_per_session"`
	MaxRequestBodyBytes           int    `json:"max_request_body_bytes"`
	MaxResponseBytesPreEncode     int    `json:"max_response_bytes_pre_encode"`
	InitialResponseCapEnabled     *bool  `json:"initial_response_cap_enabled"`
	InitialResponseBytesPreEncode int    `json:"initial_response_bytes_pre_encode"`
	SecondResponseCapEnabled      *bool  `json:"second_response_cap_enabled"`
	SecondResponseBytesPreEncode  int    `json:"second_response_bytes_pre_encode"`
	DownstreamReplayEnabled       bool   `json:"downstream_replay_enabled"`

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
	b = stripUTF8BOM(b)
	var f serverFile
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("config %q is not valid JSON: %v\n  Common causes: missing comma between fields, trailing comma after the last field, unclosed quote, or a typo in a field name", path, err)
	}
	unknownFields, err := unknownJSONFields(b, serverFile{})
	if err != nil {
		return nil, fmt.Errorf("config %q is not valid JSON: %v", path, err)
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
		return nil, fmt.Errorf("tunnel_key must be exactly 64 hex characters (got %d) in %s.\n  Fix: paste the SAME tunnel_key from client_config.json - both files must contain byte-identical values", len(key), path)
	}
	raw, err := hex.DecodeString(key)
	if err != nil || len(raw) != 32 {
		return nil, fmt.Errorf("tunnel_key in %s contains non-hex characters.\n  Valid characters are 0-9 and a-f. Copy the value from client_config.json carefully - no spaces, quotes, or extra newlines", path)
	}

	var upstreamProxy string
	var upstreamProxyUser string
	var upstreamProxyPass string
	if raw := strings.TrimSpace(f.UpstreamProxy); raw != "" {
		u, err := url.Parse(raw)
		if err != nil || u.Scheme != "socks5" {
			return nil, fmt.Errorf("upstream_proxy must be a socks5:// URL (e.g. socks5://127.0.0.1:40000)")
		}
		if u.Host == "" {
			return nil, fmt.Errorf("upstream_proxy is missing host:port (e.g. socks5://127.0.0.1:40000)")
		}
		_, portText, err := net.SplitHostPort(u.Host)
		if err != nil {
			return nil, fmt.Errorf("upstream_proxy must include a valid host:port (e.g. socks5://127.0.0.1:40000)")
		}
		port, err := strconv.Atoi(portText)
		if err != nil || port < 1 || port > 65535 {
			return nil, fmt.Errorf("upstream_proxy port must be between 1 and 65535")
		}
		if u.User != nil {
			user := u.User.Username()
			pass, hasPass := u.User.Password()
			if hasPass && user == "" {
				return nil, fmt.Errorf("upstream_proxy username is required when a password is provided")
			}
			if len(user) > 255 || len(pass) > 255 {
				return nil, fmt.Errorf("upstream_proxy username/password must be 255 bytes or shorter")
			}
			upstreamProxyUser = user
			upstreamProxyPass = pass
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
	maxDrainFramesPerSession := f.MaxDrainFramesPerSession
	maxRequestBodyBytes := f.MaxRequestBodyBytes
	maxResponseBytesPreEncode := f.MaxResponseBytesPreEncode
	initialResponseCapEnabled := true
	if f.InitialResponseCapEnabled != nil {
		initialResponseCapEnabled = *f.InitialResponseCapEnabled
	}
	initialResponseBytesPreEncode := f.InitialResponseBytesPreEncode
	secondResponseCapEnabled := true
	if f.SecondResponseCapEnabled != nil {
		secondResponseCapEnabled = *f.SecondResponseCapEnabled
	}
	secondResponseBytesPreEncode := f.SecondResponseBytesPreEncode
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
		maxResponseBytesPreEncode = protocol.DefaultMaxResponseBytesPreEncode
	}
	if initialResponseBytesPreEncode == 0 {
		initialResponseBytesPreEncode = protocol.InitialResponseBytesPreEncode
	}
	if secondResponseBytesPreEncode == 0 {
		secondResponseBytesPreEncode = protocol.SecondResponseBytesPreEncode
	}
	if maxRequestBodyBytes == 0 {
		maxRequestBodyBytes = protocol.MaxRequestBodyBytes
	}
	if maxSessions == 0 {
		maxSessions = protocol.DefaultMaxServerSessions
	}
	if maxDrainFramesPerSession == 0 {
		maxDrainFramesPerSession = protocol.DefaultMaxDrainFramesPerSession
	}
	if activeDrainWindowMs < 1 || longPollWindowMs < 1 || upstreamDialTimeoutMs < 1 || coalesceWindowMs < 0 || coalesceWindowBusyMs < 0 {
		return nil, fmt.Errorf("performance timing values must be positive durations, except coalesce windows may be 0 in %s", path)
	}
	if maxResponseBytesPreEncode < protocol.MaxFramePayload {
		return nil, fmt.Errorf("max_response_bytes_pre_encode must be at least %d in %s", protocol.MaxFramePayload, path)
	}
	if maxResponseBytesPreEncode > protocol.MaxResponseBytesPreEncode {
		return nil, fmt.Errorf("max_response_bytes_pre_encode must be at most %d in %s", protocol.MaxResponseBytesPreEncode, path)
	}
	if f.DownstreamReplayEnabled && maxResponseBytesPreEncode > protocol.DownstreamReplayPerSessionBytes {
		return nil, fmt.Errorf("max_response_bytes_pre_encode must be at most %d when downstream_replay_enabled is true in %s", protocol.DownstreamReplayPerSessionBytes, path)
	}
	if initialResponseCapEnabled && initialResponseBytesPreEncode < protocol.MaxFramePayload {
		return nil, fmt.Errorf("initial_response_bytes_pre_encode must be at least %d in %s", protocol.MaxFramePayload, path)
	}
	if initialResponseCapEnabled && initialResponseBytesPreEncode > maxResponseBytesPreEncode {
		initialResponseBytesPreEncode = maxResponseBytesPreEncode
	}
	if secondResponseCapEnabled && secondResponseBytesPreEncode < protocol.MaxFramePayload {
		return nil, fmt.Errorf("second_response_bytes_pre_encode must be at least %d in %s", protocol.MaxFramePayload, path)
	}
	if secondResponseCapEnabled && secondResponseBytesPreEncode > maxResponseBytesPreEncode {
		secondResponseBytesPreEncode = maxResponseBytesPreEncode
	}
	if maxRequestBodyBytes < protocol.MaxFramePayload {
		return nil, fmt.Errorf("max_request_body_bytes must be at least %d in %s", protocol.MaxFramePayload, path)
	}
	if maxRequestBodyBytes > protocol.MaxRequestBodyBytes {
		return nil, fmt.Errorf("max_request_body_bytes must be at most %d in %s", protocol.MaxRequestBodyBytes, path)
	}
	if maxSessions < 1 {
		return nil, fmt.Errorf("max_sessions must be at least 1 in %s", path)
	}
	if maxDrainFramesPerSession < 1 || maxDrainFramesPerSession > protocol.MaxDrainFramesPerSession {
		return nil, fmt.Errorf("max_drain_frames_per_session must be between 1 and %d in %s", protocol.MaxDrainFramesPerSession, path)
	}

	c := Server{
		ListenAddr:                    net.JoinHostPort(listenHost, strconv.Itoa(listenPort)),
		AESKeyHex:                     key,
		DebugTiming:                   f.DebugTiming,
		StatsJSON:                     f.StatsJSON,
		DebugPprofAddr:                strings.TrimSpace(f.DebugPprofAddr),
		WriteStartupDiagnostics:       f.WriteStartupDiagnostics,
		DiagnosticsOutputDir:          strings.TrimSpace(f.DiagnosticsOutputDir),
		SaveTerminalLog:               f.SaveTerminalLog,
		TerminalLogFile:               strings.TrimSpace(f.TerminalLogFile),
		AutoTune:                      f.AutoTune,
		UpstreamProxy:                 upstreamProxy,
		UpstreamProxyUser:             upstreamProxyUser,
		UpstreamProxyPass:             upstreamProxyPass,
		PerformanceMode:               performanceMode,
		ActiveDrainWindowMs:           activeDrainWindowMs,
		LongPollWindowMs:              longPollWindowMs,
		UpstreamDialTimeoutMs:         upstreamDialTimeoutMs,
		CoalesceWindowMs:              coalesceWindowMs,
		CoalesceWindowBusyMs:          coalesceWindowBusyMs,
		MaxSessions:                   maxSessions,
		MaxDrainFramesPerSession:      maxDrainFramesPerSession,
		MaxRequestBodyBytes:           maxRequestBodyBytes,
		MaxResponseBytesPreEncode:     maxResponseBytesPreEncode,
		InitialResponseBytesPreEncode: initialResponseBytesPreEncode,
		SecondResponseBytesPreEncode:  secondResponseBytesPreEncode,
		InitialResponseCapEnabled:     initialResponseCapEnabled,
		SecondResponseCapEnabled:      secondResponseCapEnabled,
		DownstreamReplayEnabled:       f.DownstreamReplayEnabled,
		UnknownFields:                 unknownFields,
	}
	return &c, nil
}
