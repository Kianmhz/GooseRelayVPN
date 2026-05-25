// Package config defines the JSON config structures for the client and server
// binaries.
package config

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/kianmhz/GooseRelayVPN/internal/protocol"
)

// Client is the relay-tunnel client config.
type Client struct {
	ListenAddr              string
	GoogleIP                string   // "ip:port"; empty when direct relay_urls mode is used
	SNIHosts                []string // one or more TLS SNI names; empty when direct relay_urls mode is used
	FrontingHTTPVersion     string
	ScriptURLs              []string // one or more relay endpoints (Apps Script URLs or direct relay_urls)
	DirectStreamURLs        []string
	UseFronting             bool
	AESKeyHex               string // 64-char hex
	DebugTiming             bool   // when true, log per-session TTFB and per-poll Apps Script RTT
	StatsJSON               bool
	DebugPprofAddr          string
	WriteStartupDiagnostics bool
	DiagnosticsOutputDir    string
	SaveTerminalLog         bool
	TerminalLogFile         string
	AutoTune                bool
	SocksUser               string // optional SOCKS5 username (RFC 1929); empty = no auth
	SocksPass               string // optional SOCKS5 password (RFC 1929); empty = no auth
	MaxLocalSessions        int
	PerformanceMode         string
	TransportMode           string
	IdlePollMode            string
	DownstreamReplayMode    string
	FreshStartReset         bool
	ClientInstanceID        string
	ClientInstanceIDFile    string
	QuotaStatePath          string

	// ScriptAccounts is an optional parallel slice to ScriptURLs. When the user
	// labels deployments with an `account` field in script_keys, the carrier
	// uses these labels to aggregate per-account totals in the stats line so
	// the user can see how much of each Google account's ~20k/day quota has
	// been spent. Index i in this slice is the account label for ScriptURLs[i];
	// empty string = unlabeled. Always the same length as ScriptURLs.
	ScriptAccounts []string

	// Adaptive uplink coalescing. When CoalesceStepMs > 0, the carrier waits
	// up to that many ms for more TX ops to arrive before sending, resetting
	// the timer on each new op. Bursts collapse into a single poll. Off by
	// default (=0). The hard cap (~step × 25) is internal.
	CoalesceStepMs int
	CoalesceMaxMs  int

	// IdleSlotsPerBucket controls how many concurrent idle long-polls the
	// carrier maintains per account bucket. Default 1 (matches the bucket
	// model's safe baseline). Raising to 2–3 increases download throughput
	// when an account has multiple deployments, at the cost of more
	// simultaneous executions on that account. 0 = use default.
	IdleSlotsPerBucket       int
	IdlePollMaxBuckets       int
	TxSlotsPerBucket         int
	WorkersPerEndpoint       int
	PollIdleSleepMs          int
	PollTimeoutMs            int
	EndpointBlacklistBaseMs  int
	EndpointBlacklistMaxMs   int
	EndpointOutageGraceMs    int
	MaxRequestBytesPreEncode int
	TxBufferBudgetBytes      int
	StreamConnectTimeoutMs   int
	StreamPingIntervalMs     int
	StreamReconnectBackoffMs int
	UnknownFields            []string
}

// clientFile is the user-friendly client config format.
type clientFile struct {
	// Local SOCKS listener.
	SocksHost string `json:"socks_host"`
	SocksPort int    `json:"socks_port"`

	// Google front endpoint.
	GoogleHost string `json:"google_host"`

	// TLS SNI: accepts a single string ("www.google.com") or an array of
	// strings (["www.google.com", "mail.google.com", "accounts.google.com"]).
	// Multiple SNI hosts are round-robined per request. They use separate TLS
	// sessions and can help on networks that treat Google front names
	// differently, but Google does not document per-SNI throttle buckets.
	SNI json.RawMessage `json:"sni"`

	// Apps Script Deployment IDs (one or more). Each entry may be either:
	//   - a plain string (the Deployment ID), or
	//   - an object {"id": "...", "account": "..."} where account is an
	//     optional human-readable label used to group deployments belonging
	//     to the same Google account in the [stats] line. Mixing the two
	//     forms is allowed.
	ScriptKeys json.RawMessage `json:"script_keys"`

	// Optional direct relay endpoints for local/integration testing.
	// When set, these URLs are used as-is and Google fronting is disabled.
	RelayURLs []string `json:"relay_urls"`

	// Optional first-class direct streaming endpoints. Values may be ws://,
	// wss://, http://, or https://. HTTP(S) values are normalized to WS(S);
	// bare server or /tunnel paths are normalized to /stream.
	DirectStreamURLs []string `json:"direct_stream_urls"`

	// Shared AES key (64-char hex).
	TunnelKey string `json:"tunnel_key"`

	// Optional: when true, log per-session time-to-first-byte and per-poll
	// Apps Script round-trip latency to help pinpoint where a slow connection
	// is spending its time. Off by default.
	DebugTiming             bool   `json:"debug_timing"`
	StatsJSON               bool   `json:"stats_json"`
	DebugPprofAddr          string `json:"debug_pprof_addr"`
	WriteStartupDiagnostics bool   `json:"write_startup_diagnostics"`
	DiagnosticsOutputDir    string `json:"diagnostics_output_dir"`
	SaveTerminalLog         bool   `json:"save_terminal_log"`
	TerminalLogFile         string `json:"terminal_log_file"`
	AutoTune                bool   `json:"auto_tune"`

	// Optional SOCKS5 RFC 1929 credentials. When set, clients must supply
	// these credentials or the connection is rejected. Both must be non-empty
	// together — setting only one is an error.
	SocksUser string `json:"socks_user"`
	SocksPass string `json:"socks_pass"`
	// Optional local SOCKS session cap. 0 = unlimited. Set a positive value to
	// stop browser/app connection storms before they create tunnel state.
	MaxLocalSessions int `json:"max_local_sessions"`

	// Optional adaptive uplink coalescing. Both 0 = disabled (default).
	// coalesce_step_ms: wait time for a burst of TX operation(s). Each new
	// operation resets the timer. Set it to 0 to disable coalescing. The
	// internal safety cap is derived from this value and is not user-configurable.
	CoalesceStepMs int `json:"coalesce_step_ms"`

	// Optional download-throughput tuning. Concurrent idle long-polls per
	// account bucket. Default 1 (safe). Set to 2 to roughly double download
	// throughput when each account has 2+ deployments. Higher than 3 is
	// rejected — past that the per-account concurrency cap that issue #56
	// surfaced becomes reachable again.
	IdleSlotsPerBucket int `json:"idle_slots_per_bucket"`
	IdlePollMaxBuckets int `json:"idle_poll_max_buckets"`
	TxSlotsPerBucket   int `json:"tx_slots_per_bucket"`

	PerformanceMode          string  `json:"performance_mode"`
	TransportMode            string  `json:"transport_mode"`
	FrontingHTTPVersion      string  `json:"fronting_http_version"`
	IdlePollMode             string  `json:"idle_poll_mode"`
	DownstreamReplayMode     string  `json:"downstream_replay_mode"`
	FreshStartReset          *bool   `json:"fresh_start_reset"`
	ClientInstanceID         string  `json:"client_instance_id"`
	ClientInstanceIDFile     string  `json:"client_instance_id_file"`
	QuotaStatePath           *string `json:"quota_state_path"`
	WorkersPerEndpoint       int     `json:"workers_per_endpoint"`
	PollIdleSleepMs          int     `json:"poll_idle_sleep_ms"`
	PollTimeoutMs            int     `json:"poll_timeout_ms"`
	EndpointBlacklistBaseMs  int     `json:"endpoint_blacklist_base_ms"`
	EndpointBlacklistMaxMs   int     `json:"endpoint_blacklist_max_ms"`
	EndpointOutageGraceMs    int     `json:"endpoint_outage_grace_ms"`
	MaxRequestBytesPreEncode int     `json:"max_request_bytes_pre_encode"`
	TxBufferBudgetBytes      int     `json:"tx_buffer_budget_bytes"`
	StreamConnectTimeoutMs   int     `json:"stream_connect_timeout_ms"`
	StreamPingIntervalMs     int     `json:"stream_ping_interval_ms"`
	StreamReconnectBackoffMs int     `json:"stream_reconnect_backoff_ms"`
}

var defaultSNIHosts = []string{"www.google.com", "mail.google.com", "accounts.google.com"}

func normalizePerformanceMode(mode string) (string, error) {
	mode = strings.TrimSpace(strings.ToLower(mode))
	if mode == "" {
		return "latency", nil
	}
	switch mode {
	case "balanced", "latency", "throughput":
		return mode, nil
	default:
		return "", fmt.Errorf("performance_mode must be one of balanced, latency, throughput (got %q)", mode)
	}
}

func normalizeTransportMode(mode string) (string, error) {
	mode = strings.TrimSpace(strings.ToLower(mode))
	if mode == "" {
		return "apps_script", nil
	}
	switch mode {
	case "auto", "apps_script", "direct_post", "direct_stream":
		return mode, nil
	default:
		return "", fmt.Errorf("transport_mode must be one of auto, apps_script, direct_post, direct_stream (got %q)", mode)
	}
}

func normalizeFrontingHTTPVersion(mode string) (string, error) {
	mode = strings.TrimSpace(strings.ToLower(mode))
	if mode == "" {
		return "auto", nil
	}
	switch mode {
	case "auto", "h1", "h2":
		return mode, nil
	default:
		return "", fmt.Errorf("fronting_http_version must be one of auto, h1, h2 (got %q)", mode)
	}
}

func normalizeIdlePollMode(mode string) (string, error) {
	mode = strings.TrimSpace(strings.ToLower(mode))
	if mode == "" {
		return "always", nil
	}
	switch mode {
	case "always", "adaptive", "off":
		return mode, nil
	default:
		return "", fmt.Errorf("idle_poll_mode must be one of always, adaptive, off (got %q)", mode)
	}
}

func normalizeDownstreamReplayMode(mode string) (string, error) {
	mode = strings.TrimSpace(strings.ToLower(mode))
	if mode == "" {
		return "auto", nil
	}
	switch mode {
	case "off", "auto":
		return mode, nil
	default:
		return "", fmt.Errorf("downstream_replay_mode must be one of off, auto (got %q)", mode)
	}
}

func validateClientInstanceID(id string) error {
	id = strings.TrimSpace(id)
	if id == "" {
		return nil
	}
	if len(id) > 128 {
		return fmt.Errorf("client_instance_id must be 128 characters or fewer")
	}
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '-' || r == '_' || r == '.' || r == ':':
		default:
			return fmt.Errorf("client_instance_id may contain only letters, numbers, dash, underscore, dot, and colon")
		}
	}
	return nil
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v != "" {
			return v
		}
	}
	return ""
}

func firstPositive(values ...int) int {
	for _, v := range values {
		if v > 0 {
			return v
		}
	}
	return 0
}

func normalizeGoogleHost(raw string) (string, error) {
	host := firstNonEmpty(raw, "216.239.38.120")
	if strings.Contains(host, "://") || strings.ContainsAny(host, "/\\?#") {
		return "", fmt.Errorf("google_host must be a bare host or IP without scheme, port, or path (got %q)", raw)
	}
	if h, p, err := net.SplitHostPort(host); err == nil && h != "" && p != "" {
		return "", fmt.Errorf("google_host must not include a port; set only the host/IP because port 443 is fixed (got %q)", raw)
	}
	if strings.Contains(host, ":") && net.ParseIP(host) == nil {
		return "", fmt.Errorf("google_host must be a bare host or IP without a port (got %q)", raw)
	}
	return host, nil
}

func normalizeDeploymentID(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	// Accept plain deployment key and tolerate pasting the full /exec URL.
	v = strings.TrimSuffix(v, "/exec")
	v = strings.Trim(v, "/")
	parts := strings.Split(v, "/")
	if len(parts) >= 2 {
		for i := 0; i < len(parts)-1; i++ {
			if parts[i] == "s" {
				return parts[i+1]
			}
		}
	}
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return v
}

func buildScriptURL(deploymentID string) string {
	return fmt.Sprintf("https://script.google.com/macros/s/%s/exec", deploymentID)
}

func dedupeStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

func normalizeRelayURL(v string) (string, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return "", nil
	}
	u, err := url.Parse(v)
	if err != nil {
		return "", fmt.Errorf("invalid relay_urls value: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("invalid relay_urls value: scheme must be http or https")
	}
	if strings.TrimSpace(u.Host) == "" {
		return "", fmt.Errorf("invalid relay_urls value: host is required")
	}
	return u.String(), nil
}

func normalizeDirectStreamURL(v string) (string, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return "", nil
	}
	u, err := url.Parse(v)
	if err != nil {
		return "", fmt.Errorf("invalid direct_stream_urls value: %w", err)
	}
	switch u.Scheme {
	case "ws", "wss":
	case "http":
		u.Scheme = "ws"
	case "https":
		u.Scheme = "wss"
	default:
		return "", fmt.Errorf("invalid direct_stream_urls value: scheme must be ws, wss, http, or https")
	}
	if strings.TrimSpace(u.Host) == "" {
		return "", fmt.Errorf("invalid direct_stream_urls value: host is required")
	}
	if u.Path == "" || u.Path == "/" || u.Path == "/tunnel" {
		u.Path = "/stream"
	}
	return u.String(), nil
}

// scriptKeyEntry is the parsed result of one script_keys array element. The
// JSON form is either a plain string (legacy / unlabeled) or an object with
// id+account fields. Account is "" when unlabeled.
type scriptKeyEntry struct {
	ID      string `json:"id"`
	Account string `json:"account"`
}

// parseScriptKeys turns the script_keys JSON value into a slice of entries.
// Returns a usage-friendly error when a particular element is malformed so
// the user can fix the right index without parsing line numbers.
func parseScriptKeys(raw json.RawMessage) ([]scriptKeyEntry, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var arr []json.RawMessage
	if err := json.Unmarshal(raw, &arr); err != nil {
		return nil, fmt.Errorf("script_keys must be a JSON array (a list of strings or {id, account} objects)")
	}
	out := make([]scriptKeyEntry, 0, len(arr))
	for i, item := range arr {
		// Try the bare-string form first (preserves the existing config shape).
		var s string
		if err := json.Unmarshal(item, &s); err == nil {
			out = append(out, scriptKeyEntry{ID: s})
			continue
		}
		var obj scriptKeyEntry
		dec := json.NewDecoder(bytes.NewReader(item))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&obj); err != nil {
			return nil, fmt.Errorf("script_keys[%d] must be a Deployment ID string or an object {\"id\": \"...\", \"account\": \"...\"}", i)
		}
		if strings.TrimSpace(obj.ID) == "" {
			return nil, fmt.Errorf("script_keys[%d] is an object without an \"id\" field - provide the Deployment ID there", i)
		}
		out = append(out, obj)
	}
	return out, nil
}

// validateDeploymentID checks that the value looks like an Apps Script
// deployment ID and produces a hint when it looks like a common copy-paste
// mistake. The exact format Google uses isn't documented, but every observed
// ID starts with "AKfycb" and is 50+ characters long.
func validateDeploymentID(id string) error {
	if id == "" {
		return errors.New("empty value in script_keys")
	}
	if id == "REPLACE_WITH_DEPLOYMENT_ID" || id == "OPTIONAL_SECOND_DEPLOYMENT_ID" {
		return errors.New("script_keys still contains the placeholder text from client_config.example.json - replace it with your real Deployment ID (see README Step 5)")
	}
	if strings.Contains(id, "/edit") || strings.Contains(id, "script.google.com/d/") {
		return errors.New("this looks like the Apps Script *editor* URL, not a Deployment ID. Open the deployment from Deploy -> Manage deployments, click the deployed Web App URL, and copy the long string between /s/ and /exec")
	}
	if strings.ContainsAny(id, " \t\n\r") {
		return errors.New("script_keys value contains whitespace - paste the Deployment ID without spaces or line breaks")
	}
	if !strings.HasPrefix(id, "AKfycb") {
		return errors.New("deployment IDs start with 'AKfycb' - you may have pasted the script ID (from the editor) instead of the Deployment ID. After deploying, open Deploy -> Manage deployments and copy the ID from the Web App URL")
	}
	if len(id) < 50 {
		return fmt.Errorf("deployment ID looks too short (%d chars; expected ~70) - it may be truncated, re-copy from Deploy -> Manage deployments", len(id))
	}
	return nil
}

// parseSNIHosts parses the "sni" JSON field, which may be either a single
// string ("www.google.com") or an array (["www.google.com", "mail.google.com"]).
// Falls back to multiple Google SNI hosts when the field is absent, null, or
// empty. Malformed non-empty shapes fail loudly so typos do not silently use
// the default fronting hosts.
// Each host gets its own fronted HTTP transport and connection pool, spreading
// requests across several Google front names by default.
func parseSNIHosts(raw json.RawMessage) ([]string, error) {
	defaults := func() []string { return append([]string(nil), defaultSNIHosts...) }
	if len(raw) == 0 || strings.TrimSpace(string(raw)) == "null" {
		return defaults(), nil
	}
	// Try string first (backward-compatible single-SNI config).
	var single string
	if err := json.Unmarshal(raw, &single); err == nil {
		single = strings.TrimSpace(single)
		if single == "" {
			return defaults(), nil
		}
		return []string{single}, nil
	}
	// Try array.
	var multi []string
	if err := json.Unmarshal(raw, &multi); err != nil {
		return nil, fmt.Errorf("sni must be a string or an array of strings")
	}
	out := make([]string, 0, len(multi))
	for _, h := range multi {
		h = strings.TrimSpace(h)
		if h != "" {
			out = append(out, h)
		}
	}
	if len(out) == 0 {
		return defaults(), nil
	}
	return out, nil
}

// LoadClient reads and validates a client config file.
func LoadClient(path string) (*Client, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("config file %q not found.\n  Fix: copy the example and edit it:\n      cp client_config.example.json %s", path, path)
		}
		return nil, fmt.Errorf("cannot read config %q: %w", path, err)
	}
	b = stripUTF8BOM(b)

	var f clientFile
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("config %q is not valid JSON: %v\n  Common causes: missing comma between fields, trailing comma after the last field, unclosed quote, or a typo in a field name", path, err)
	}
	unknownFields, err := unknownJSONFields(b, clientFile{})
	if err != nil {
		return nil, fmt.Errorf("config %q is not valid JSON: %v", path, err)
	}

	listenHost := firstNonEmpty(f.SocksHost, "127.0.0.1")
	listenPort := firstPositive(f.SocksPort)
	if listenPort == 0 {
		listenPort = 1080
	}
	if listenPort < 1 || listenPort > 65535 {
		return nil, fmt.Errorf("socks_port %d is out of range (must be 1-65535)", listenPort)
	}

	relayURLs := make([]string, 0, len(f.RelayURLs))
	for _, raw := range f.RelayURLs {
		normalized, nerr := normalizeRelayURL(raw)
		if nerr != nil {
			return nil, nerr
		}
		if normalized != "" {
			relayURLs = append(relayURLs, normalized)
		}
	}
	relayURLs = dedupeStrings(relayURLs)

	directStreamURLs := make([]string, 0, len(f.DirectStreamURLs))
	for _, raw := range f.DirectStreamURLs {
		normalized, nerr := normalizeDirectStreamURL(raw)
		if nerr != nil {
			return nil, nerr
		}
		if normalized != "" {
			directStreamURLs = append(directStreamURLs, normalized)
		}
	}
	directStreamURLs = dedupeStrings(directStreamURLs)

	key := strings.TrimSpace(f.TunnelKey)
	if key == "" || key == "REPLACE_WITH_OUTPUT_OF_scripts_gen-key.sh" || key == "REPLACE_WITH_64_HEX_CHARACTER_RANDOM_KEY" {
		return nil, fmt.Errorf("tunnel_key is empty or still the placeholder text in %s.\n  Fix: run `openssl rand -hex 32`, paste the 64-character output into tunnel_key, and use the same value in server_config.json", path)
	}
	if len(key) != 64 {
		return nil, fmt.Errorf("tunnel_key must be exactly 64 hex characters (got %d) in %s.\n  Fix: run `openssl rand -hex 32`, paste the full 64-character value, and use the SAME value in client_config.json and server_config.json", len(key), path)
	}
	raw, err := hex.DecodeString(key)
	if err != nil || len(raw) != 32 {
		return nil, fmt.Errorf("tunnel_key in %s contains non-hex characters.\n  Valid characters are 0-9 and a-f. Run `openssl rand -hex 32` and copy it carefully - no spaces, quotes, or extra newlines", path)
	}

	transportMode, err := normalizeTransportMode(f.TransportMode)
	if err != nil {
		return nil, err
	}
	frontingHTTPVersion, err := normalizeFrontingHTTPVersion(f.FrontingHTTPVersion)
	if err != nil {
		return nil, err
	}

	useFronting := false
	scriptURLs := relayURLs
	scriptAccounts := make([]string, len(relayURLs)) // direct relay_urls have no account labels
	googleIP := ""
	var sniHosts []string

	allowAppsScript := transportMode == "auto" || transportMode == "apps_script"
	allowDirectPost := transportMode == "auto" || transportMode == "direct_post"
	allowDirectStream := transportMode == "auto" || transportMode == "direct_stream"

	switch {
	case transportMode == "direct_stream" && len(directStreamURLs) == 0:
		return nil, fmt.Errorf("transport_mode direct_stream requires at least one direct_stream_urls entry in %s", path)
	case transportMode == "direct_post" && len(relayURLs) == 0:
		return nil, fmt.Errorf("transport_mode direct_post requires at least one relay_urls entry in %s", path)
	case !allowDirectStream && len(directStreamURLs) > 0:
		return nil, fmt.Errorf("direct_stream_urls can only be used with transport_mode auto or direct_stream in %s", path)
	case !allowDirectPost && len(relayURLs) > 0:
		return nil, fmt.Errorf("relay_urls can only be used with transport_mode auto or direct_post in %s", path)
	case transportMode == "apps_script" && len(f.ScriptKeys) == 0:
		return nil, fmt.Errorf("transport_mode apps_script requires script_keys in %s", path)
	}

	if len(relayURLs) > 0 {
		useFronting = false
	} else if allowAppsScript && len(f.ScriptKeys) > 0 {
		useFronting = true
	} else {
		useFronting = false
		scriptURLs = nil
		scriptAccounts = nil
	}

	if useFronting {
		googleHost, err := normalizeGoogleHost(f.GoogleHost)
		if err != nil {
			return nil, err
		}
		googlePort := 443
		googleIP = net.JoinHostPort(googleHost, strconv.Itoa(googlePort))
		sniHosts, err = parseSNIHosts(f.SNI)
		if err != nil {
			return nil, fmt.Errorf("invalid sni in %s: %w", path, err)
		}

		entries, err := parseScriptKeys(f.ScriptKeys)
		if err != nil {
			return nil, err
		}
		if len(entries) == 0 {
			return nil, fmt.Errorf("script_keys is empty in %s.\n  Fix: deploy apps_script/Code.gs as a Web App with Access: Anyone, then paste the Deployment ID into the script_keys array. See README Step 5", path)
		}

		// Dedupe by Deployment ID, keeping the first occurrence's account label.
		seen := make(map[string]struct{}, len(entries))
		deploymentIDs := make([]string, 0, len(entries))
		accounts := make([]string, 0, len(entries))
		for i, entry := range entries {
			deploymentID := normalizeDeploymentID(entry.ID)
			if err := validateDeploymentID(deploymentID); err != nil {
				return nil, fmt.Errorf("script_keys[%d] is invalid: %v", i, err)
			}
			if _, dup := seen[deploymentID]; dup {
				continue
			}
			seen[deploymentID] = struct{}{}
			deploymentIDs = append(deploymentIDs, deploymentID)
			accounts = append(accounts, strings.TrimSpace(entry.Account))
		}

		scriptURLs = make([]string, 0, len(deploymentIDs))
		for _, deploymentID := range deploymentIDs {
			scriptURLs = append(scriptURLs, buildScriptURL(deploymentID))
		}
		scriptAccounts = accounts
	}
	if len(scriptURLs) == 0 && len(directStreamURLs) == 0 {
		return nil, fmt.Errorf("no relay transport configured in %s: set direct_stream_urls, relay_urls, or script_keys", path)
	}

	socksUser := strings.TrimSpace(f.SocksUser)
	socksPass := strings.TrimSpace(f.SocksPass)
	if (socksUser == "") != (socksPass == "") {
		return nil, fmt.Errorf("socks_user and socks_pass must both be set or both be empty in %s", path)
	}
	if f.MaxLocalSessions < 0 {
		return nil, fmt.Errorf("max_local_sessions must be >= 0 in %s (got %d)", path, f.MaxLocalSessions)
	}

	if f.CoalesceStepMs < 0 {
		return nil, fmt.Errorf("coalesce_step_ms must be >= 0 in %s (got %d)", path, f.CoalesceStepMs)
	}
	performanceMode, err := normalizePerformanceMode(f.PerformanceMode)
	if err != nil {
		return nil, err
	}
	idlePollMode, err := normalizeIdlePollMode(f.IdlePollMode)
	if err != nil {
		return nil, err
	}
	downstreamReplayMode, err := normalizeDownstreamReplayMode(f.DownstreamReplayMode)
	if err != nil {
		return nil, err
	}
	freshStartReset := true
	if f.FreshStartReset != nil {
		freshStartReset = *f.FreshStartReset
	}
	clientInstanceID := strings.TrimSpace(f.ClientInstanceID)
	if err := validateClientInstanceID(clientInstanceID); err != nil {
		return nil, fmt.Errorf("%s in %s", err, path)
	}
	clientInstanceIDFile := strings.TrimSpace(f.ClientInstanceIDFile)
	quotaStatePath := filepath.Join(filepath.Dir(path), ".goose-quota-state.json")
	if f.QuotaStatePath != nil {
		quotaStatePath = strings.TrimSpace(*f.QuotaStatePath)
		if quotaStatePath != "" && !filepath.IsAbs(quotaStatePath) {
			quotaStatePath = filepath.Join(filepath.Dir(path), quotaStatePath)
		}
	}
	coalesceStep := f.CoalesceStepMs
	idleSlotsPerBucket := f.IdleSlotsPerBucket
	idlePollMaxBuckets := f.IdlePollMaxBuckets
	txSlotsPerBucket := f.TxSlotsPerBucket
	pollIdleSleepMs := f.PollIdleSleepMs
	pollTimeoutMs := f.PollTimeoutMs
	workersPerEndpoint := f.WorkersPerEndpoint
	blacklistBaseMs := f.EndpointBlacklistBaseMs
	blacklistMaxMs := f.EndpointBlacklistMaxMs
	outageGraceMs := f.EndpointOutageGraceMs
	maxRequestBytesPreEncode := f.MaxRequestBytesPreEncode
	txBufferBudgetBytes := f.TxBufferBudgetBytes
	streamConnectTimeoutMs := f.StreamConnectTimeoutMs
	streamPingIntervalMs := f.StreamPingIntervalMs
	streamReconnectBackoffMs := f.StreamReconnectBackoffMs
	switch performanceMode {
	case "latency":
		if pollIdleSleepMs == 0 {
			pollIdleSleepMs = protocol.LatencyPollIdleSleepMs
		}
	case "throughput":
		if coalesceStep == 0 {
			coalesceStep = protocol.ThroughputCoalesceStepMs
		}
		if idleSlotsPerBucket == 0 {
			idleSlotsPerBucket = protocol.ThroughputIdleSlotsPerBucket
		}
	}
	if pollIdleSleepMs == 0 {
		pollIdleSleepMs = protocol.DefaultPollIdleSleepMs
	}
	if pollTimeoutMs == 0 {
		pollTimeoutMs = protocol.DefaultPollTimeoutMs
	}
	if workersPerEndpoint == 0 {
		workersPerEndpoint = protocol.DefaultWorkersPerEndpoint
	}
	if txSlotsPerBucket == 0 {
		txSlotsPerBucket = protocol.DefaultWorkersPerEndpoint
	}
	if idleSlotsPerBucket == 0 {
		idleSlotsPerBucket = 1
	}
	if idlePollMaxBuckets == 0 {
		idlePollMaxBuckets = protocol.DefaultIdlePollMaxBuckets
	}
	if blacklistBaseMs == 0 {
		blacklistBaseMs = protocol.DefaultEndpointBlacklistBaseMs
	}
	if blacklistMaxMs == 0 {
		blacklistMaxMs = protocol.DefaultEndpointBlacklistMaxMs
	}
	if outageGraceMs == 0 {
		outageGraceMs = protocol.DefaultEndpointOutageGraceMs
	}
	if maxRequestBytesPreEncode == 0 {
		maxRequestBytesPreEncode = protocol.MaxRequestBytesPreEncode
	}
	if txBufferBudgetBytes == 0 {
		txBufferBudgetBytes = protocol.DefaultTxBufferBudgetBytes
	}
	if streamConnectTimeoutMs == 0 {
		streamConnectTimeoutMs = protocol.DefaultStreamConnectTimeoutMs
	}
	if streamPingIntervalMs == 0 {
		streamPingIntervalMs = protocol.DefaultStreamPingIntervalMs
	}
	if streamReconnectBackoffMs == 0 {
		streamReconnectBackoffMs = protocol.DefaultStreamReconnectBackoffMs
	}
	if pollIdleSleepMs < 1 {
		return nil, fmt.Errorf("poll_idle_sleep_ms must be >= 1 in %s (got %d)", path, pollIdleSleepMs)
	}
	if pollTimeoutMs < 1 {
		return nil, fmt.Errorf("poll_timeout_ms must be >= 1 in %s (got %d)", path, pollTimeoutMs)
	}
	if workersPerEndpoint < 1 {
		return nil, fmt.Errorf("workers_per_endpoint must be >= 1 in %s (got %d)", path, workersPerEndpoint)
	}
	if blacklistBaseMs < 1 || blacklistMaxMs < blacklistBaseMs {
		return nil, fmt.Errorf("endpoint blacklist TTLs must satisfy 1 <= base <= max in %s", path)
	}
	if outageGraceMs < 1 {
		return nil, fmt.Errorf("endpoint_outage_grace_ms must be >= 1 in %s (got %d)", path, outageGraceMs)
	}
	if maxRequestBytesPreEncode < protocol.MaxFramePayload {
		return nil, fmt.Errorf("max_request_bytes_pre_encode must be at least %d in %s", protocol.MaxFramePayload, path)
	}
	if maxRequestBytesPreEncode > protocol.MaxRequestBytesPreEncode {
		return nil, fmt.Errorf("max_request_bytes_pre_encode must be at most %d in %s", protocol.MaxRequestBytesPreEncode, path)
	}
	if txBufferBudgetBytes < protocol.MaxFramePayload {
		return nil, fmt.Errorf("tx_buffer_budget_bytes must be at least %d in %s", protocol.MaxFramePayload, path)
	}
	if streamConnectTimeoutMs < 1 || streamPingIntervalMs < 1 || streamReconnectBackoffMs < 1 {
		return nil, fmt.Errorf("stream timeout values must be positive in %s", path)
	}
	if idleSlotsPerBucket < 0 || idleSlotsPerBucket > 3 {
		return nil, fmt.Errorf("idle_slots_per_bucket must be 0-3 in %s (got %d)", path, idleSlotsPerBucket)
	}
	if idlePollMaxBuckets < 1 || idlePollMaxBuckets > protocol.DefaultIdlePollMaxBuckets {
		return nil, fmt.Errorf("idle_poll_max_buckets must be 1-%d in %s (got %d)", protocol.DefaultIdlePollMaxBuckets, path, idlePollMaxBuckets)
	}
	if txSlotsPerBucket < 1 || txSlotsPerBucket > 8 {
		return nil, fmt.Errorf("tx_slots_per_bucket must be 1-8 in %s (got %d). Use 1-2 for fragile Apps Script accounts, 3 for the default speed profile, and 4-8 only after field testing the account can sustain it", path, txSlotsPerBucket)
	}
	coalesceMax := 0
	if coalesceStep > 0 {
		coalesceMax = coalesceStep * 25
	}

	if f.IdleSlotsPerBucket < 0 || f.IdleSlotsPerBucket > 3 {
		return nil, fmt.Errorf("idle_slots_per_bucket must be 0–3 in %s (got %d). 0 or unset = default (1, safest); 2–3 increases download throughput at the cost of more simultaneous executions per Google account, which can re-trigger issue #56 if your accounts can't sustain that concurrency", path, f.IdleSlotsPerBucket)
	}

	c := Client{
		ListenAddr:               net.JoinHostPort(listenHost, strconv.Itoa(listenPort)),
		GoogleIP:                 googleIP,
		SNIHosts:                 sniHosts,
		FrontingHTTPVersion:      frontingHTTPVersion,
		ScriptURLs:               scriptURLs,
		ScriptAccounts:           scriptAccounts,
		DirectStreamURLs:         directStreamURLs,
		UseFronting:              useFronting,
		AESKeyHex:                key,
		DebugTiming:              f.DebugTiming,
		StatsJSON:                f.StatsJSON,
		DebugPprofAddr:           strings.TrimSpace(f.DebugPprofAddr),
		WriteStartupDiagnostics:  f.WriteStartupDiagnostics,
		DiagnosticsOutputDir:     strings.TrimSpace(f.DiagnosticsOutputDir),
		SaveTerminalLog:          f.SaveTerminalLog,
		TerminalLogFile:          strings.TrimSpace(f.TerminalLogFile),
		AutoTune:                 f.AutoTune,
		SocksUser:                socksUser,
		SocksPass:                socksPass,
		MaxLocalSessions:         f.MaxLocalSessions,
		PerformanceMode:          performanceMode,
		TransportMode:            transportMode,
		IdlePollMode:             idlePollMode,
		DownstreamReplayMode:     downstreamReplayMode,
		FreshStartReset:          freshStartReset,
		ClientInstanceID:         clientInstanceID,
		ClientInstanceIDFile:     clientInstanceIDFile,
		QuotaStatePath:           quotaStatePath,
		CoalesceStepMs:           coalesceStep,
		CoalesceMaxMs:            coalesceMax,
		IdleSlotsPerBucket:       idleSlotsPerBucket,
		IdlePollMaxBuckets:       idlePollMaxBuckets,
		TxSlotsPerBucket:         txSlotsPerBucket,
		WorkersPerEndpoint:       workersPerEndpoint,
		PollIdleSleepMs:          pollIdleSleepMs,
		PollTimeoutMs:            pollTimeoutMs,
		EndpointBlacklistBaseMs:  blacklistBaseMs,
		EndpointBlacklistMaxMs:   blacklistMaxMs,
		EndpointOutageGraceMs:    outageGraceMs,
		MaxRequestBytesPreEncode: maxRequestBytesPreEncode,
		TxBufferBudgetBytes:      txBufferBudgetBytes,
		StreamConnectTimeoutMs:   streamConnectTimeoutMs,
		StreamPingIntervalMs:     streamPingIntervalMs,
		StreamReconnectBackoffMs: streamReconnectBackoffMs,
		UnknownFields:            unknownFields,
	}
	return &c, nil
}
