// Package config defines the JSON config structures for the client and server
// binaries.
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

// Client is the relay-tunnel client config.
type Client struct {
	ListenAddr  string
	GoogleIP    string   // "ip:port"; empty when direct relay_urls mode is used
	SNIHosts    []string // one or more TLS SNI names; empty when direct relay_urls mode is used
	ScriptURLs  []string // one or more relay endpoints (Apps Script URLs or direct relay_urls)
	UseFronting bool
	AESKeyHex   string // 64-char hex
	DebugTiming bool   // when true, log per-session TTFB and per-poll Apps Script RTT
	SocksUser   string // optional SOCKS5 username (RFC 1929); empty = no auth
	SocksPass   string // optional SOCKS5 password (RFC 1929); empty = no auth

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
	IdleSlotsPerBucket int
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
	// Multiple SNI hosts are round-robined per request, each hitting a separate
	// throttle bucket on the Google CDN — useful in regions that rate-limit
	// per domain name.
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

	// Shared AES key (64-char hex).
	TunnelKey string `json:"tunnel_key"`

	// Optional: when true, log per-session time-to-first-byte and per-poll
	// Apps Script round-trip latency to help pinpoint where a slow connection
	// is spending its time. Off by default.
	DebugTiming bool `json:"debug_timing"`

	// Optional SOCKS5 RFC 1929 credentials. When set, clients must supply
	// these credentials or the connection is rejected. Both must be non-empty
	// together — setting only one is an error.
	SocksUser string `json:"socks_user"`
	SocksPass string `json:"socks_pass"`

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
		return "", fmt.Errorf("invalid relay_urls value %q: %w", v, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("invalid relay_urls value %q: scheme must be http or https", v)
	}
	if strings.TrimSpace(u.Host) == "" {
		return "", fmt.Errorf("invalid relay_urls value %q: host is required", v)
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
		if err := json.Unmarshal(item, &obj); err != nil {
			return nil, fmt.Errorf("script_keys[%d] must be a Deployment ID string or an object {\"id\": \"...\", \"account\": \"...\"}", i)
		}
		if strings.TrimSpace(obj.ID) == "" {
			return nil, fmt.Errorf("script_keys[%d] is an object without an \"id\" field — provide the Deployment ID there", i)
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
		return errors.New("script_keys still contains the placeholder text from client_config.example.json — replace it with your real Deployment ID (see README Step 5)")
	}
	if strings.Contains(id, "/edit") || strings.Contains(id, "script.google.com/d/") {
		return errors.New("this looks like the Apps Script *editor* URL, not a Deployment ID. Open the deployment from Deploy → Manage deployments, click the deployed Web App URL, and copy the long string between /s/ and /exec")
	}
	if strings.ContainsAny(id, " \t\n\r") {
		return errors.New("script_keys value contains whitespace — paste the Deployment ID without spaces or line breaks")
	}
	if !strings.HasPrefix(id, "AKfycb") {
		return errors.New("deployment IDs start with 'AKfycb' — you may have pasted the script ID (from the editor) instead of the Deployment ID. After deploying, open Deploy → Manage deployments and copy the ID from the Web App URL")
	}
	if len(id) < 50 {
		return fmt.Errorf("deployment ID looks too short (%d chars; expected ~70) — it may be truncated, re-copy from Deploy → Manage deployments", len(id))
	}
	return nil
}

// parseSNIHosts parses the "sni" JSON field, which may be either a single
// string ("www.google.com") or an array (["www.google.com", "mail.google.com"]).
// Falls back to ["www.google.com"] when the field is absent or empty.
func parseSNIHosts(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return []string{"www.google.com"}
	}
	// Try string first (backward-compatible single-SNI config).
	var single string
	if err := json.Unmarshal(raw, &single); err == nil {
		single = strings.TrimSpace(single)
		if single == "" {
			return []string{"www.google.com"}
		}
		return []string{single}
	}
	// Try array.
	var multi []string
	if err := json.Unmarshal(raw, &multi); err != nil {
		// Malformed — fall back to default and let the rest of validation catch it.
		return []string{"www.google.com"}
	}
	out := make([]string, 0, len(multi))
	for _, h := range multi {
		h = strings.TrimSpace(h)
		if h != "" {
			out = append(out, h)
		}
	}
	if len(out) == 0 {
		return []string{"www.google.com"}
	}
	return out
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

	var f clientFile
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("config %q is not valid JSON: %v\n  Common causes: missing comma between fields, trailing comma after the last field, unclosed quote, or a typo in a field name", path, err)
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

	key := strings.TrimSpace(f.TunnelKey)
	if key == "" || key == "REPLACE_WITH_64_HEX_CHARACTER_RANDOM_KEY" {
		return nil, fmt.Errorf("tunnel_key is empty or still the placeholder text in %s.\n  Fix: generate a key with 'openssl rand -hex 32' and paste the 64-character output into the tunnel_key field. The same value must be in server_config.json", path)
	}
	if len(key) != 64 {
		return nil, fmt.Errorf("tunnel_key must be exactly 64 hex characters (got %d) in %s.\n  Fix: generate a fresh key with 'openssl rand -hex 32' and paste the full output. Use the SAME value in client_config.json and server_config.json", len(key), path)
	}
	raw, err := hex.DecodeString(key)
	if err != nil || len(raw) != 32 {
		return nil, fmt.Errorf("tunnel_key in %s contains non-hex characters.\n  Valid characters are 0-9 and a-f. Generate a fresh key with 'openssl rand -hex 32' and copy it carefully — no spaces, quotes, or extra newlines", path)
	}

	useFronting := len(relayURLs) == 0
	scriptURLs := relayURLs
	scriptAccounts := make([]string, len(relayURLs)) // direct relay_urls have no account labels
	googleIP := ""
	var sniHosts []string

	if useFronting {
		googleHost := firstNonEmpty(f.GoogleHost, "216.239.38.120")
		googlePort := 443
		googleIP = net.JoinHostPort(googleHost, strconv.Itoa(googlePort))
		sniHosts = parseSNIHosts(f.SNI)

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

	socksUser := strings.TrimSpace(f.SocksUser)
	socksPass := strings.TrimSpace(f.SocksPass)
	if (socksUser == "") != (socksPass == "") {
		return nil, fmt.Errorf("socks_user and socks_pass must both be set or both be empty in %s", path)
	}

	if f.CoalesceStepMs < 0 {
		return nil, fmt.Errorf("coalesce_step_ms must be >= 0 in %s (got %d)", path, f.CoalesceStepMs)
	}
	coalesceMax := 0
	if f.CoalesceStepMs > 0 {
		coalesceMax = f.CoalesceStepMs * 25
	}

	if f.IdleSlotsPerBucket < 0 || f.IdleSlotsPerBucket > 3 {
		return nil, fmt.Errorf("idle_slots_per_bucket must be 0–3 in %s (got %d). 0 or unset = default (1, safest); 2–3 increases download throughput at the cost of more simultaneous executions per Google account, which can re-trigger issue #56 if your accounts can't sustain that concurrency", path, f.IdleSlotsPerBucket)
	}

	c := Client{
		ListenAddr:                  net.JoinHostPort(listenHost, strconv.Itoa(listenPort)),
		GoogleIP:                    googleIP,
		SNIHosts:                    sniHosts,
		ScriptURLs:                  scriptURLs,
		ScriptAccounts:              scriptAccounts,
		UseFronting:                 useFronting,
		AESKeyHex:                   key,
		DebugTiming:                 f.DebugTiming,
		SocksUser:                   socksUser,
		SocksPass:                   socksPass,
		CoalesceStepMs:              f.CoalesceStepMs,
		CoalesceMaxMs:               coalesceMax,
		IdleSlotsPerBucket:          f.IdleSlotsPerBucket,
	}
	return &c, nil
}
