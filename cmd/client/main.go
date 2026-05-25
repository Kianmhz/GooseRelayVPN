// GooseRelayVPN client: SOCKS5 listener that tunnels TCP through Apps Script.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	neturl "net/url"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/kianmhz/GooseRelayVPN/internal/carrier"
	"github.com/kianmhz/GooseRelayVPN/internal/config"
	"github.com/kianmhz/GooseRelayVPN/internal/debughttp"
	"github.com/kianmhz/GooseRelayVPN/internal/protocol"
	"github.com/kianmhz/GooseRelayVPN/internal/runlog"
	"github.com/kianmhz/GooseRelayVPN/internal/session"
	"github.com/kianmhz/GooseRelayVPN/internal/socks"
)

var version = "dev"

type clientLogWriter struct {
	out      io.Writer
	file     io.Writer
	useColor bool
	mu       sync.Mutex
}

func (w *clientLogWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	raw := strings.TrimRight(string(p), "\r\n")
	if raw == "" {
		if _, err := w.out.Write(p); err != nil {
			return len(p), err
		}
		if w.file != nil {
			if _, err := w.file.Write(p); err != nil {
				return len(p), err
			}
		}
		return len(p), nil
	}

	module := "client"
	msg := raw
	if strings.HasPrefix(raw, "[") {
		if idx := strings.Index(raw, "]"); idx > 1 {
			module = strings.ToUpper(strings.TrimSpace(raw[1:idx]))
			msg = strings.TrimSpace(raw[idx+1:])
		}
	}
	module = strings.ToUpper(module)

	level := "INFO"
	lower := strings.ToLower(msg)
	if strings.Contains(lower, "fatal") || strings.Contains(lower, "invalid") || strings.Contains(lower, "required") {
		level = "ERROR"
	} else if strings.Contains(lower, "timeout") || strings.Contains(lower, "non-ok") || strings.Contains(lower, "failed") || strings.Contains(lower, "shutting down") {
		level = "WARN"
	}

	ts := time.Now().Format("15:04:05")
	line := fmt.Sprintf("%s  %-7s %-7s %s\n", ts, module, level, msg)

	var terminalErr error
	if !w.useColor {
		_, terminalErr = io.WriteString(w.out, line)
	} else {
		levelColor := "\x1b[36m" // cyan
		if level == "WARN" {
			levelColor = "\x1b[33m" // yellow
		}
		if level == "ERROR" {
			levelColor = "\x1b[31m" // red
		}
		colored := fmt.Sprintf("%s  \x1b[35m%-7s\x1b[0m %s%-7s\x1b[0m %s\n", ts, module, levelColor, level, msg)
		_, terminalErr = io.WriteString(w.out, colored)
	}
	if terminalErr != nil {
		return len(p), terminalErr
	}
	if w.file != nil {
		if _, err := io.WriteString(w.file, line); err != nil {
			return len(p), err
		}
	}
	return len(p), nil
}

func (w *clientLogWriter) SetFile(file io.Writer) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.file = file
}

func setupClientLogging() *clientLogWriter {
	log.SetFlags(0)
	useColor := shouldUseColor(os.Stdout)
	w := &clientLogWriter{out: os.Stdout, useColor: useColor}
	log.SetOutput(w)
	return w
}

func configureCertificateBundle() (string, bool) {
	if runtime.GOOS != "linux" || os.Getenv("SSL_CERT_FILE") != "" {
		return "", false
	}
	candidates := []string{}
	if prefix := strings.TrimSpace(os.Getenv("PREFIX")); prefix != "" {
		candidates = append(candidates, filepath.Join(prefix, "etc", "tls", "cert.pem"))
	}
	candidates = append(candidates, "/data/data/com.termux/files/usr/etc/tls/cert.pem")
	for _, path := range candidates {
		info, err := os.Stat(path)
		if err == nil && !info.IsDir() {
			_ = os.Setenv("SSL_CERT_FILE", path)
			return path, true
		}
	}
	return "", false
}

func shouldIgnoreServeError(ctx context.Context, err error) bool {
	if err == nil {
		return true
	}
	if errors.Is(err, context.Canceled) {
		return true
	}
	if ctxErr := ctx.Err(); ctxErr != nil && errors.Is(err, ctxErr) {
		return true
	}
	return false
}

func clientShutdownTimeout(cfg *config.Client) time.Duration {
	if cfg == nil {
		return 5 * time.Second
	}
	mode := strings.ToLower(strings.TrimSpace(cfg.TransportMode))
	if mode == "apps_script" {
		return 15 * time.Second
	}
	if mode == "auto" && len(cfg.ScriptURLs) > 0 {
		return 15 * time.Second
	}
	if mode == "" && len(cfg.ScriptURLs) > 0 {
		return 15 * time.Second
	}
	return 5 * time.Second
}

func socksListenNeedsAuthWarning(listenAddr, socksUser, socksPass string) bool {
	if strings.TrimSpace(socksUser) != "" && strings.TrimSpace(socksPass) != "" {
		return false
	}
	host, _, err := net.SplitHostPort(strings.TrimSpace(listenAddr))
	if err != nil {
		return false
	}
	host = strings.Trim(host, "[]")
	if host == "" {
		return true
	}
	if strings.EqualFold(host, "localhost") {
		return false
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return true
	}
	return !ip.IsLoopback()
}

func shortScriptKey(scriptURL string) string {
	if u, err := neturl.Parse(scriptURL); err == nil && u.Host != "" {
		if strings.EqualFold(u.Hostname(), "script.google.com") {
			parts := strings.Split(strings.Trim(u.EscapedPath(), "/"), "/")
			for i := 0; i < len(parts)-1; i++ {
				if parts[i] == "s" {
					id := parts[i+1]
					if len(id) > 14 {
						return id[:6] + "..." + id[len(id)-6:]
					}
					return id
				}
			}
		}
		return u.Host
	}
	parts := strings.Split(strings.Trim(scriptURL, "/"), "/")
	if len(parts) >= 3 {
		return parts[2]
	}
	return scriptURL
}

func summarizeScriptURLs(scriptURLs []string) string {
	if len(scriptURLs) == 0 {
		return "(none)"
	}
	maxShown := len(scriptURLs)
	if maxShown > 3 {
		maxShown = 3
	}
	parts := make([]string, 0, maxShown)
	for i := 0; i < maxShown; i++ {
		parts = append(parts, shortScriptKey(scriptURLs[i]))
	}
	if len(scriptURLs) > maxShown {
		parts = append(parts, fmt.Sprintf("+%d more", len(scriptURLs)-maxShown))
	}
	return strings.Join(parts, ", ")
}

func resolveDefaultConfigPath(path, defaultName string) string {
	if path != defaultName {
		return path
	}
	if _, err := os.Stat(path); err == nil {
		return path
	}
	exe, err := os.Executable()
	if err != nil {
		return path
	}
	next := filepath.Join(filepath.Dir(exe), defaultName)
	if _, err := os.Stat(next); err == nil {
		return next
	}
	return path
}

func validClientInstanceID(id string) bool {
	id = strings.TrimSpace(id)
	if id == "" || len(id) > 128 {
		return false
	}
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '-' || r == '_' || r == '.' || r == ':':
		default:
			return false
		}
	}
	return true
}

func newClientInstanceID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

func resolveClientInstanceIDFile(configPath string, cfg *config.Client) string {
	if strings.TrimSpace(cfg.ClientInstanceIDFile) != "" {
		path := strings.TrimSpace(cfg.ClientInstanceIDFile)
		if filepath.IsAbs(path) {
			return path
		}
		return filepath.Join(filepath.Dir(configPath), path)
	}
	return filepath.Join(filepath.Dir(configPath), ".goose-client-instance")
}

func ensureClientInstanceID(configPath string, cfg *config.Client) (string, error) {
	if cfg == nil || !cfg.FreshStartReset {
		return "", nil
	}
	if id := strings.TrimSpace(cfg.ClientInstanceID); id != "" {
		if !validClientInstanceID(id) {
			return "", fmt.Errorf("client_instance_id contains unsupported characters")
		}
		return id, nil
	}
	explicitFile := strings.TrimSpace(cfg.ClientInstanceIDFile) != ""
	path := resolveClientInstanceIDFile(configPath, cfg)
	if b, err := os.ReadFile(path); err == nil {
		id := strings.TrimSpace(string(b))
		if validClientInstanceID(id) {
			return id, nil
		}
		if !explicitFile {
			log.Printf("[client] WARNING: default client instance file %s contains an invalid id; using a temporary id for this run", path)
			return newClientInstanceID()
		}
		return "", fmt.Errorf("client instance file %s contains an invalid id; delete it and restart to regenerate", path)
	} else if !errors.Is(err, os.ErrNotExist) {
		if !explicitFile {
			log.Printf("[client] WARNING: default client instance file %s could not be read (%v); using a temporary id for this run", path, err)
			return newClientInstanceID()
		}
		return "", fmt.Errorf("read client instance file %s: %w", path, err)
	}
	id, err := newClientInstanceID()
	if err != nil {
		return "", fmt.Errorf("generate client instance id: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		if !explicitFile {
			log.Printf("[client] WARNING: default client instance directory %s could not be created (%v); using a temporary id for this run", filepath.Dir(path), err)
			return id, nil
		}
		return "", fmt.Errorf("create client instance directory: %w", err)
	}
	if err := os.WriteFile(path, []byte(id+"\n"), 0o600); err != nil {
		if !explicitFile {
			log.Printf("[client] WARNING: default client instance file %s could not be written (%v); using a temporary id for this run", path, err)
			return id, nil
		}
		return "", fmt.Errorf("write client instance file %s: %w", path, err)
	}
	return id, nil
}

func logUnknownFieldsForReload(cfg *config.Client, w io.Writer) {
	if cfg == nil || len(cfg.UnknownFields) == 0 {
		return
	}
	msg := fmt.Sprintf("[config] reload warning: unknown config field(s) ignored: %s", strings.Join(cfg.UnknownFields, ", "))
	if w != nil {
		_, _ = fmt.Fprintln(w, msg)
		return
	}
	log.Print(msg)
}

func sameStringSlice(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func hotReloadPostWorkerPlan(c *config.Client) int {
	mode := strings.TrimSpace(strings.ToLower(c.TransportMode))
	if mode == "direct_stream" || len(c.ScriptURLs) == 0 {
		return 0
	}
	workers := c.WorkersPerEndpoint
	if workers <= 0 {
		workers = protocol.DefaultWorkersPerEndpoint
	}
	return workers * len(c.ScriptURLs)
}

func hotReloadRestartReason(current, next *config.Client) string {
	switch {
	case current.AESKeyHex != next.AESKeyHex:
		return "tunnel_key changed"
	case current.ListenAddr != next.ListenAddr:
		return "SOCKS listen address changed"
	case current.TransportMode != next.TransportMode:
		return "transport_mode changed"
	case current.UseFronting != next.UseFronting:
		return "relay mode changed"
	case current.PerformanceMode != next.PerformanceMode:
		return "performance_mode changed"
	case current.IdlePollMode != next.IdlePollMode:
		return "idle_poll_mode changed"
	case current.DownstreamReplayMode != next.DownstreamReplayMode:
		return "downstream_replay_mode changed"
	case current.FreshStartReset != next.FreshStartReset:
		return "fresh_start_reset changed"
	case current.ClientInstanceID != next.ClientInstanceID:
		return "client_instance_id changed"
	case current.ClientInstanceIDFile != next.ClientInstanceIDFile:
		return "client_instance_id_file changed"
	case current.QuotaStatePath != next.QuotaStatePath:
		return "quota_state_path changed"
	case current.IdleSlotsPerBucket != next.IdleSlotsPerBucket:
		return "idle_slots_per_bucket changed"
	case current.IdlePollMaxBuckets != next.IdlePollMaxBuckets:
		return "idle_poll_max_buckets changed"
	case current.TxSlotsPerBucket != next.TxSlotsPerBucket:
		return "tx_slots_per_bucket changed"
	case current.AutoTune != next.AutoTune:
		return "auto_tune changed"
	case current.DebugTiming != next.DebugTiming:
		return "debug_timing changed"
	case current.StatsJSON != next.StatsJSON:
		return "stats_json changed"
	case current.DebugPprofAddr != next.DebugPprofAddr:
		return "debug_pprof_addr changed"
	case current.WriteStartupDiagnostics != next.WriteStartupDiagnostics ||
		current.DiagnosticsOutputDir != next.DiagnosticsOutputDir:
		return "write_startup_diagnostics changed"
	case current.SaveTerminalLog != next.SaveTerminalLog || current.TerminalLogFile != next.TerminalLogFile:
		return "terminal log capture changed"
	case current.SocksUser != next.SocksUser || current.SocksPass != next.SocksPass:
		return "SOCKS auth changed"
	case current.MaxLocalSessions != next.MaxLocalSessions:
		return "max_local_sessions changed"
	case current.GoogleIP != next.GoogleIP:
		return "google_host changed"
	case !sameStringSlice(current.SNIHosts, next.SNIHosts):
		return "sni changed"
	case !sameStringSlice(current.DirectStreamURLs, next.DirectStreamURLs):
		return "direct_stream_urls changed"
	case current.CoalesceStepMs != next.CoalesceStepMs || current.CoalesceMaxMs != next.CoalesceMaxMs:
		return "coalesce settings changed"
	case current.PollIdleSleepMs != next.PollIdleSleepMs:
		return "poll_idle_sleep_ms changed"
	case current.PollTimeoutMs != next.PollTimeoutMs:
		return "poll_timeout_ms changed"
	case current.EndpointOutageGraceMs != next.EndpointOutageGraceMs:
		return "endpoint_outage_grace_ms changed"
	case current.EndpointBlacklistBaseMs != next.EndpointBlacklistBaseMs || current.EndpointBlacklistMaxMs != next.EndpointBlacklistMaxMs:
		return "endpoint blacklist TTL changed"
	case current.MaxRequestBytesPreEncode != next.MaxRequestBytesPreEncode:
		return "max_request_bytes_pre_encode changed"
	case current.TxBufferBudgetBytes != next.TxBufferBudgetBytes:
		return "tx_buffer_budget_bytes changed"
	case current.StreamConnectTimeoutMs != next.StreamConnectTimeoutMs ||
		current.StreamPingIntervalMs != next.StreamPingIntervalMs ||
		current.StreamReconnectBackoffMs != next.StreamReconnectBackoffMs:
		return "direct stream timeout changed"
	case current.FrontingHTTPVersion != next.FrontingHTTPVersion:
		return "fronting_http_version changed"
	case hotReloadPostWorkerPlan(current) != hotReloadPostWorkerPlan(next):
		return "relay worker count changed"
	default:
		return ""
	}
}

func watchClientConfig(ctx context.Context, path string, initial *config.Client, carr *carrier.Client) {
	info, err := os.Stat(path)
	if err != nil {
		log.Printf("[config] hot reload disabled: stat %s: %v", path, err)
		return
	}
	lastMod := info.ModTime()
	current := *initial
	current.SNIHosts = append([]string(nil), initial.SNIHosts...)
	current.ScriptURLs = append([]string(nil), initial.ScriptURLs...)
	current.ScriptAccounts = append([]string(nil), initial.ScriptAccounts...)
	current.DirectStreamURLs = append([]string(nil), initial.DirectStreamURLs...)

	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		info, err := os.Stat(path)
		if err != nil {
			log.Printf("[config] reload skipped: stat %s: %v", path, err)
			continue
		}
		if !info.ModTime().After(lastMod) {
			continue
		}
		lastMod = info.ModTime()
		next, err := config.LoadClient(path)
		if err != nil {
			log.Printf("[config] reload skipped: %v", err)
			continue
		}
		logUnknownFieldsForReload(next, nil)
		if reason := hotReloadRestartReason(&current, next); reason != "" {
			log.Printf("[config] reload saw %s; restart the client for that change to take effect", reason)
			continue
		}
		count := carr.UpdateEndpoints(next.ScriptURLs, next.ScriptAccounts)
		log.Printf("[config] reloaded %d relay endpoint(s): %s", count, summarizeScriptURLs(next.ScriptURLs))
		current = *next
		current.SNIHosts = append([]string(nil), next.SNIHosts...)
		current.ScriptURLs = append([]string(nil), next.ScriptURLs...)
		current.ScriptAccounts = append([]string(nil), next.ScriptAccounts...)
		current.DirectStreamURLs = append([]string(nil), next.DirectStreamURLs...)
	}
}

const gooseBanner = `
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⣤⣄⡀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣿⣿⣏⣹⣿⠄⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⠿⠋⢠⣷⣦⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣧⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣆⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣿⣿⣿⣿⡆⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣤⣶⣿⣿⣿⠛⣿⣿⣿⣧⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⣾⣿⣿⣿⣿⣿⣿⡇⢸⣿⣿⣿⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⣠⣴⣿⣿⣿⣿⣿⣿⣿⣿⣿⠇⢸⣿⣿⡿⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⢀⣠⣴⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠿⠋⣠⣿⣿⣿⠇⠀⠀⠀⠀⠀⠀
⠀⠀⠰⢾⣿⣿⣿⡟⠿⠿⣿⣿⠿⠿⠛⠋⣁⣴⣾⣿⣿⠿⠋⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠉⠛⠻⠷⣶⣤⣤⣤⣤⣶⣾⣿⡿⠿⠛⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⢀⣶⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⠛⠛⠛⠛⠛⠂⠀⠀⠀⠀
`

func main() {
	configPath := flag.String("config", "client_config.json", "path to client config JSON")
	dumpDiag := flag.Bool("dump-diag", false, "write a redacted diagnostics zip and exit")
	diagOutput := flag.String("diag-output", "", "path for --dump-diag output (default: diagnostics/goose-diagnostics-YYYYMMDD-HHMMSS.zip beside the binary)")
	debugPprof := flag.String("debug-pprof", "", "optional localhost address for live pprof, e.g. 127.0.0.1:6060")
	statsJSON := flag.Bool("stats-json", false, "emit periodic stats as JSON log lines")
	showVersion := flag.Bool("version", false, "show version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println(version)
		return
	}
	resolvedConfigPath := resolveDefaultConfigPath(*configPath, "client_config.json")
	if *dumpDiag {
		out, err := writeDiagnosticsZip(*diagOutput, resolvedConfigPath, version)
		if err != nil {
			log.Fatalf("[client] diagnostics failed: %v", err)
		}
		fmt.Printf("diagnostics written to %s\n", out)
		return
	}
	fmt.Print(gooseBanner)
	logWriter := setupClientLogging()
	if certPath, ok := configureCertificateBundle(); ok {
		log.Printf("[client] using CA bundle from %s", certPath)
	}

	cfg, err := config.LoadClient(resolvedConfigPath)
	if err != nil {
		log.Fatalf("%v", err)
	}
	if cfg.SaveTerminalLog {
		f, path, err := runlog.Open("goose-client", cfg.TerminalLogFile)
		if err != nil {
			log.Printf("[client] WARN: terminal log file disabled: %v", err)
		} else {
			defer f.Close()
			logWriter.SetFile(f)
			log.Printf("[client] saving terminal log to %s", path)
		}
	}
	if len(cfg.UnknownFields) > 0 {
		log.Printf("[client] WARNING: unknown config field(s) ignored: %s", strings.Join(cfg.UnknownFields, ", "))
	}
	clientInstanceID, err := ensureClientInstanceID(resolvedConfigPath, cfg)
	if err != nil {
		log.Fatalf("[client] fresh-start reset setup failed: %v", err)
	}
	cfg.ClientInstanceID = clientInstanceID
	effectivePprofAddr := strings.TrimSpace(cfg.DebugPprofAddr)
	if strings.TrimSpace(*debugPprof) != "" {
		effectivePprofAddr = strings.TrimSpace(*debugPprof)
	}
	debughttp.StartPprof(effectivePprofAddr, "client")
	if cfg.WriteStartupDiagnostics {
		outPath, err := startupDiagnosticsOutputPath(cfg.DiagnosticsOutputDir, "goose-diagnostics")
		if err != nil {
			log.Printf("[client] WARN: startup diagnostics path failed: %v", err)
		} else if out, err := writeDiagnosticsZip(outPath, resolvedConfigPath, version); err != nil {
			log.Printf("[client] WARN: startup diagnostics failed: %v", err)
		} else {
			log.Printf("[client] startup diagnostics written to %s", out)
		}
	}
	log.Printf("[client] GooseRelayVPN client starting")
	log.Printf("[client] config loaded from %s", resolvedConfigPath)
	log.Printf("[client] SOCKS5 proxy: socks5://%s", cfg.ListenAddr)
	log.Printf("[client] transport mode: %s", cfg.TransportMode)
	if len(cfg.DirectStreamURLs) > 0 {
		log.Printf("[client] direct stream endpoints: %d", len(cfg.DirectStreamURLs))
	}
	if cfg.UseFronting {
		log.Printf("[client] mode: fronting")
		if len(cfg.SNIHosts) == 1 {
			log.Printf("[client] fronting via %s (sni=%s)", cfg.GoogleIP, cfg.SNIHosts[0])
		} else {
			log.Printf("[client] fronting via %s (sni hosts: %s - %d front pools)", cfg.GoogleIP, strings.Join(cfg.SNIHosts, ", "), len(cfg.SNIHosts))
		}
	} else if len(cfg.ScriptURLs) > 0 {
		log.Printf("[client] mode: direct relay_urls (fronting disabled)")
	} else if len(cfg.DirectStreamURLs) > 0 {
		log.Printf("[client] mode: direct stream (POST relay fallback disabled)")
	} else {
		log.Printf("[client] mode: no relay endpoints configured")
	}
	if len(cfg.ScriptURLs) > 0 {
		log.Printf("[client] relay endpoints: %d (%s)", len(cfg.ScriptURLs), summarizeScriptURLs(cfg.ScriptURLs))
	} else {
		log.Printf("[client] relay endpoints: 0 (POST relay disabled)")
	}
	if cfg.DebugTiming {
		log.Printf("[client] debug_timing enabled - per-session TTFB and per-poll RTT will be logged")
	}
	if cfg.AutoTune {
		log.Printf("[client] auto_tune enabled - poll idle sleep will adjust inside fixed latency-safe caps")
	}
	if cfg.CoalesceStepMs > 0 {
		log.Printf("[client] uplink coalescing: step=%dms (internal safety cap %dms; bursts of TX collapse into a single poll)", cfg.CoalesceStepMs, cfg.CoalesceMaxMs)
	}
	if cfg.FreshStartReset && cfg.ClientInstanceID != "" {
		shortID := cfg.ClientInstanceID
		if len(shortID) > 8 {
			shortID = shortID[:8]
		}
		log.Printf("[client] fresh-start reset enabled (client instance %s)", shortID)
	}
	carr, err := carrier.New(carrier.Config{
		ScriptURLs:               cfg.ScriptURLs,
		ScriptAccounts:           cfg.ScriptAccounts,
		DirectStreamURLs:         cfg.DirectStreamURLs,
		TransportMode:            cfg.TransportMode,
		AESKeyHex:                cfg.AESKeyHex,
		DebugTiming:              cfg.DebugTiming,
		AutoTune:                 cfg.AutoTune,
		StatsJSON:                cfg.StatsJSON || *statsJSON,
		IdlePollMode:             cfg.IdlePollMode,
		DownstreamReplayMode:     cfg.DownstreamReplayMode,
		FreshStartReset:          cfg.FreshStartReset,
		ClientInstanceID:         cfg.ClientInstanceID,
		QuotaStatePath:           cfg.QuotaStatePath,
		UseFronting:              cfg.UseFronting,
		BinaryDirect:             false,
		ClientVersion:            version,
		CoalesceStep:             time.Duration(cfg.CoalesceStepMs) * time.Millisecond,
		CoalesceMax:              time.Duration(cfg.CoalesceMaxMs) * time.Millisecond,
		IdleSlotsPerBucket:       cfg.IdleSlotsPerBucket,
		IdlePollMaxBuckets:       cfg.IdlePollMaxBuckets,
		TxSlotsPerBucket:         cfg.TxSlotsPerBucket,
		WorkersPerEndpoint:       cfg.WorkersPerEndpoint,
		PollIdleSleep:            time.Duration(cfg.PollIdleSleepMs) * time.Millisecond,
		PollTimeout:              time.Duration(cfg.PollTimeoutMs) * time.Millisecond,
		EndpointBlacklistBaseTTL: time.Duration(cfg.EndpointBlacklistBaseMs) * time.Millisecond,
		EndpointBlacklistMaxTTL:  time.Duration(cfg.EndpointBlacklistMaxMs) * time.Millisecond,
		EndpointOutageGrace:      time.Duration(cfg.EndpointOutageGraceMs) * time.Millisecond,
		MaxRequestBytesPreEncode: cfg.MaxRequestBytesPreEncode,
		TxBufferBudgetBytes:      cfg.TxBufferBudgetBytes,
		StreamConnectTimeout:     time.Duration(cfg.StreamConnectTimeoutMs) * time.Millisecond,
		StreamPingInterval:       time.Duration(cfg.StreamPingIntervalMs) * time.Millisecond,
		StreamReconnectBackoff:   time.Duration(cfg.StreamReconnectBackoffMs) * time.Millisecond,
		Fronting: carrier.FrontingConfig{
			GoogleIP:    cfg.GoogleIP,
			SNIHosts:    cfg.SNIHosts,
			HTTPVersion: cfg.FrontingHTTPVersion,
		},
	})
	if err != nil {
		log.Fatalf("carrier: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go watchClientConfig(ctx, resolvedConfigPath, cfg, carr)

	if len(cfg.ScriptURLs) > 0 {
		// Pre-flight check: one-shot end-to-end probe so users see actionable
		// errors at startup instead of cryptic mid-session failures.
		if cfg.UseFronting {
			log.Printf("[client] running pre-flight check (Apps Script reachable, VPS reachable, key matches)...")
		} else {
			log.Printf("[client] running pre-flight check (direct relay reachable, key matches)...")
		}
		diagCtx, cancelDiag := context.WithTimeout(ctx, 20*time.Second)
		if err := carr.Diagnose(diagCtx); err != nil {
			log.Printf("[client] pre-flight FAILED:")
			for _, line := range strings.Split(err.Error(), "\n") {
				log.Printf("[client]   %s", line)
			}
			log.Printf("[client] continuing anyway - the issue may be transient or recover on its own")
		} else {
			log.Printf("[client] pre-flight OK: at least one relay endpoint is healthy, AES key matches end-to-end")
		}
		cancelDiag()
	} else {
		log.Printf("[client] pre-flight skipped: direct_stream-only mode will connect to the VPS stream endpoint")
	}

	go func() {
		if err := carr.Run(ctx); err != nil && ctx.Err() == nil {
			log.Fatalf("carrier run: %v", err)
		}
	}()

	factory := socks.SessionFactory(func(target string) *session.Session {
		return carr.NewSession(target)
	})

	socksCtx, stopSocks := context.WithCancel(ctx)
	defer stopSocks()

	go func() {
		log.Printf("[client] ready: local SOCKS5 is listening on %s", cfg.ListenAddr)
		if cfg.SocksUser != "" {
			log.Printf("[client] SOCKS5 auth enabled (RFC 1929 username/password required)")
		} else if socksListenNeedsAuthWarning(cfg.ListenAddr, cfg.SocksUser, cfg.SocksPass) {
			log.Printf("[client] WARNING: SOCKS5 is listening on a non-loopback address without auth; anyone on that network may use this tunnel. Set socks_user and socks_pass or bind to 127.0.0.1.")
		}
		if err := socks.Serve(socksCtx, cfg.ListenAddr, cfg.SocksUser, cfg.SocksPass, cfg.DebugTiming, cfg.MaxLocalSessions, factory); err != nil {
			if !shouldIgnoreServeError(socksCtx, err) {
				log.Fatalf("socks: %v", err)
			}
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
	log.Println("[client] shutting down - notifying server of active sessions")
	stopSocks()
	// Send RSTs for active sessions so the server can release their upstream
	// connections immediately. Bounded so a slow server can't block exit.
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), clientShutdownTimeout(cfg))
	shutdownStart := time.Now()
	carr.Shutdown(shutdownCtx)
	if err := shutdownCtx.Err(); err != nil {
		log.Printf("[client] shutdown timed out after %s; exiting with local cleanup only", time.Since(shutdownStart).Round(time.Millisecond))
	} else {
		log.Printf("[client] shutdown completed in %s", time.Since(shutdownStart).Round(time.Millisecond))
	}
	shutdownCancel()
	cancel()
}
