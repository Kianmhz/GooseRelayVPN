// GooseRelayVPN client: SOCKS5 listener that tunnels TCP through Apps Script.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/kianmhz/GooseRelayVPN/internal/carrier"
	"github.com/kianmhz/GooseRelayVPN/internal/config"
	"github.com/kianmhz/GooseRelayVPN/internal/protocol"
	"github.com/kianmhz/GooseRelayVPN/internal/session"
	"github.com/kianmhz/GooseRelayVPN/internal/socks"
)

var version = "dev"

type clientLogWriter struct {
	out      io.Writer
	useColor bool
}

func (w *clientLogWriter) Write(p []byte) (int, error) {
	raw := strings.TrimRight(string(p), "\r\n")
	if raw == "" {
		_, err := w.out.Write(p)
		return len(p), err
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

	if !w.useColor {
		_, err := io.WriteString(w.out, line)
		return len(p), err
	}

	levelColor := "\x1b[36m" // cyan
	if level == "WARN" {
		levelColor = "\x1b[33m" // yellow
	}
	if level == "ERROR" {
		levelColor = "\x1b[31m" // red
	}
	colored := fmt.Sprintf("%s  \x1b[35m%-7s\x1b[0m %s%-7s\x1b[0m %s\n", ts, module, levelColor, level, msg)
	_, err := io.WriteString(w.out, colored)
	return len(p), err
}

func setupClientLogging() {
	log.SetFlags(0)
	useColor := shouldUseColor(os.Stdout)
	log.SetOutput(&clientLogWriter{out: os.Stdout, useColor: useColor})
}

func shortScriptKey(scriptURL string) string {
	parts := strings.Split(strings.Trim(scriptURL, "/"), "/")
	for i := 0; i < len(parts)-1; i++ {
		if parts[i] == "s" {
			id := parts[i+1]
			if len(id) > 14 {
				return id[:6] + "..." + id[len(id)-6:]
			}
			return id
		}
	}
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
	idleSlots := c.IdleSlotsPerBucket
	if idleSlots <= 0 {
		idleSlots = 1
	}
	buckets := make(map[string]struct{}, len(c.ScriptURLs))
	for i := range c.ScriptURLs {
		account := ""
		if i < len(c.ScriptAccounts) {
			account = strings.TrimSpace(c.ScriptAccounts[i])
		}
		buckets[account] = struct{}{}
	}
	if len(buckets) == 0 {
		return 0
	}
	return (workers + idleSlots - 1) * len(buckets)
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
	case current.AutoTune != next.AutoTune:
		return "auto_tune changed"
	case current.DebugTiming != next.DebugTiming:
		return "debug_timing changed"
	case current.SocksUser != next.SocksUser || current.SocksPass != next.SocksPass:
		return "SOCKS auth changed"
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
	case current.EndpointBlacklistBaseMs != next.EndpointBlacklistBaseMs || current.EndpointBlacklistMaxMs != next.EndpointBlacklistMaxMs:
		return "endpoint blacklist TTL changed"
	case current.MaxRequestBytesPreEncode != next.MaxRequestBytesPreEncode:
		return "max_request_bytes_pre_encode changed"
	case current.StreamConnectTimeoutMs != next.StreamConnectTimeoutMs ||
		current.StreamPingIntervalMs != next.StreamPingIntervalMs ||
		current.StreamReconnectBackoffMs != next.StreamReconnectBackoffMs:
		return "direct stream timeout changed"
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
	fmt.Print(gooseBanner)
	setupClientLogging()

	configPath := flag.String("config", "client_config.json", "path to client config JSON")
	dumpDiag := flag.Bool("dump-diag", false, "write a redacted diagnostics zip and exit")
	diagOutput := flag.String("diag-output", "", "path for --dump-diag output (default: goose-diagnostics-YYYYMMDD-HHMMSS.zip)")
	flag.Parse()
	resolvedConfigPath := resolveDefaultConfigPath(*configPath, "client_config.json")
	if *dumpDiag {
		out, err := writeDiagnosticsZip(*diagOutput, resolvedConfigPath, version)
		if err != nil {
			log.Fatalf("[client] diagnostics failed: %v", err)
		}
		log.Printf("[client] diagnostics written to %s", out)
		return
	}

	cfg, err := config.LoadClient(resolvedConfigPath)
	if err != nil {
		log.Fatalf("%v", err)
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
			log.Printf("[client] fronting via %s (sni hosts: %s — %d throttle buckets)", cfg.GoogleIP, strings.Join(cfg.SNIHosts, ", "), len(cfg.SNIHosts))
		}
	} else {
		log.Printf("[client] mode: direct relay_urls (fronting disabled)")
	}
	log.Printf("[client] relay endpoints: %d (%s)", len(cfg.ScriptURLs), summarizeScriptURLs(cfg.ScriptURLs))
	if cfg.DebugTiming {
		log.Printf("[client] debug_timing enabled — per-session TTFB and per-poll RTT will be logged")
	}
	if cfg.AutoTune {
		log.Printf("[client] auto_tune enabled - poll idle sleep will adjust inside fixed latency-safe caps")
	}
	if cfg.CoalesceStepMs > 0 {
		log.Printf("[client] uplink coalescing: step=%dms (internal safety cap %dms; bursts of TX collapse into a single poll)", cfg.CoalesceStepMs, cfg.CoalesceMaxMs)
	}
	carr, err := carrier.New(carrier.Config{
		ScriptURLs:               cfg.ScriptURLs,
		ScriptAccounts:           cfg.ScriptAccounts,
		DirectStreamURLs:         cfg.DirectStreamURLs,
		TransportMode:            cfg.TransportMode,
		AESKeyHex:                cfg.AESKeyHex,
		DebugTiming:              cfg.DebugTiming,
		AutoTune:                 cfg.AutoTune,
		UseFronting:              cfg.UseFronting,
		BinaryDirect:             !cfg.UseFronting,
		ClientVersion:            version,
		CoalesceStep:             time.Duration(cfg.CoalesceStepMs) * time.Millisecond,
		CoalesceMax:              time.Duration(cfg.CoalesceMaxMs) * time.Millisecond,
		IdleSlotsPerBucket:       cfg.IdleSlotsPerBucket,
		WorkersPerEndpoint:       cfg.WorkersPerEndpoint,
		PollIdleSleep:            time.Duration(cfg.PollIdleSleepMs) * time.Millisecond,
		EndpointBlacklistBaseTTL: time.Duration(cfg.EndpointBlacklistBaseMs) * time.Millisecond,
		EndpointBlacklistMaxTTL:  time.Duration(cfg.EndpointBlacklistMaxMs) * time.Millisecond,
		EndpointOutageGrace:      time.Duration(cfg.EndpointOutageGraceMs) * time.Millisecond,
		MaxRequestBytesPreEncode: cfg.MaxRequestBytesPreEncode,
		StreamConnectTimeout:     time.Duration(cfg.StreamConnectTimeoutMs) * time.Millisecond,
		StreamPingInterval:       time.Duration(cfg.StreamPingIntervalMs) * time.Millisecond,
		StreamReconnectBackoff:   time.Duration(cfg.StreamReconnectBackoffMs) * time.Millisecond,
		Fronting: carrier.FrontingConfig{
			GoogleIP: cfg.GoogleIP,
			SNIHosts: cfg.SNIHosts,
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
			log.Printf("[client] running pre-flight check (Apps Script reachable, VPS reachable, key matches)…")
		} else {
			log.Printf("[client] running pre-flight check (direct relay reachable, key matches)…")
		}
		diagCtx, cancelDiag := context.WithTimeout(ctx, 20*time.Second)
		if err := carr.Diagnose(diagCtx); err != nil {
			log.Printf("[client] pre-flight FAILED:")
			for _, line := range strings.Split(err.Error(), "\n") {
				log.Printf("[client]   %s", line)
			}
			log.Printf("[client] continuing anyway — the issue may be transient or recover on its own")
		} else {
			log.Printf("[client] pre-flight OK: relay healthy, AES key matches end-to-end")
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

	go func() {
		log.Printf("[client] ready: local SOCKS5 is listening on %s", cfg.ListenAddr)
		if cfg.SocksUser != "" {
			log.Printf("[client] SOCKS5 auth enabled (RFC 1929 username/password required)")
		}
		if err := socks.Serve(ctx, cfg.ListenAddr, cfg.SocksUser, cfg.SocksPass, cfg.DebugTiming, factory); err != nil {
			log.Fatalf("socks: %v", err)
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
	log.Println("[client] shutting down — notifying server of active sessions")
	// Send RSTs for active sessions so the server can release their upstream
	// connections immediately. Bounded so a slow server can't block exit.
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 3*time.Second)
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
