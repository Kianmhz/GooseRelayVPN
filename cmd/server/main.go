// GooseRelayVPN server (VPS exit): receives AES-encrypted frame batches from
// Apps Script, decrypts, and bridges to real upstream TCP targets.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/kianmhz/GooseRelayVPN/internal/config"
	"github.com/kianmhz/GooseRelayVPN/internal/debughttp"
	"github.com/kianmhz/GooseRelayVPN/internal/exit"
	"github.com/kianmhz/GooseRelayVPN/internal/runlog"
)

var version = "dev"

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

func main() {
	configPath := flag.String("config", "server_config.json", "path to server config JSON")
	dumpDiag := flag.Bool("dump-diag", false, "write a redacted diagnostics zip and exit")
	diagOutput := flag.String("diag-output", "", "path for --dump-diag output (default: diagnostics/goose-server-diagnostics-YYYYMMDD-HHMMSS.zip beside the binary)")
	debugPprof := flag.String("debug-pprof", "", "optional localhost address for live pprof, e.g. 127.0.0.1:6061")
	statsJSON := flag.Bool("stats-json", false, "emit periodic stats as JSON log lines")
	showVersion := flag.Bool("version", false, "show version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println(version)
		return
	}
	resolvedConfigPath := resolveDefaultConfigPath(*configPath, "server_config.json")
	if *dumpDiag {
		out, err := writeServerDiagnosticsZip(*diagOutput, resolvedConfigPath, version)
		if err != nil {
			log.Fatalf("[exit] diagnostics failed: %v", err)
		}
		log.Printf("[exit] diagnostics written to %s", out)
		return
	}

	cfg, err := config.LoadServer(resolvedConfigPath)
	if err != nil {
		log.Fatalf("%v", err)
	}
	if cfg.SaveTerminalLog {
		f, path, err := runlog.Open("goose-server", cfg.TerminalLogFile)
		if err != nil {
			log.Printf("[exit] WARN: terminal log file disabled: %v", err)
		} else {
			defer f.Close()
			log.SetOutput(io.MultiWriter(os.Stderr, f))
			log.Printf("[exit] saving terminal log to %s", path)
		}
	}
	if len(cfg.UnknownFields) > 0 {
		log.Printf("[exit] WARNING: unknown config field(s) ignored: %s", strings.Join(cfg.UnknownFields, ", "))
	}
	effectivePprofAddr := strings.TrimSpace(cfg.DebugPprofAddr)
	if strings.TrimSpace(*debugPprof) != "" {
		effectivePprofAddr = strings.TrimSpace(*debugPprof)
	}
	debughttp.StartPprof(effectivePprofAddr, "exit")
	if cfg.WriteStartupDiagnostics {
		outPath, err := startupDiagnosticsOutputPath(cfg.DiagnosticsOutputDir, "goose-server-diagnostics")
		if err != nil {
			log.Printf("[exit] WARN: startup diagnostics path failed: %v", err)
		} else if out, err := writeServerDiagnosticsZip(outPath, resolvedConfigPath, version); err != nil {
			log.Printf("[exit] WARN: startup diagnostics failed: %v", err)
		} else {
			log.Printf("[exit] startup diagnostics written to %s", out)
		}
	}

	srv, err := exit.New(exit.Config{
		ListenAddr:                    cfg.ListenAddr,
		AESKeyHex:                     cfg.AESKeyHex,
		DebugTiming:                   cfg.DebugTiming,
		AutoTune:                      cfg.AutoTune,
		StatsJSON:                     cfg.StatsJSON || *statsJSON,
		UpstreamProxy:                 cfg.UpstreamProxy,
		UpstreamProxyUser:             cfg.UpstreamProxyUser,
		UpstreamProxyPass:             cfg.UpstreamProxyPass,
		Version:                       version,
		ActiveDrainWindow:             time.Duration(cfg.ActiveDrainWindowMs) * time.Millisecond,
		LongPollWindow:                time.Duration(cfg.LongPollWindowMs) * time.Millisecond,
		UpstreamDialTimeout:           time.Duration(cfg.UpstreamDialTimeoutMs) * time.Millisecond,
		CoalesceWindow:                time.Duration(cfg.CoalesceWindowMs) * time.Millisecond,
		CoalesceWindowBusy:            time.Duration(cfg.CoalesceWindowBusyMs) * time.Millisecond,
		DisableCoalesce:               cfg.CoalesceWindowMs == 0 && cfg.CoalesceWindowBusyMs == 0,
		MaxSessions:                   cfg.MaxSessions,
		MaxDrainFramesPerSession:      cfg.MaxDrainFramesPerSession,
		MaxRequestBodyBytes:           cfg.MaxRequestBodyBytes,
		MaxResponseBytesPreEncode:     cfg.MaxResponseBytesPreEncode,
		InitialResponseBytesPreEncode: cfg.InitialResponseBytesPreEncode,
		SecondResponseBytesPreEncode:  cfg.SecondResponseBytesPreEncode,
		DisableInitialResponseCap:     !cfg.InitialResponseCapEnabled,
		DisableSecondResponseCap:      !cfg.SecondResponseCapEnabled,
		DownstreamReplayEnabled:       cfg.DownstreamReplayEnabled,
	})
	if err != nil {
		log.Fatalf("exit: %v", err)
	}

	// Surface a few sanity-check URLs the operator can curl to verify the
	// server is reachable from outside (Apps Script must be able to POST here).
	_, port, _ := net.SplitHostPort(cfg.ListenAddr)
	log.Printf("[exit] tunnel_key loaded (32 bytes)")
	log.Printf("[exit] healthz: curl http://YOUR.VPS.IP:%s/healthz   (should return HTTP 200)", port)
	log.Printf("[exit] tunnel : POST http://YOUR.VPS.IP:%s/tunnel    (put this in RELAY_URLS in Code.gs)", port)
	log.Printf("[exit] stream : WS   ws://YOUR.VPS.IP:%s/stream     (direct_stream_urls endpoint)", port)
	if cfg.DebugTiming {
		log.Printf("[exit] debug_timing enabled - per-session dial breakdown will be logged")
	}
	if cfg.AutoTune {
		log.Printf("[exit] auto_tune enabled - server latency windows will be adjusted within fixed safety caps")
	}
	if cfg.UpstreamProxy != "" {
		log.Printf("[exit] upstream_proxy enabled - outbound connections routed via SOCKS5 %s", cfg.UpstreamProxy)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := srv.ListenAndServeContext(ctx); err != nil {
		msg := err.Error()
		if strings.Contains(msg, "address already in use") {
			log.Fatalf("port %s is already in use - another goose-server may be running.\n  Check with: sudo lsof -i :%s", port, port)
		}
		if strings.Contains(msg, "permission denied") {
			log.Fatalf("permission denied binding %s - ports below 1024 require root, or pick a different server_port (e.g. 8443)", cfg.ListenAddr)
		}
		log.Fatalf("listen: %v", err)
	}
}
