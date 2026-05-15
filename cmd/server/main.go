// GooseRelayVPN server (VPS exit): receives AES-encrypted frame batches from
// Apps Script, decrypts, and bridges to real upstream TCP targets.
package main

import (
	"context"
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/kianmhz/GooseRelayVPN/internal/config"
	"github.com/kianmhz/GooseRelayVPN/internal/exit"
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
	flag.Parse()
	resolvedConfigPath := resolveDefaultConfigPath(*configPath, "server_config.json")

	cfg, err := config.LoadServer(resolvedConfigPath)
	if err != nil {
		log.Fatalf("%v", err)
	}

	srv, err := exit.New(exit.Config{
		ListenAddr:                cfg.ListenAddr,
		AESKeyHex:                 cfg.AESKeyHex,
		DebugTiming:               cfg.DebugTiming,
		AutoTune:                  cfg.AutoTune,
		UpstreamProxy:             cfg.UpstreamProxy,
		Version:                   version,
		ActiveDrainWindow:         time.Duration(cfg.ActiveDrainWindowMs) * time.Millisecond,
		LongPollWindow:            time.Duration(cfg.LongPollWindowMs) * time.Millisecond,
		UpstreamDialTimeout:       time.Duration(cfg.UpstreamDialTimeoutMs) * time.Millisecond,
		CoalesceWindow:            time.Duration(cfg.CoalesceWindowMs) * time.Millisecond,
		CoalesceWindowBusy:        time.Duration(cfg.CoalesceWindowBusyMs) * time.Millisecond,
		DisableCoalesce:           cfg.CoalesceWindowMs == 0 && cfg.CoalesceWindowBusyMs == 0,
		MaxSessions:               cfg.MaxSessions,
		MaxRequestBodyBytes:       cfg.MaxRequestBodyBytes,
		MaxResponseBytesPreEncode: cfg.MaxResponseBytesPreEncode,
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
		log.Printf("[exit] debug_timing enabled — per-session dial breakdown will be logged")
	}
	if cfg.AutoTune {
		log.Printf("[exit] auto_tune enabled — server latency windows will be adjusted within fixed safety caps")
	}
	if cfg.UpstreamProxy != "" {
		log.Printf("[exit] upstream_proxy enabled — outbound connections routed via SOCKS5 %s", cfg.UpstreamProxy)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := srv.ListenAndServeContext(ctx); err != nil {
		msg := err.Error()
		if strings.Contains(msg, "address already in use") {
			log.Fatalf("port %s is already in use — another goose-server may be running.\n  Check with: sudo lsof -i :%s", port, port)
		}
		if strings.Contains(msg, "permission denied") {
			log.Fatalf("permission denied binding %s — ports below 1024 require root, or pick a different server_port (e.g. 8443)", cfg.ListenAddr)
		}
		log.Fatalf("listen: %v", err)
	}
}
