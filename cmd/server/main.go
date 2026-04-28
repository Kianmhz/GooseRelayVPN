// GooseRelayVPN server (VPS exit): receives AES-encrypted frame batches from
// Apps Script, decrypts, and bridges to real upstream TCP targets.
package main

import (
	"flag"
	"log"
	"net"
	"strings"

	"github.com/kianmhz/GooseRelayVPN/internal/config"
	"github.com/kianmhz/GooseRelayVPN/internal/exit"
)

func main() {
	configPath := flag.String("config", "server_config.json", "path to server config JSON")
	flag.Parse()

	cfg, err := config.LoadServer(*configPath)
	if err != nil {
		log.Fatalf("%v", err)
	}

	srv, err := exit.New(exit.Config{
		ListenAddr:  cfg.ListenAddr,
		AESKeyHex:   cfg.AESKeyHex,
		DebugTiming: cfg.DebugTiming,
	})
	if err != nil {
		log.Fatalf("exit: %v", err)
	}

	// Surface a few sanity-check URLs the operator can curl to verify the
	// server is reachable from outside (Apps Script must be able to POST here).
	_, port, _ := net.SplitHostPort(cfg.ListenAddr)
	log.Printf("[exit] tunnel_key loaded (32 bytes)")
	log.Printf("[exit] healthz: curl http://YOUR.VPS.IP:%s/healthz   (should return HTTP 200)", port)
	log.Printf("[exit] tunnel : POST http://YOUR.VPS.IP:%s/tunnel    (this is the VPS_URL in Code.gs)", port)
	if cfg.DebugTiming {
		log.Printf("[exit] debug_timing enabled — per-session dial breakdown will be logged")
	}

	if err := srv.ListenAndServe(); err != nil {
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
