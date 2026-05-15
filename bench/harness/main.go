// harness drives a loopback end-to-end benchmark for relay-tunnel.
//
// It owns three child processes: the bench sink (upstream targets), goose-server
// (the VPS exit), and goose-client (the local SOCKS5 listener). The client is
// pointed at goose-server directly (direct POST or direct WebSocket stream),
// bypassing Apps Script entirely so results are reproducible.
//
// Each scenario is a Go function that drives traffic through the local SOCKS5
// proxy. Results are written as a single JSON document so bench.sh can diff
// two refs.
//
// This program is intentionally single-file and stdlib-only (plus
// golang.org/x/net/proxy, which the project already depends on transitively).
package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/proxy"
)

const (
	socksPort  = 11080
	serverPort = 18443

	// Sink ports — must match bench/sink/main.go.
	sinkEcho   = "127.0.0.1:9101"
	sinkSized  = "127.0.0.1:9102"
	sinkSource = "127.0.0.1:9103"
	sinkQuick  = "127.0.0.1:9104"
)

type host struct {
	OS   string `json:"os"`
	Arch string `json:"arch"`
	NCPU int    `json:"ncpu"`
}

type result struct {
	Ref        string                     `json:"ref"`
	Commit     string                     `json:"commit"`
	GoVersion  string                     `json:"go_version"`
	Host       host                       `json:"host"`
	StartedAt  string                     `json:"started_at"`
	DurationMS int64                      `json:"duration_ms"`
	Scenarios  map[string]json.RawMessage `json:"scenarios"`
}

type scenario struct {
	name string
	run  func(context.Context, *runEnv) (any, error)
}

type runEnv struct {
	dialer proxy.Dialer
	dir    string
	server *exec.Cmd
	client *exec.Cmd
}

func main() {
	log.SetFlags(0)
	log.SetPrefix("[harness] ")

	var (
		clientBin   = flag.String("client-bin", "", "path to goose-client binary")
		serverBin   = flag.String("server-bin", "", "path to goose-server binary")
		sinkBin     = flag.String("sink-bin", "", "path to bench sink binary")
		outPath     = flag.String("out", "", "where to write the results JSON")
		ref         = flag.String("ref", "", "ref label to record in JSON (e.g. v1.3.0, HEAD)")
		commit      = flag.String("commit", "", "short commit SHA to record in JSON")
		only        = flag.String("scenarios", "", "comma-separated subset of scenario names to run; empty = all")
		transport   = flag.String("transport", "direct_post", "loopback transport: direct_post or direct_stream")
		showVerbose = flag.Bool("v", false, "stream child stdout/stderr to this process")
	)
	flag.Parse()

	if *clientBin == "" || *serverBin == "" || *sinkBin == "" || *outPath == "" {
		fmt.Fprintln(os.Stderr, "usage: harness --client-bin PATH --server-bin PATH --sink-bin PATH --out PATH [--ref X] [--commit Y] [--scenarios a,b] [--transport direct_post|direct_stream]")
		os.Exit(2)
	}
	if *transport != "direct_post" && *transport != "direct_stream" {
		log.Fatalf("invalid --transport %q", *transport)
	}

	scenarios := allScenarios()
	if *only != "" {
		want := map[string]bool{}
		for _, s := range strings.Split(*only, ",") {
			want[strings.TrimSpace(s)] = true
		}
		filtered := scenarios[:0]
		for _, s := range scenarios {
			if want[s.name] {
				filtered = append(filtered, s)
			}
		}
		scenarios = filtered
	}
	if len(scenarios) == 0 {
		log.Fatalf("no scenarios selected")
	}

	tmpDir, err := os.MkdirTemp("", "bench-harness-*")
	if err != nil {
		log.Fatalf("mkdir tmp: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	tunnelKey := mustHexKey()
	if err := writeConfigs(tmpDir, tunnelKey, *transport); err != nil {
		log.Fatalf("write configs: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sink, err := startProcess(ctx, *sinkBin, nil, *showVerbose, "sink")
	if err != nil {
		log.Fatalf("start sink: %v", err)
	}
	defer killProcess(sink)
	if err := waitTCP(ctx, sinkEcho, 10*time.Second); err != nil {
		log.Fatalf("sink readiness: %v", err)
	}

	server, err := startProcess(ctx, *serverBin,
		[]string{"-config", filepath.Join(tmpDir, "server_config.json")}, *showVerbose, "server")
	if err != nil {
		log.Fatalf("start server: %v", err)
	}
	defer killProcess(server)
	if err := waitTCP(ctx, fmt.Sprintf("127.0.0.1:%d", serverPort), 10*time.Second); err != nil {
		log.Fatalf("server readiness: %v", err)
	}

	client, err := startProcess(ctx, *clientBin,
		[]string{"-config", filepath.Join(tmpDir, "client_config.json")}, *showVerbose, "client")
	if err != nil {
		log.Fatalf("start client: %v", err)
	}
	defer killProcess(client)
	if err := waitTCP(ctx, fmt.Sprintf("127.0.0.1:%d", socksPort), 30*time.Second); err != nil {
		log.Fatalf("client readiness: %v", err)
	}

	// Confirm the SOCKS path is healthy end-to-end before we start measuring.
	dialer, err := proxy.SOCKS5("tcp", fmt.Sprintf("127.0.0.1:%d", socksPort), nil, proxy.Direct)
	if err != nil {
		log.Fatalf("socks5 dialer: %v", err)
	}
	if err := preflight(ctx, dialer); err != nil {
		log.Fatalf("preflight echo failed: %v", err)
	}

	env := &runEnv{
		dialer: dialer,
		dir:    tmpDir,
		server: server,
		client: client,
	}

	out := result{
		Ref:       *ref,
		Commit:    *commit,
		GoVersion: runtime.Version(),
		Host: host{
			OS:   runtime.GOOS,
			Arch: runtime.GOARCH,
			NCPU: runtime.NumCPU(),
		},
		StartedAt: time.Now().UTC().Format(time.RFC3339),
		Scenarios: map[string]json.RawMessage{},
	}
	t0 := time.Now()

	for _, s := range scenarios {
		log.Printf("scenario %s: running", s.name)
		sCtx, sCancel := context.WithTimeout(ctx, 5*time.Minute)
		val, err := s.run(sCtx, env)
		sCancel()
		if err != nil {
			log.Printf("scenario %s: FAILED: %v", s.name, err)
			out.Scenarios[s.name] = mustJSON(map[string]any{"error": err.Error()})
			continue
		}
		out.Scenarios[s.name] = mustJSON(val)
		log.Printf("scenario %s: %s", s.name, summarize(val))
	}
	out.DurationMS = time.Since(t0).Milliseconds()

	body, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		log.Fatalf("marshal results: %v", err)
	}
	if err := os.WriteFile(*outPath, append(body, '\n'), 0o644); err != nil {
		log.Fatalf("write results: %v", err)
	}
	log.Printf("wrote %s", *outPath)
}

func allScenarios() []scenario {
	// Sizes are tuned so a full run completes in ~90 s on a quiet laptop while
	// still being big enough to amortise carrier setup. Throughput numbers are
	// dominated by ActiveDrainWindow (~350 ms per HTTP round) — bigger payloads
	// don't change the ratio, just inflate wall clock.
	return []scenario{
		{"throughput_up_1MB_1session", scenarioThroughputUp(1 * 1024 * 1024)},
		{"throughput_up_8MB_1session", scenarioThroughputUp(8 * 1024 * 1024)},
		{"throughput_up_8MB_4sessions", scenarioThroughputUpConcurrent(8*1024*1024, 4)},
		{"throughput_down_8MB_1session", scenarioThroughputDown(8 * 1024 * 1024)},
		{"ttfb_p50_p95", scenarioTTFB(50)},
		{"sessions_per_sec", scenarioSessionsPerSec(10 * time.Second)},
		{"idle_overhead_15s", scenarioIdleOverhead(15*time.Second, 50)},
		{"mixed_stream_bad_syn_bulk", scenarioMixedStreamBadSYNBulk()},
	}
}

// ─── scenarios ──────────────────────────────────────────────────────────────

// uploadOnce sends `payload` bytes to the sized sink and waits for the 1-byte
// ACK that confirms the upstream has consumed everything. The protocol exists
// because VirtualConn doesn't support half-close — see bench/sink/main.go.
func uploadOnce(d proxy.Dialer, payload int) error {
	conn, err := d.Dial("tcp", sinkSized)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()

	var hdr [8]byte
	binary.BigEndian.PutUint64(hdr[:], uint64(payload))
	if _, err := conn.Write(hdr[:]); err != nil {
		return fmt.Errorf("write header: %w", err)
	}
	buf := make([]byte, 64*1024)
	remaining := payload
	for remaining > 0 {
		n := len(buf)
		if n > remaining {
			n = remaining
		}
		if _, err := conn.Write(buf[:n]); err != nil {
			return fmt.Errorf("write payload: %w", err)
		}
		remaining -= n
	}
	ack := make([]byte, 1)
	if _, err := io.ReadFull(conn, ack); err != nil {
		return fmt.Errorf("read ack: %w", err)
	}
	return nil
}

func scenarioThroughputUp(payload int) func(context.Context, *runEnv) (any, error) {
	return func(ctx context.Context, env *runEnv) (any, error) {
		t0 := time.Now()
		if err := uploadOnce(env.dialer, payload); err != nil {
			return nil, err
		}
		dur := time.Since(t0)
		return map[string]any{
			"bytes":       payload,
			"duration_ms": dur.Milliseconds(),
			"mb_per_sec":  bytesPerSecMB(payload, dur),
		}, nil
	}
}

func scenarioThroughputUpConcurrent(payloadEach int, n int) func(context.Context, *runEnv) (any, error) {
	return func(ctx context.Context, env *runEnv) (any, error) {
		var wg sync.WaitGroup
		errs := make(chan error, n)
		t0 := time.Now()
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if err := uploadOnce(env.dialer, payloadEach); err != nil {
					errs <- err
				}
			}()
		}
		wg.Wait()
		close(errs)
		dur := time.Since(t0)
		for err := range errs {
			if err != nil {
				return nil, err
			}
		}
		total := payloadEach * n
		return map[string]any{
			"sessions":          n,
			"bytes_per_session": payloadEach,
			"total_bytes":       total,
			"duration_ms":       dur.Milliseconds(),
			"mb_per_sec":        bytesPerSecMB(total, dur),
		}, nil
	}
}

func scenarioThroughputDown(payload int) func(context.Context, *runEnv) (any, error) {
	return func(ctx context.Context, env *runEnv) (any, error) {
		conn, err := env.dialer.Dial("tcp", sinkSource)
		if err != nil {
			return nil, fmt.Errorf("dial sink: %w", err)
		}
		defer conn.Close()
		var hdr [8]byte
		binary.BigEndian.PutUint64(hdr[:], uint64(payload))
		if _, err := conn.Write(hdr[:]); err != nil {
			return nil, fmt.Errorf("write header: %w", err)
		}
		buf := make([]byte, 128*1024)
		t0 := time.Now()
		remaining := payload
		for remaining > 0 {
			n, err := conn.Read(buf)
			if err != nil {
				return nil, fmt.Errorf("read: %w", err)
			}
			if n == 0 {
				return nil, errors.New("source returned 0 bytes without error")
			}
			remaining -= n
		}
		dur := time.Since(t0)
		return map[string]any{
			"bytes":       payload,
			"duration_ms": dur.Milliseconds(),
			"mb_per_sec":  bytesPerSecMB(payload, dur),
		}, nil
	}
}

func scenarioTTFB(n int) func(context.Context, *runEnv) (any, error) {
	return func(ctx context.Context, env *runEnv) (any, error) {
		samples := make([]int64, 0, n)
		ping := []byte{'p'}
		readBuf := make([]byte, 1)
		for i := 0; i < n; i++ {
			conn, err := env.dialer.Dial("tcp", sinkEcho)
			if err != nil {
				return nil, fmt.Errorf("dial[%d]: %w", i, err)
			}
			t0 := time.Now()
			if _, err := conn.Write(ping); err != nil {
				conn.Close()
				return nil, fmt.Errorf("write[%d]: %w", i, err)
			}
			if _, err := io.ReadFull(conn, readBuf); err != nil {
				conn.Close()
				return nil, fmt.Errorf("read[%d]: %w", i, err)
			}
			samples = append(samples, time.Since(t0).Microseconds())
			conn.Close()
		}
		return map[string]any{
			"n":       n,
			"p50_us":  percentile(samples, 50),
			"p95_us":  percentile(samples, 95),
			"p99_us":  percentile(samples, 99),
			"mean_us": meanInt64(samples),
		}, nil
	}
}

func scenarioSessionsPerSec(d time.Duration) func(context.Context, *runEnv) (any, error) {
	return func(ctx context.Context, env *runEnv) (any, error) {
		end := time.Now().Add(d)
		var ok int64
		var fail int64
		buf := make([]byte, 1)
		t0 := time.Now()
		for time.Now().Before(end) {
			conn, err := env.dialer.Dial("tcp", sinkQuick)
			if err != nil {
				atomic.AddInt64(&fail, 1)
				continue
			}
			if _, err := io.ReadFull(conn, buf); err != nil {
				atomic.AddInt64(&fail, 1)
				conn.Close()
				continue
			}
			conn.Close()
			atomic.AddInt64(&ok, 1)
		}
		dur := time.Since(t0)
		secs := dur.Seconds()
		rate := 0.0
		if secs > 0 {
			rate = float64(ok) / secs
		}
		return map[string]any{
			"ok":          ok,
			"fail":        fail,
			"duration_ms": dur.Milliseconds(),
			"per_sec":     round2(rate),
		}, nil
	}
}

func scenarioIdleOverhead(d time.Duration, sessions int) func(context.Context, *runEnv) (any, error) {
	return func(ctx context.Context, env *runEnv) (any, error) {
		// Open `sessions` echo connections and let them sit idle so we measure
		// the cost of the carrier's idle long-poll loop, not just an empty client.
		conns := make([]net.Conn, 0, sessions)
		defer func() {
			for _, c := range conns {
				_ = c.Close()
			}
		}()
		for i := 0; i < sessions; i++ {
			c, err := env.dialer.Dial("tcp", sinkEcho)
			if err != nil {
				return nil, fmt.Errorf("dial[%d]: %w", i, err)
			}
			conns = append(conns, c)
		}

		clientPID := env.client.Process.Pid
		serverPID := env.server.Process.Pid

		// Discard the first sample on each side: it's a noisy initialization
		// snapshot, not the steady-state cost.
		_ = sampleCPU(clientPID)
		_ = sampleCPU(serverPID)

		var clientCPU, serverCPU []float64
		tick := time.NewTicker(500 * time.Millisecond)
		defer tick.Stop()
		end := time.Now().Add(d)
		for time.Now().Before(end) {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-tick.C:
				clientCPU = append(clientCPU, sampleCPU(clientPID))
				serverCPU = append(serverCPU, sampleCPU(serverPID))
			}
		}
		return map[string]any{
			"sessions":        sessions,
			"duration_ms":     d.Milliseconds(),
			"samples":         len(clientCPU),
			"client_cpu_mean": round2(meanFloat(clientCPU)),
			"client_cpu_max":  round2(maxFloat(clientCPU)),
			"server_cpu_mean": round2(meanFloat(serverCPU)),
			"server_cpu_max":  round2(maxFloat(serverCPU)),
		}, nil
	}
}

// ─── child-process management ───────────────────────────────────────────────

func scenarioMixedStreamBadSYNBulk() func(context.Context, *runEnv) (any, error) {
	return func(ctx context.Context, env *runEnv) (any, error) {
		t0 := time.Now()
		badStarted := make(chan struct{})
		go func() {
			close(badStarted)
			conn, err := env.dialer.Dial("tcp", "10.255.255.1:81")
			if err == nil {
				_ = conn.Close()
			}
		}()
		select {
		case <-badStarted:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		// Let the bad CONNECT enqueue first. If direct-stream SYN routing ever
		// becomes serial again, the echo/download work below stalls behind this
		// target until the upstream dial timeout fires.
		time.Sleep(100 * time.Millisecond)

		bulkCh := make(chan struct {
			val any
			err error
		}, 1)
		go func() {
			val, err := scenarioThroughputDown(1*1024*1024)(ctx, env)
			bulkCh <- struct {
				val any
				err error
			}{val: val, err: err}
		}()

		ttfb, err := scenarioTTFB(20)(ctx, env)
		if err != nil {
			return nil, fmt.Errorf("ttfb under bad SYN/bulk mix: %w", err)
		}
		var bulk any
		select {
		case got := <-bulkCh:
			if got.err != nil {
				return nil, fmt.Errorf("download under bad SYN mix: %w", got.err)
			}
			bulk = got.val
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		return map[string]any{
			"duration_ms": time.Since(t0).Milliseconds(),
			"ttfb":        ttfb,
			"download":    bulk,
		}, nil
	}
}

func startProcess(ctx context.Context, bin string, args []string, verbose bool, label string) (*exec.Cmd, error) {
	cmd := exec.CommandContext(ctx, bin, args...)
	// Stdout is suppressed unless --verbose; stderr is always streamed so a
	// child failure (port collision, key mismatch, etc.) is visible.
	cmd.Stdout = labelWriter(os.Stdout, label, verbose)
	cmd.Stderr = labelWriter(os.Stderr, label, true)
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return cmd, nil
}

func killProcess(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	_ = cmd.Process.Signal(os.Interrupt)
	done := make(chan struct{})
	go func() {
		_ = cmd.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		_ = cmd.Process.Kill()
		<-done
	}
}

func labelWriter(under *os.File, label string, verbose bool) io.Writer {
	if !verbose {
		return io.Discard
	}
	pr, pw := io.Pipe()
	go func() {
		s := bufio.NewScanner(pr)
		s.Buffer(make([]byte, 64*1024), 1024*1024)
		for s.Scan() {
			fmt.Fprintf(under, "[%s] %s\n", label, s.Text())
		}
	}()
	return pw
}

func waitTCP(ctx context.Context, addr string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		if time.Now().After(deadline) {
			return fmt.Errorf("timed out waiting for %s", addr)
		}
		c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			c.Close()
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func preflight(ctx context.Context, d proxy.Dialer) error {
	deadline := time.Now().Add(10 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		conn, err := d.Dial("tcp", sinkEcho)
		if err == nil {
			defer conn.Close()
			if _, err := conn.Write([]byte{'X'}); err != nil {
				lastErr = err
			} else {
				buf := make([]byte, 1)
				if _, err := io.ReadFull(conn, buf); err == nil && buf[0] == 'X' {
					return nil
				} else {
					lastErr = err
				}
			}
		} else {
			lastErr = err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
	return fmt.Errorf("preflight echo never succeeded: %v", lastErr)
}

// sampleCPU runs `ps -o %cpu= -p PID` and returns the parsed value. Cross-platform
// on macOS and Linux. Returns 0 on parse error rather than failing the scenario,
// since a single missed sample is fine for a regression-detection metric.
func sampleCPU(pid int) float64 {
	out, err := exec.Command("ps", "-o", "%cpu=", "-p", strconv.Itoa(pid)).Output()
	if err != nil {
		return 0
	}
	v, err := strconv.ParseFloat(strings.TrimSpace(string(out)), 64)
	if err != nil {
		return 0
	}
	return v
}

// ─── config + crypto helpers ────────────────────────────────────────────────

func mustHexKey() string {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		log.Fatalf("rand: %v", err)
	}
	return hex.EncodeToString(b[:])
}

func writeConfigs(dir, tunnelKey, transport string) error {
	serverCfg := map[string]any{
		"server_host": "127.0.0.1",
		"server_port": serverPort,
		"tunnel_key":  tunnelKey,
	}
	clientCfg := map[string]any{
		"socks_host":   "127.0.0.1",
		"socks_port":   socksPort,
		"tunnel_key":   tunnelKey,
		"debug_timing": false,
		"auto_tune":    false,
	}
	if transport == "direct_stream" {
		clientCfg["transport_mode"] = "direct_stream"
		clientCfg["direct_stream_urls"] = []string{fmt.Sprintf("ws://127.0.0.1:%d/stream", serverPort)}
	} else {
		clientCfg["transport_mode"] = "direct_post"
		clientCfg["relay_urls"] = []string{fmt.Sprintf("http://127.0.0.1:%d/tunnel", serverPort)}
	}
	if err := writeJSON(filepath.Join(dir, "server_config.json"), serverCfg); err != nil {
		return err
	}
	if err := writeJSON(filepath.Join(dir, "client_config.json"), clientCfg); err != nil {
		return err
	}
	return nil
}

func writeJSON(path string, v any) error {
	body, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(body, '\n'), 0o600)
}

// ─── stats helpers ──────────────────────────────────────────────────────────

func bytesPerSecMB(n int, d time.Duration) float64 {
	if d <= 0 {
		return 0
	}
	return round2(float64(n) / d.Seconds() / (1024 * 1024))
}

func percentile(samples []int64, p int) int64 {
	if len(samples) == 0 {
		return 0
	}
	sorted := append([]int64(nil), samples...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	idx := (p * (len(sorted) - 1)) / 100
	return sorted[idx]
}

func meanInt64(samples []int64) int64 {
	if len(samples) == 0 {
		return 0
	}
	var s int64
	for _, v := range samples {
		s += v
	}
	return s / int64(len(samples))
}

func meanFloat(samples []float64) float64 {
	if len(samples) == 0 {
		return 0
	}
	s := 0.0
	for _, v := range samples {
		s += v
	}
	return s / float64(len(samples))
}

func maxFloat(samples []float64) float64 {
	if len(samples) == 0 {
		return 0
	}
	m := samples[0]
	for _, v := range samples[1:] {
		if v > m {
			m = v
		}
	}
	return m
}

func round2(v float64) float64 {
	return float64(int(v*100+0.5)) / 100
}

func mustJSON(v any) json.RawMessage {
	body, err := json.Marshal(v)
	if err != nil {
		return json.RawMessage(fmt.Sprintf(`{"_marshal_error":%q}`, err.Error()))
	}
	return body
}

func summarize(v any) string {
	body, err := json.Marshal(v)
	if err != nil {
		return "?"
	}
	return string(body)
}
