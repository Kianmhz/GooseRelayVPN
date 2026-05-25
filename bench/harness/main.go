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
	"net/http"
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
	socksPort           = 11080
	serverPort          = 18443
	impairmentProxyPort = 18444

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
	Ref               string                     `json:"ref"`
	Commit            string                     `json:"commit"`
	GoVersion         string                     `json:"go_version"`
	Host              host                       `json:"host"`
	Metadata          benchMetadata              `json:"metadata"`
	StartedAt         string                     `json:"started_at"`
	DurationMS        int64                      `json:"duration_ms"`
	ScenarioSubset    bool                       `json:"scenario_subset"`
	SelectedScenarios []string                   `json:"selected_scenarios,omitempty"`
	Scenarios         map[string]json.RawMessage `json:"scenarios"`
}

type scenario struct {
	name string
	run  func(context.Context, *runEnv) (any, error)
}

type benchMetadata struct {
	Transport  string         `json:"transport"`
	Impairment string         `json:"impairment"`
	Config     map[string]any `json:"config"`
}

func benchmarkMetadataFor(transport string, impairment impairmentProfile) benchMetadata {
	impairmentName := strings.TrimSpace(impairment.Name)
	if impairmentName == "" {
		impairmentName = "none"
	}
	return benchMetadata{
		Transport:  transport,
		Impairment: impairmentName,
		Config: map[string]any{
			"socks_port":       socksPort,
			"server_port":      serverPort,
			"impairment_port":  impairmentProxyPort,
			"auto_tune":        false,
			"debug_timing":     false,
			"loopback_profile": true,
		},
	}
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
		ref         = flag.String("ref", "", "ref label to record in JSON (e.g. v1.6.0, HEAD)")
		commit      = flag.String("commit", "", "short commit SHA to record in JSON")
		only        = flag.String("scenarios", "", "comma-separated subset of scenario names to run; empty = all")
		transport   = flag.String("transport", "direct_post", "loopback transport: direct_post or direct_stream")
		impairment  = flag.String("impairment", "", "optional direct_post impairment profile: mobile, lossy, quota")
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
	impairmentProfile, err := parseImpairmentProfile(*impairment)
	if err != nil {
		log.Fatal(err)
	}
	if impairmentProfile.Enabled() && *transport != "direct_post" {
		log.Fatalf("--impairment requires --transport direct_post")
	}

	scenarios, err := selectScenarios(allScenarios(), *only)
	if err != nil {
		log.Fatal(err)
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
	if err := writeConfigs(tmpDir, tunnelKey, *transport, impairmentProfile.Enabled()); err != nil {
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
	var impairmentSrv *http.Server
	if impairmentProfile.Enabled() {
		impairmentSrv, err = startImpairmentProxy(ctx, fmt.Sprintf("127.0.0.1:%d", impairmentProxyPort), fmt.Sprintf("http://127.0.0.1:%d", serverPort), impairmentProfile)
		if err != nil {
			log.Fatalf("start impairment proxy: %v", err)
		}
		defer func() {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), time.Second)
			_ = impairmentSrv.Shutdown(shutdownCtx)
			cancel()
		}()
		if err := waitTCP(ctx, fmt.Sprintf("127.0.0.1:%d", impairmentProxyPort), 10*time.Second); err != nil {
			log.Fatalf("impairment proxy readiness: %v", err)
		}
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
		Metadata:       benchmarkMetadataFor(*transport, impairmentProfile),
		StartedAt:      time.Now().UTC().Format(time.RFC3339),
		ScenarioSubset: strings.TrimSpace(*only) != "",
		Scenarios:      map[string]json.RawMessage{},
	}
	for _, s := range scenarios {
		out.SelectedScenarios = append(out.SelectedScenarios, s.name)
	}
	t0 := time.Now()
	failures := 0

	for _, s := range scenarios {
		log.Printf("scenario %s: running", s.name)
		sCtx, sCancel := context.WithTimeout(ctx, 5*time.Minute)
		val, err := s.run(sCtx, env)
		sCancel()
		if err != nil {
			log.Printf("scenario %s: FAILED: %v", s.name, err)
			out.Scenarios[s.name] = mustJSON(map[string]any{"error": err.Error()})
			failures++
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
	if failures > 0 {
		log.Fatalf("%d scenario(s) failed", failures)
	}
}

func allScenarios() []scenario {
	// Sizes are tuned so a full run completes in ~90 s on a quiet laptop while
	// still being big enough to amortise carrier setup. Throughput numbers are
	// dominated by ActiveDrainWindow (~150 ms per HTTP round) — bigger payloads
	// don't change the ratio, just inflate wall clock.
	return []scenario{
		{"throughput_up_1MB_1session", scenarioThroughputUp(1 * 1024 * 1024)},
		{"throughput_up_8MB_1session", scenarioThroughputUp(8 * 1024 * 1024)},
		{"throughput_up_8MB_4sessions", scenarioThroughputUpConcurrent(8*1024*1024, 4)},
		{"throughput_down_8MB_1session", scenarioThroughputDown(8 * 1024 * 1024)},
		{"download_first_byte_8MB", scenarioDownloadFirstByte(8 * 1024 * 1024)},
		{"download_first_byte_16MB", scenarioDownloadFirstByte(16 * 1024 * 1024)},
		{"download_pause_at_97pct_8MB", scenarioDownloadPauseAt(8*1024*1024, 97, time.Second)},
		{"ttfb_p50_p95", scenarioTTFB(50)},
		{"ttfb_under_8MB_download", scenarioTTFBUnderDownload(8*1024*1024, 30)},
		{"browsing_latency_while_download_active", scenarioTTFBUnderDownload(8*1024*1024, 30)},
		{"sessions_per_sec", scenarioSessionsPerSec(10 * time.Second)},
		{"idle_overhead_15s", scenarioIdleOverhead(15*time.Second, 50)},
		{"mixed_stream_bad_syn_bulk", scenarioMixedStreamBadSYNBulk()},
	}
}

func selectScenarios(available []scenario, only string) ([]scenario, error) {
	only = strings.TrimSpace(only)
	if only == "" {
		return available, nil
	}
	want := map[string]bool{}
	for _, name := range strings.Split(only, ",") {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		want[name] = true
	}
	filtered := available[:0]
	for _, s := range available {
		if want[s.name] {
			filtered = append(filtered, s)
			delete(want, s.name)
		}
	}
	if len(want) > 0 {
		var unknown []string
		for name := range want {
			unknown = append(unknown, name)
		}
		sort.Strings(unknown)
		return nil, fmt.Errorf("unknown benchmark scenario(s): %s", strings.Join(unknown, ", "))
	}
	return filtered, nil
}

type impairmentProfile struct {
	Name                string
	BaseDelay           time.Duration
	JitterStep          time.Duration
	JitterSlots         int
	TransientErrorEvery int64
	RateLimitEvery      int64
	DailyQuotaEvery     int64
}

func (p impairmentProfile) Enabled() bool {
	return p.Name != ""
}

func (p impairmentProfile) DelayForRequest(n int64) time.Duration {
	if !p.Enabled() || n <= 0 {
		return 0
	}
	delay := p.BaseDelay
	if p.JitterStep > 0 && p.JitterSlots > 0 {
		slot := n % int64(p.JitterSlots)
		delay += time.Duration(slot) * p.JitterStep
	}
	return delay
}

func parseImpairmentProfile(name string) (impairmentProfile, error) {
	name = strings.TrimSpace(strings.ToLower(name))
	switch name {
	case "", "none", "off":
		return impairmentProfile{}, nil
	case "mobile":
		return impairmentProfile{
			Name:        name,
			BaseDelay:   250 * time.Millisecond,
			JitterStep:  75 * time.Millisecond,
			JitterSlots: 5,
		}, nil
	case "lossy":
		return impairmentProfile{
			Name:                name,
			BaseDelay:           80 * time.Millisecond,
			JitterStep:          40 * time.Millisecond,
			JitterSlots:         4,
			TransientErrorEvery: 7,
		}, nil
	case "quota":
		return impairmentProfile{
			Name:            name,
			BaseDelay:       150 * time.Millisecond,
			JitterStep:      50 * time.Millisecond,
			JitterSlots:     3,
			RateLimitEvery:  5,
			DailyQuotaEvery: 13,
		}, nil
	default:
		return impairmentProfile{}, fmt.Errorf("unknown impairment profile %q (valid: mobile, lossy, quota)", name)
	}
}

func startImpairmentProxy(ctx context.Context, listenAddr, upstreamBase string, profile impairmentProfile) (*http.Server, error) {
	handler := newImpairmentHandler(strings.TrimRight(upstreamBase, "/"), profile)
	srv := &http.Server{Addr: listenAddr, Handler: handler}
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return nil, err
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		_ = srv.Shutdown(shutdownCtx)
		cancel()
	}()
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("impairment proxy stopped: %v", err)
		}
	}()
	return srv, nil
}

func newImpairmentHandler(upstreamBase string, profile impairmentProfile) http.Handler {
	var seq atomic.Int64
	client := &http.Client{Timeout: 30 * time.Second}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := seq.Add(1)
		if delay := profile.DelayForRequest(n); delay > 0 {
			time.Sleep(delay)
		}
		switch {
		case profile.DailyQuotaEvery > 0 && n%profile.DailyQuotaEvery == 0:
			w.WriteHeader(http.StatusForbidden)
			_, _ = io.WriteString(w, "Exception: Service invoked too many times: UrlFetch.")
			return
		case profile.RateLimitEvery > 0 && n%profile.RateLimitEvery == 0:
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = io.WriteString(w, "Exception: Service invoked too many times in a short time: UrlFetch.")
			return
		case profile.TransientErrorEvery > 0 && n%profile.TransientErrorEvery == 0:
			w.WriteHeader(http.StatusBadGateway)
			_, _ = io.WriteString(w, "simulated dropped response")
			return
		}
		req, err := http.NewRequestWithContext(r.Context(), r.Method, upstreamBase+r.URL.RequestURI(), r.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadGateway)
			_, _ = io.WriteString(w, err.Error())
			return
		}
		req.Header = r.Header.Clone()
		resp, err := client.Do(req)
		if err != nil {
			w.WriteHeader(http.StatusBadGateway)
			_, _ = io.WriteString(w, err.Error())
			return
		}
		defer resp.Body.Close()
		for k, vals := range resp.Header {
			for _, v := range vals {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	})
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

func scenarioDownloadFirstByte(payload int) func(context.Context, *runEnv) (any, error) {
	return func(ctx context.Context, env *runEnv) (any, error) {
		conn, err := env.dialer.Dial("tcp", sinkSource)
		if err != nil {
			return nil, fmt.Errorf("dial sink: %w", err)
		}
		defer conn.Close()

		var hdr [8]byte
		binary.BigEndian.PutUint64(hdr[:], uint64(payload))
		start := time.Now()
		if _, err := conn.Write(hdr[:]); err != nil {
			return nil, fmt.Errorf("write header: %w", err)
		}

		buf := make([]byte, 128*1024)
		n, err := conn.Read(buf)
		if err != nil {
			return nil, fmt.Errorf("read first byte: %w", err)
		}
		if n == 0 {
			return nil, errors.New("source returned 0 bytes without error")
		}
		firstByte := time.Since(start)
		remaining := payload - n
		for remaining > 0 {
			n, err := conn.Read(buf)
			if err != nil {
				return nil, fmt.Errorf("read remainder: %w", err)
			}
			if n == 0 {
				return nil, errors.New("source returned 0 bytes without error")
			}
			remaining -= n
		}
		total := time.Since(start)
		return map[string]any{
			"bytes":         payload,
			"first_byte_us": firstByte.Microseconds(),
			"duration_ms":   total.Milliseconds(),
			"mb_per_sec":    bytesPerSecMB(payload, total),
		}, nil
	}
}

func scenarioDownloadPauseAt(payload int, pausePercent int, pauseFor time.Duration) func(context.Context, *runEnv) (any, error) {
	return func(ctx context.Context, env *runEnv) (any, error) {
		conn, err := env.dialer.Dial("tcp", sinkSource)
		if err != nil {
			return nil, fmt.Errorf("dial sink: %w", err)
		}
		defer conn.Close()

		var hdr [8]byte
		binary.BigEndian.PutUint64(hdr[:], uint64(payload))
		start := time.Now()
		if _, err := conn.Write(hdr[:]); err != nil {
			return nil, fmt.Errorf("write header: %w", err)
		}

		pauseAt := payload * pausePercent / 100
		buf := make([]byte, 128*1024)
		read := 0
		var firstByte time.Duration
		for read < pauseAt {
			n, err := conn.Read(buf)
			if err != nil {
				return nil, fmt.Errorf("read before pause: %w", err)
			}
			if n == 0 {
				return nil, errors.New("source returned 0 bytes without error")
			}
			if read == 0 {
				firstByte = time.Since(start)
			}
			read += n
		}
		beforePause := time.Since(start)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(pauseFor):
		}
		postPauseBytes := payload - read
		afterPauseStart := time.Now()
		for read < payload {
			n, err := conn.Read(buf)
			if err != nil {
				return nil, fmt.Errorf("read after pause: %w", err)
			}
			if n == 0 {
				return nil, errors.New("source returned 0 bytes without error")
			}
			read += n
		}
		afterPause := time.Since(afterPauseStart)
		total := time.Since(start)
		return map[string]any{
			"bytes":             payload,
			"pause_percent":     pausePercent,
			"pause_ms":          pauseFor.Milliseconds(),
			"first_byte_us":     firstByte.Microseconds(),
			"before_pause_ms":   beforePause.Milliseconds(),
			"after_pause_ms":    afterPause.Milliseconds(),
			"duration_ms":       total.Milliseconds(),
			"effective_mb_sec":  bytesPerSecMB(payload, total),
			"post_pause_mb_sec": bytesPerSecMB(postPauseBytes, afterPause),
		}, nil
	}
}

func scenarioTTFBUnderDownload(payload int, samples int) func(context.Context, *runEnv) (any, error) {
	return func(ctx context.Context, env *runEnv) (any, error) {
		type scenarioResult struct {
			val any
			err error
		}
		stopLoad := make(chan struct{})
		loadDone := make(chan scenarioResult, 1)
		var downloadsCompleted int64
		go func() {
			var last any
			for {
				select {
				case <-stopLoad:
					loadDone <- scenarioResult{val: last}
					return
				default:
				}
				val, err := scenarioThroughputDown(payload)(ctx, env)
				if err != nil {
					loadDone <- scenarioResult{err: err}
					return
				}
				last = val
				atomic.AddInt64(&downloadsCompleted, 1)
			}
		}()

		time.Sleep(100 * time.Millisecond)
		ttfb, err := scenarioTTFB(samples)(ctx, env)
		close(stopLoad)
		if err != nil {
			select {
			case <-loadDone:
			case <-ctx.Done():
			}
			return nil, fmt.Errorf("ttfb while download active: %w", err)
		}

		select {
		case got := <-loadDone:
			if got.err != nil {
				return nil, fmt.Errorf("download load: %w", got.err)
			}
			return map[string]any{
				"download_bytes":      payload,
				"downloads_completed": atomic.LoadInt64(&downloadsCompleted),
				"ttfb":                ttfb,
				"last_download":       got.val,
			}, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
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
		_, _ = sampleCPU(clientPID)
		_, _ = sampleCPU(serverPID)

		var clientCPU, serverCPU []float64
		tick := time.NewTicker(500 * time.Millisecond)
		defer tick.Stop()
		end := time.Now().Add(d)
		for time.Now().Before(end) {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-tick.C:
				if v, ok := sampleCPU(clientPID); ok {
					clientCPU = append(clientCPU, v)
				}
				if v, ok := sampleCPU(serverPID); ok {
					serverCPU = append(serverCPU, v)
				}
			}
		}
		out := map[string]any{
			"sessions":    sessions,
			"duration_ms": d.Milliseconds(),
			"samples":     max(len(clientCPU), len(serverCPU)),
		}
		if len(clientCPU) > 0 && len(serverCPU) > 0 {
			out["client_cpu_mean"] = round2(meanFloat(clientCPU))
			out["client_cpu_max"] = round2(maxFloat(clientCPU))
			out["server_cpu_mean"] = round2(meanFloat(serverCPU))
			out["server_cpu_max"] = round2(maxFloat(serverCPU))
		} else {
			out["cpu_unavailable"] = true
		}
		return out, nil
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

// sampleCPU runs `ps -o %cpu= -p PID` and returns the parsed value. It is
// available on macOS/Linux; on Windows or missing `ps`, callers omit CPU metrics
// rather than silently recording zero.
func sampleCPU(pid int) (float64, bool) {
	out, err := exec.Command("ps", "-o", "%cpu=", "-p", strconv.Itoa(pid)).Output()
	if err != nil {
		return 0, false
	}
	v, err := strconv.ParseFloat(strings.TrimSpace(string(out)), 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

// ─── config + crypto helpers ────────────────────────────────────────────────

func mustHexKey() string {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		log.Fatalf("rand: %v", err)
	}
	return hex.EncodeToString(b[:])
}

func writeConfigs(dir, tunnelKey, transport string, impaired bool) error {
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
		relayPort := serverPort
		if impaired {
			relayPort = impairmentProxyPort
		}
		clientCfg["transport_mode"] = "direct_post"
		clientCfg["relay_urls"] = []string{fmt.Sprintf("http://127.0.0.1:%d/tunnel", relayPort)}
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
