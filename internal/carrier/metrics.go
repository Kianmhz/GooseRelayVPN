package carrier

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// pollRTTRing is a fixed-size ring buffer of recent successful poll RTTs.
// Exposing percentiles (p50/p90/p99) is significantly more useful for
// operators than a single average — tail latency is what users feel during
// streaming, not the mean.
const pollRTTRing = 256

type pollRTTHistogram struct {
	mu     sync.Mutex
	buf    [pollRTTRing]time.Duration
	cursor int
	count  int
}

func (h *pollRTTHistogram) record(d time.Duration) {
	h.mu.Lock()
	h.buf[h.cursor%pollRTTRing] = d
	h.cursor++
	if h.count < pollRTTRing {
		h.count++
	}
	h.mu.Unlock()
}

// percentiles returns p50, p90, p99 of recent samples in milliseconds.
// Returns three zeros if no samples have been recorded yet.
func (h *pollRTTHistogram) percentiles() (p50, p90, p99 time.Duration) {
	h.mu.Lock()
	if h.count == 0 {
		h.mu.Unlock()
		return 0, 0, 0
	}
	samples := make([]time.Duration, h.count)
	copy(samples, h.buf[:h.count])
	h.mu.Unlock()
	sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
	pick := func(p float64) time.Duration {
		idx := int(float64(len(samples)-1) * p)
		return samples[idx]
	}
	return pick(0.50), pick(0.90), pick(0.99)
}

func (c *Client) recordPollRTT(d time.Duration) {
	c.pollRTT.record(d)
}

// MetricsHandler returns a Prometheus-style /metrics handler that surfaces
// counters, gauges, and poll-RTT percentiles. Mount it via
// StartLocalMetrics(addr) or attach to your own mux.
func (c *Client) MetricsHandler() http.Handler {
	startedAt := time.Now()
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		var b strings.Builder

		fmt.Fprintf(&b, "# HELP goose_client_uptime_seconds Carrier uptime.\n# TYPE goose_client_uptime_seconds counter\n")
		fmt.Fprintf(&b, "goose_client_uptime_seconds %d\n", int64(time.Since(startedAt).Seconds()))

		fmt.Fprintf(&b, "# HELP goose_client_polls_ok_total Successful polls.\n# TYPE goose_client_polls_ok_total counter\n")
		fmt.Fprintf(&b, "goose_client_polls_ok_total %d\n", c.stats.pollsOK.Load())
		fmt.Fprintf(&b, "# HELP goose_client_polls_fail_total Failed polls.\n# TYPE goose_client_polls_fail_total counter\n")
		fmt.Fprintf(&b, "goose_client_polls_fail_total %d\n", c.stats.pollsFail.Load())

		fmt.Fprintf(&b, "# HELP goose_client_frames_out_total Frames sent to server.\n# TYPE goose_client_frames_out_total counter\n")
		fmt.Fprintf(&b, "goose_client_frames_out_total %d\n", c.stats.framesOut.Load())
		fmt.Fprintf(&b, "# HELP goose_client_frames_in_total Frames received from server.\n# TYPE goose_client_frames_in_total counter\n")
		fmt.Fprintf(&b, "goose_client_frames_in_total %d\n", c.stats.framesIn.Load())
		fmt.Fprintf(&b, "# HELP goose_client_bytes_out_total Bytes sent to server.\n# TYPE goose_client_bytes_out_total counter\n")
		fmt.Fprintf(&b, "goose_client_bytes_out_total %d\n", c.stats.bytesOut.Load())
		fmt.Fprintf(&b, "# HELP goose_client_bytes_in_total Bytes received from server.\n# TYPE goose_client_bytes_in_total counter\n")
		fmt.Fprintf(&b, "goose_client_bytes_in_total %d\n", c.stats.bytesIn.Load())

		fmt.Fprintf(&b, "# HELP goose_client_sessions_open_total Sessions opened.\n# TYPE goose_client_sessions_open_total counter\n")
		fmt.Fprintf(&b, "goose_client_sessions_open_total %d\n", c.stats.sessionsOpen.Load())
		fmt.Fprintf(&b, "# HELP goose_client_sessions_close_total Sessions closed.\n# TYPE goose_client_sessions_close_total counter\n")
		fmt.Fprintf(&b, "goose_client_sessions_close_total %d\n", c.stats.sessionsClose.Load())
		fmt.Fprintf(&b, "# HELP goose_client_rst_from_server_total RSTs received from the server.\n# TYPE goose_client_rst_from_server_total counter\n")
		fmt.Fprintf(&b, "goose_client_rst_from_server_total %d\n", c.stats.rstFromServer.Load())

		c.mu.Lock()
		active := len(c.sessions)
		txReady := len(c.txReady)
		c.mu.Unlock()
		fmt.Fprintf(&b, "# HELP goose_client_sessions_active Current active sessions.\n# TYPE goose_client_sessions_active gauge\n")
		fmt.Fprintf(&b, "goose_client_sessions_active %d\n", active)
		fmt.Fprintf(&b, "# HELP goose_client_sessions_tx_ready Sessions with pending tx frames.\n# TYPE goose_client_sessions_tx_ready gauge\n")
		fmt.Fprintf(&b, "goose_client_sessions_tx_ready %d\n", txReady)

		// Poll RTT percentiles.
		p50, p90, p99 := c.pollRTT.percentiles()
		fmt.Fprintf(&b, "# HELP goose_client_poll_rtt_ms Poll RTT percentiles (recent ring of 256 samples).\n# TYPE goose_client_poll_rtt_ms gauge\n")
		fmt.Fprintf(&b, "goose_client_poll_rtt_ms{q=\"0.5\"} %d\n", p50.Milliseconds())
		fmt.Fprintf(&b, "goose_client_poll_rtt_ms{q=\"0.9\"} %d\n", p90.Milliseconds())
		fmt.Fprintf(&b, "goose_client_poll_rtt_ms{q=\"0.99\"} %d\n", p99.Milliseconds())

		// Per-endpoint EWMA RTT.
		c.endpointMu.Lock()
		fmt.Fprintf(&b, "# HELP goose_client_endpoint_rtt_ms_ewma Per-endpoint EWMA RTT for power-of-two-choices selection.\n# TYPE goose_client_endpoint_rtt_ms_ewma gauge\n")
		for i := range c.endpoints {
			ep := &c.endpoints[i]
			label := shortScriptKey(ep.url)
			fmt.Fprintf(&b, "goose_client_endpoint_rtt_ms_ewma{endpoint=%q} %d\n", label, ep.ewmaRTT.Milliseconds())
			fmt.Fprintf(&b, "goose_client_endpoint_ok_total{endpoint=%q} %d\n", label, ep.statsOK)
			fmt.Fprintf(&b, "goose_client_endpoint_fail_total{endpoint=%q} %d\n", label, ep.statsFail)
		}
		c.endpointMu.Unlock()

		_, _ = w.Write([]byte(b.String()))
	})
}

// StartLocalMetrics starts a localhost-only HTTP listener serving /metrics
// at the given addr. Returns an error if the listener cannot bind. The
// listener is shut down when ctx is cancelled.
func (c *Client) StartLocalMetrics(ctx context.Context, addr string) error {
	mux := http.NewServeMux()
	mux.Handle("/metrics", c.MetricsHandler())
	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()
	go func() {
		log.Printf("[carrier] /metrics listening on %s", addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("[carrier] /metrics server: %v", err)
		}
	}()
	return nil
}
