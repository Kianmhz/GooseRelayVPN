package exit

import (
	"fmt"
	"net/http"
	"strings"
	"time"
)

// metricsHandler returns a Prometheus-style text-format /metrics handler.
// Surfaced on the same port as /tunnel and /healthz; ops scrapers should be
// firewalled from the public internet (the listener already only binds to
// the configured ListenAddr, so put it on a private interface).
func (s *Server) metricsHandler() http.Handler {
	startedAt := time.Now()
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		var b strings.Builder
		// Process-level
		fmt.Fprintf(&b, "# HELP goose_uptime_seconds Server uptime in seconds.\n")
		fmt.Fprintf(&b, "# TYPE goose_uptime_seconds counter\n")
		fmt.Fprintf(&b, "goose_uptime_seconds %d\n", int64(time.Since(startedAt).Seconds()))

		// Counters
		fmt.Fprintf(&b, "# HELP goose_requests_total Total /tunnel requests handled.\n# TYPE goose_requests_total counter\n")
		fmt.Fprintf(&b, "goose_requests_total %d\n", s.stats.requests.Load())
		fmt.Fprintf(&b, "# HELP goose_frames_in_total Frames decoded from clients.\n# TYPE goose_frames_in_total counter\n")
		fmt.Fprintf(&b, "goose_frames_in_total %d\n", s.stats.framesIn.Load())
		fmt.Fprintf(&b, "# HELP goose_frames_out_total Frames sent to clients.\n# TYPE goose_frames_out_total counter\n")
		fmt.Fprintf(&b, "goose_frames_out_total %d\n", s.stats.framesOut.Load())
		fmt.Fprintf(&b, "# HELP goose_bytes_in_total Bytes received from clients (payload only).\n# TYPE goose_bytes_in_total counter\n")
		fmt.Fprintf(&b, "goose_bytes_in_total %d\n", s.stats.bytesIn.Load())
		fmt.Fprintf(&b, "# HELP goose_bytes_out_total Bytes sent to clients (payload only).\n# TYPE goose_bytes_out_total counter\n")
		fmt.Fprintf(&b, "goose_bytes_out_total %d\n", s.stats.bytesOut.Load())
		fmt.Fprintf(&b, "# HELP goose_sessions_opened_total Sessions opened.\n# TYPE goose_sessions_opened_total counter\n")
		fmt.Fprintf(&b, "goose_sessions_opened_total %d\n", s.stats.sessionsOpen.Load())
		fmt.Fprintf(&b, "# HELP goose_sessions_closed_total Sessions closed.\n# TYPE goose_sessions_closed_total counter\n")
		fmt.Fprintf(&b, "goose_sessions_closed_total %d\n", s.stats.sessionsClose.Load())
		fmt.Fprintf(&b, "# HELP goose_dials_ok_total Successful upstream dials.\n# TYPE goose_dials_ok_total counter\n")
		fmt.Fprintf(&b, "goose_dials_ok_total %d\n", s.stats.dialsOK.Load())
		fmt.Fprintf(&b, "# HELP goose_dials_fail_total Failed upstream dials.\n# TYPE goose_dials_fail_total counter\n")
		fmt.Fprintf(&b, "goose_dials_fail_total %d\n", s.stats.dialsFail.Load())
		fmt.Fprintf(&b, "# HELP goose_rsts_sent_total RSTs emitted to clients.\n# TYPE goose_rsts_sent_total counter\n")
		fmt.Fprintf(&b, "goose_rsts_sent_total %d\n", s.stats.rstSent.Load())
		fmt.Fprintf(&b, "# HELP goose_decode_failures_total Frame batches that failed to decode (likely key mismatch).\n# TYPE goose_decode_failures_total counter\n")
		fmt.Fprintf(&b, "goose_decode_failures_total %d\n", s.stats.decodeFailures.Load())

		// Gauges
		s.mu.Lock()
		active := len(s.sessions)
		txReady := len(s.txReady)
		dialFail := len(s.dialFail)
		s.mu.Unlock()
		fmt.Fprintf(&b, "# HELP goose_sessions_active Currently active sessions.\n# TYPE goose_sessions_active gauge\n")
		fmt.Fprintf(&b, "goose_sessions_active %d\n", active)
		fmt.Fprintf(&b, "# HELP goose_sessions_tx_ready Sessions with pending tx frames.\n# TYPE goose_sessions_tx_ready gauge\n")
		fmt.Fprintf(&b, "goose_sessions_tx_ready %d\n", txReady)
		fmt.Fprintf(&b, "# HELP goose_dial_fail_targets Currently suppressed dial targets.\n# TYPE goose_dial_fail_targets gauge\n")
		fmt.Fprintf(&b, "goose_dial_fail_targets %d\n", dialFail)

		_, _ = w.Write([]byte(b.String()))
	})
}
