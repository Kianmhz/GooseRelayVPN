package exit

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"runtime"
	"time"

	"github.com/kianmhz/GooseRelayVPN/internal/metrics"
)

// statsInterval is how often the periodic stats line is logged.
const statsInterval = 60 * time.Second

// runStatsLoop emits a one-line health summary every statsInterval until
// ctx is canceled. Cheap (atomic Loads + one log line) so it's safe to keep
// always-on.
func (s *Server) runStatsLoop(ctx context.Context) {
	t := time.NewTicker(statsInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.logStats()
		}
	}
}

func (s *Server) logStats() {
	s.mu.Lock()
	active := len(s.sessions)
	clients := len(s.activity)
	s.mu.Unlock()

	if s.statsJSON {
		s.logStatsJSON(active, clients)
		return
	}

	// goroutines is the headline leak indicator: each session spawns 3
	// (read, write, rxLoop), so under healthy operation goroutines should
	// track ~3×active plus a small constant. A monotonic climb while active
	// stays flat is the signature of the leak fixed in the openSession read
	// goroutine path — keep this in the always-on stats line so regressions
	// surface in service logs without needing pprof.
	log.Printf("[stats] goroutines=%d active=%d clients=%d sessions(open=%d close=%d) frames(in=%d out=%d) bytes(in=%s out=%s) requests=%d dials(ok=%d fail=%d suppressed=%d attempts=%d race_wins=%d ipv4=%d ipv6=%d proxy=%d) rst_sent=%d decode_fail=%d",
		runtime.NumGoroutine(),
		active, clients,
		s.stats.sessionsOpen.Load(), s.stats.sessionsClose.Load(),
		s.stats.framesIn.Load(), s.stats.framesOut.Load(),
		humanBytes(s.stats.bytesIn.Load()), humanBytes(s.stats.bytesOut.Load()),
		s.stats.requests.Load(),
		s.stats.dialsOK.Load(), s.stats.dialsFail.Load(), s.stats.dialsSuppressed.Load(),
		s.stats.dialAttempts.Load(), s.stats.dialRaceWins.Load(),
		s.stats.dialIPv4.Load(), s.stats.dialIPv6.Load(), s.stats.dialProxy.Load(),
		s.stats.rstSent.Load(),
		s.stats.decodeFailures.Load(),
	)
	log.Printf("[stats] latency queue_wait[%s] encode[%s] decode[%s]",
		s.stats.queueWait.Snapshot().StringMS(),
		s.stats.encode.Snapshot().StringMS(),
		s.stats.decode.Snapshot().StringMS(),
	)
	log.Printf("[stats] payload req={%s} resp={%s} wire_ratio={%s}",
		s.stats.reqSize.String(),
		s.stats.respSize.String(),
		s.stats.wireRatio.String(),
	)
	if compression := s.compressionStatsMap(); len(compression) > 0 {
		log.Printf("[stats] compression modes(raw=%d zstd=%d) attempted=%d used=%d skipped=%d raw_bytes=%s body_bytes=%s wire_bytes=%s saved_bytes=%s lost_bytes=%s",
			compression["raw"], compression["zstd"],
			compression["attempted"], compression["used"], compression["skipped"],
			humanBytes(compression["raw_bytes"]), humanBytes(compression["body_bytes"]),
			humanBytes(compression["wire_bytes"]), humanBytes(compression["saved_bytes"]),
			humanBytes(compression["lost_bytes"]),
		)
	}
	log.Printf("[stats] replay enabled=%t ack_received=%d frames=%d bytes=%s pruned=%d dropped_sessions=%d dropped_cap=%d dropped_expired=%d buffer=%s",
		s.downstreamReplayEnabled,
		s.stats.ackReceived.Load(),
		s.stats.replayFrames.Load(),
		humanBytes(s.stats.replayBytes.Load()),
		s.stats.replayPruned.Load(),
		s.stats.replayDropped.Load(),
		s.stats.replayDroppedCap.Load(),
		s.stats.replayDroppedExpired.Load(),
		humanBytes(s.replayBufferBytes()),
	)
}

func (s *Server) logStatsJSON(active, clients int) {
	payload := map[string]any{
		"event":      "stats",
		"component":  "exit",
		"ts":         time.Now().Format(time.RFC3339),
		"goroutines": runtime.NumGoroutine(),
		"active":     active,
		"clients":    clients,
		"sessions": map[string]uint64{
			"open":  s.stats.sessionsOpen.Load(),
			"close": s.stats.sessionsClose.Load(),
		},
		"frames": map[string]uint64{
			"in":  s.stats.framesIn.Load(),
			"out": s.stats.framesOut.Load(),
		},
		"bytes": map[string]uint64{
			"in":  s.stats.bytesIn.Load(),
			"out": s.stats.bytesOut.Load(),
		},
		"requests": s.stats.requests.Load(),
		"dials": map[string]uint64{
			"ok":         s.stats.dialsOK.Load(),
			"fail":       s.stats.dialsFail.Load(),
			"suppressed": s.stats.dialsSuppressed.Load(),
			"attempts":   s.stats.dialAttempts.Load(),
			"race_wins":  s.stats.dialRaceWins.Load(),
			"ipv4":       s.stats.dialIPv4.Load(),
			"ipv6":       s.stats.dialIPv6.Load(),
			"proxy":      s.stats.dialProxy.Load(),
		},
		"rst_sent":        s.stats.rstSent.Load(),
		"decode_failures": s.stats.decodeFailures.Load(),
		"latency_ms": map[string]any{
			"queue_wait": durationSummaryJSON(s.stats.queueWait.Snapshot()),
			"encode":     durationSummaryJSON(s.stats.encode.Snapshot()),
			"decode":     durationSummaryJSON(s.stats.decode.Snapshot()),
		},
		"payload": map[string]any{
			"request_size_buckets":  s.stats.reqSize.Snapshot(),
			"response_size_buckets": s.stats.respSize.Snapshot(),
			"wire_ratio_buckets":    s.stats.wireRatio.Snapshot(),
			"compression":           s.compressionStatsMap(),
		},
		"downstream_replay": map[string]any{
			"enabled":          s.downstreamReplayEnabled,
			"ack_received":     s.stats.ackReceived.Load(),
			"replay_frames":    s.stats.replayFrames.Load(),
			"replay_bytes":     s.stats.replayBytes.Load(),
			"replay_pruned":    s.stats.replayPruned.Load(),
			"dropped_sessions": s.stats.replayDropped.Load(),
			"dropped_cap":      s.stats.replayDroppedCap.Load(),
			"dropped_expired":  s.stats.replayDroppedExpired.Load(),
			"buffer_bytes":     s.replayBufferBytes(),
		},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		log.Printf("[stats] json marshal failed: %v", err)
		return
	}
	log.Printf("[stats_json] %s", body)
}

func (s *Server) compressionStatsMap() map[string]uint64 {
	stats := map[string]uint64{
		"attempted":   s.stats.compressAttempted.Load(),
		"used":        s.stats.compressUsed.Load(),
		"skipped":     s.stats.compressSkipped.Load(),
		"raw":         s.stats.compressRaw.Load(),
		"zstd":        s.stats.compressZstd.Load(),
		"raw_bytes":   s.stats.compressRawBytes.Load(),
		"body_bytes":  s.stats.compressBodyBytes.Load(),
		"wire_bytes":  s.stats.compressWireBytes.Load(),
		"saved_bytes": s.stats.compressSaved.Load(),
		"lost_bytes":  s.stats.compressLost.Load(),
	}
	if stats["attempted"] == 0 && stats["skipped"] == 0 && stats["raw"] == 0 && stats["zstd"] == 0 {
		return nil
	}
	return stats
}

func (s *Server) replayBufferBytes() uint64 {
	if s.replay == nil {
		return 0
	}
	return uint64(s.replay.bufferBytes())
}

func durationSummaryJSON(s metrics.DurationSummary) map[string]any {
	return map[string]any{
		"count": s.Count,
		"p50":   s.P50.Milliseconds(),
		"p95":   s.P95.Milliseconds(),
		"p99":   s.P99.Milliseconds(),
	}
}

// humanBytes formats a byte count as a short human-readable string. Mirrors
// the carrier's helper but kept package-local to avoid an inter-package
// dependency just for one tiny formatter.
func humanBytes(n uint64) string {
	const k = 1024
	switch {
	case n < k:
		return fmt.Sprintf("%dB", n)
	case n < k*k:
		return fmt.Sprintf("%.1fKB", float64(n)/float64(k))
	case n < k*k*k:
		return fmt.Sprintf("%.1fMB", float64(n)/float64(k*k))
	default:
		return fmt.Sprintf("%.2fGB", float64(n)/float64(k*k*k))
	}
}
