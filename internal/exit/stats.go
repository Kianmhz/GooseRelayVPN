package exit

import (
	"context"
	"fmt"
	"log"
	"runtime"
	"time"
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

	// goroutines is the headline leak indicator: each session spawns 3
	// (read, write, rxLoop), so under healthy operation goroutines should
	// track ~3×active plus a small constant. A monotonic climb while active
	// stays flat is the signature of the leak fixed in the openSession read
	// goroutine path — keep this in the always-on stats line so regressions
	// surface in service logs without needing pprof.
	log.Printf("[stats] goroutines=%d active=%d clients=%d sessions(open=%d close=%d) frames(in=%d out=%d) bytes(in=%s out=%s) requests=%d dials(ok=%d fail=%d) rst_sent=%d decode_fail=%d",
		runtime.NumGoroutine(),
		active, clients,
		s.stats.sessionsOpen.Load(), s.stats.sessionsClose.Load(),
		s.stats.framesIn.Load(), s.stats.framesOut.Load(),
		humanBytes(s.stats.bytesIn.Load()), humanBytes(s.stats.bytesOut.Load()),
		s.stats.requests.Load(),
		s.stats.dialsOK.Load(), s.stats.dialsFail.Load(),
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
