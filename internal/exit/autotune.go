package exit

import (
	"context"
	"log"
	"time"

	"github.com/kianmhz/GooseRelayVPN/internal/metrics"
)

const (
	serverAutoTuneInterval      = 30 * time.Second
	serverAutoTuneMinSamples    = 8
	serverAutoTuneActiveMin     = 50 * time.Millisecond
	serverAutoTuneActiveMax     = 250 * time.Millisecond
	serverAutoTuneActiveStep    = 25 * time.Millisecond
	serverAutoTuneCoalesceMax   = 25 * time.Millisecond
	serverAutoTuneCoalesceBusy  = 10 * time.Millisecond
	serverAutoTuneCoalesceStep  = 5 * time.Millisecond
	serverAutoTuneHighQueueWait = 300 * time.Millisecond
	serverAutoTuneLowQueueWait  = 75 * time.Millisecond
)

func (s *Server) runAutoTuneLoop(ctx context.Context) {
	t := time.NewTicker(serverAutoTuneInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.applyAutoTune()
		}
	}
}

func (s *Server) applyAutoTune() {
	queueWait := s.stats.queueWait.Snapshot()
	if queueWait.Count < serverAutoTuneMinSamples {
		return
	}

	activeSessions := int(s.sessionCount.Load())
	s.timingMu.Lock()
	current := serverTiming{
		activeDrain:  s.activeDrainWindow,
		coalesce:     s.coalesceWindow,
		coalesceBusy: s.coalesceWindowBusy,
		baseActive:   s.baseActiveDrainWindow,
		baseCoalesce: s.baseCoalesceWindow,
		baseBusy:     s.baseCoalesceWindowBusy,
	}
	next := tuneServerTiming(current, activeSessions, queueWait)
	if next.activeDrain == current.activeDrain &&
		next.coalesce == current.coalesce &&
		next.coalesceBusy == current.coalesceBusy {
		s.timingMu.Unlock()
		return
	}
	s.activeDrainWindow = next.activeDrain
	s.coalesceWindow = next.coalesce
	s.coalesceWindowBusy = next.coalesceBusy
	s.timingMu.Unlock()

	log.Printf("[exit] auto_tune active_drain=%s coalesce=%s/%s active=%d queue_wait=%s",
		next.activeDrain, next.coalesce, next.coalesceBusy, activeSessions, queueWait.StringMS())
}

type serverTiming struct {
	activeDrain  time.Duration
	coalesce     time.Duration
	coalesceBusy time.Duration
	baseActive   time.Duration
	baseCoalesce time.Duration
	baseBusy     time.Duration
}

func tuneServerTiming(current serverTiming, activeSessions int, queueWait metrics.DurationSummary) serverTiming {
	next := current
	next.activeDrain = clampDuration(next.activeDrain, serverAutoTuneActiveMin, serverAutoTuneActiveMax)
	next.coalesce = clampDuration(next.coalesce, 0, serverAutoTuneCoalesceMax)
	next.coalesceBusy = clampDuration(next.coalesceBusy, 0, serverAutoTuneCoalesceBusy)

	switch {
	case activeSessions == 0:
		next.activeDrain = moveTowardDuration(next.activeDrain, clampDuration(current.baseActive, serverAutoTuneActiveMin, serverAutoTuneActiveMax), serverAutoTuneActiveStep)
		next.coalesce = moveTowardDuration(next.coalesce, clampDuration(current.baseCoalesce, 0, serverAutoTuneCoalesceMax), serverAutoTuneCoalesceStep)
		next.coalesceBusy = moveTowardDuration(next.coalesceBusy, clampDuration(current.baseBusy, 0, serverAutoTuneCoalesceBusy), serverAutoTuneCoalesceStep)
	case queueWait.P95 >= serverAutoTuneHighQueueWait:
		// Downstream bytes are waiting too long; answer polls faster and remove
		// response coalescing pressure.
		next.activeDrain = clampDuration(next.activeDrain-serverAutoTuneActiveStep, serverAutoTuneActiveMin, serverAutoTuneActiveMax)
		next.coalesce = clampDuration(next.coalesce-serverAutoTuneCoalesceStep, 0, serverAutoTuneCoalesceMax)
		next.coalesceBusy = clampDuration(next.coalesceBusy-serverAutoTuneCoalesceStep, 0, serverAutoTuneCoalesceBusy)
	case activeSessions >= busySessionThreshold && queueWait.P95 <= serverAutoTuneLowQueueWait:
		// Under bulk fan-out with low queue wait, allow a little more batching.
		next.activeDrain = clampDuration(next.activeDrain+serverAutoTuneActiveStep, serverAutoTuneActiveMin, serverAutoTuneActiveMax)
		next.coalesce = clampDuration(next.coalesce+serverAutoTuneCoalesceStep, 0, serverAutoTuneCoalesceMax)
		next.coalesceBusy = clampDuration(next.coalesceBusy+serverAutoTuneCoalesceStep, 0, serverAutoTuneCoalesceBusy)
	}
	return next
}

func moveTowardDuration(current, target, step time.Duration) time.Duration {
	if current < target {
		return clampDuration(current+step, current, target)
	}
	if current > target {
		return clampDuration(current-step, target, current)
	}
	return current
}

func clampDuration(v, min, max time.Duration) time.Duration {
	if v < min {
		return min
	}
	if v > max {
		return max
	}
	return v
}
