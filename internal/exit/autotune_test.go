package exit

import (
	"testing"
	"time"

	"github.com/kianmhz/GooseRelayVPN/internal/metrics"
)

func TestTuneServerTimingHighQueueWaitLowersLatencyWindows(t *testing.T) {
	current := serverTiming{
		activeDrain:  150 * time.Millisecond,
		coalesce:     10 * time.Millisecond,
		coalesceBusy: 5 * time.Millisecond,
		baseActive:   150 * time.Millisecond,
		baseCoalesce: 10 * time.Millisecond,
		baseBusy:     5 * time.Millisecond,
	}
	next := tuneServerTiming(current, 4, metrics.DurationSummary{
		Count: serverAutoTuneMinSamples,
		P95:   serverAutoTuneHighQueueWait,
	})
	if next.activeDrain != 125*time.Millisecond {
		t.Fatalf("activeDrain = %s, want 125ms", next.activeDrain)
	}
	if next.coalesce != 5*time.Millisecond || next.coalesceBusy != 0 {
		t.Fatalf("coalesce = %s/%s, want 5ms/0", next.coalesce, next.coalesceBusy)
	}
}

func TestTuneServerTimingBusyLowQueueWaitRaisesBatchingWithinCaps(t *testing.T) {
	current := serverTiming{
		activeDrain:  225 * time.Millisecond,
		coalesce:     20 * time.Millisecond,
		coalesceBusy: 5 * time.Millisecond,
		baseActive:   150 * time.Millisecond,
		baseCoalesce: 0,
		baseBusy:     0,
	}
	next := tuneServerTiming(current, busySessionThreshold, metrics.DurationSummary{
		Count: serverAutoTuneMinSamples,
		P95:   serverAutoTuneLowQueueWait,
	})
	if next.activeDrain != serverAutoTuneActiveMax {
		t.Fatalf("activeDrain = %s, want %s", next.activeDrain, serverAutoTuneActiveMax)
	}
	if next.coalesce != serverAutoTuneCoalesceMax || next.coalesceBusy != 10*time.Millisecond {
		t.Fatalf("coalesce = %s/%s, want %s/10ms", next.coalesce, next.coalesceBusy, serverAutoTuneCoalesceMax)
	}
}

func TestTuneServerTimingIdleMovesBackToBase(t *testing.T) {
	current := serverTiming{
		activeDrain:  50 * time.Millisecond,
		coalesce:     15 * time.Millisecond,
		coalesceBusy: 10 * time.Millisecond,
		baseActive:   150 * time.Millisecond,
		baseCoalesce: 0,
		baseBusy:     0,
	}
	next := tuneServerTiming(current, 0, metrics.DurationSummary{
		Count: serverAutoTuneMinSamples,
		P95:   time.Second,
	})
	if next.activeDrain != 75*time.Millisecond {
		t.Fatalf("activeDrain = %s, want 75ms", next.activeDrain)
	}
	if next.coalesce != 10*time.Millisecond || next.coalesceBusy != 5*time.Millisecond {
		t.Fatalf("coalesce = %s/%s, want 10ms/5ms", next.coalesce, next.coalesceBusy)
	}
}
