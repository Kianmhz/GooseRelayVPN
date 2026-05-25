package carrier

import (
	"testing"
	"time"

	"github.com/kianmhz/GooseRelayVPN/internal/metrics"
)

func TestTunePollIdleSleepCaps(t *testing.T) {
	high := metrics.DurationSummary{Count: autoTuneMinSampleSize, P95: time.Second}
	got := tunePollIdleSleep(time.Millisecond, 10, high)
	if got != autoTuneMinIdleSleep {
		t.Fatalf("high-latency lower cap = %s, want %s", got, autoTuneMinIdleSleep)
	}

	low := metrics.DurationSummary{Count: autoTuneMinSampleSize, P95: 10 * time.Millisecond}
	got = tunePollIdleSleep(time.Hour, 0, low)
	if got != autoTuneMaxIdleSleep {
		t.Fatalf("idle upper cap = %s, want %s", got, autoTuneMaxIdleSleep)
	}
}

func TestTunePollIdleSleepNeedsSamplesForLatencyMove(t *testing.T) {
	summary := metrics.DurationSummary{Count: autoTuneMinSampleSize - 1, P95: time.Second}
	got := tunePollIdleSleep(20*time.Millisecond, 1, summary)
	if got != 20*time.Millisecond {
		t.Fatalf("got %s, want unchanged without enough samples", got)
	}
}
