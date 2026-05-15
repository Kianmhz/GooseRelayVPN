package carrier

import (
	"context"
	"log"
	"time"

	"github.com/kianmhz/GooseRelayVPN/internal/metrics"
)

const (
	autoTuneInterval      = 30 * time.Second
	autoTuneMinIdleSleep  = 2 * time.Millisecond
	autoTuneMaxIdleSleep  = 250 * time.Millisecond
	autoTuneHighTTFB      = 750 * time.Millisecond
	autoTuneLowTTFB       = 150 * time.Millisecond
	autoTuneMinSampleSize = 8
)

func (c *Client) runAutoTuneLoop(ctx context.Context) {
	t := time.NewTicker(autoTuneInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			c.applyAutoTune()
		}
	}
}

func (c *Client) applyAutoTune() {
	c.mu.Lock()
	active := len(c.sessions)
	current := c.pollIdleSleep
	c.mu.Unlock()

	next := tunePollIdleSleep(current, active, c.stats.ttfb.Snapshot())
	if next == current {
		return
	}
	c.mu.Lock()
	c.pollIdleSleep = next
	c.mu.Unlock()
	log.Printf("[carrier] auto_tune poll_idle_sleep=%s active=%d ttfb=%s", next, active, c.stats.ttfb.Snapshot().StringMS())
}

func tunePollIdleSleep(current time.Duration, active int, ttfb metrics.DurationSummary) time.Duration {
	current = clampDuration(current, autoTuneMinIdleSleep, autoTuneMaxIdleSleep)
	if ttfb.Count >= autoTuneMinSampleSize && active > 0 && ttfb.P95 >= autoTuneHighTTFB {
		return clampDuration((current*3)/4, autoTuneMinIdleSleep, autoTuneMaxIdleSleep)
	}
	if active == 0 || (ttfb.Count >= autoTuneMinSampleSize && ttfb.P95 <= autoTuneLowTTFB) {
		return clampDuration((current*5)/4, autoTuneMinIdleSleep, autoTuneMaxIdleSleep)
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
