package metrics

import (
	"testing"
	"time"
)

func TestDurationWindowPercentiles(t *testing.T) {
	var w DurationWindow
	for i := 1; i <= 100; i++ {
		w.Add(time.Duration(i) * time.Millisecond)
	}
	got := w.Snapshot()
	if got.Count != 100 {
		t.Fatalf("Count=%d, want 100", got.Count)
	}
	if got.P50 != 50*time.Millisecond {
		t.Fatalf("P50=%s, want 50ms", got.P50)
	}
	if got.P95 != 95*time.Millisecond {
		t.Fatalf("P95=%s, want 95ms", got.P95)
	}
	if got.P99 != 99*time.Millisecond {
		t.Fatalf("P99=%s, want 99ms", got.P99)
	}
}

func TestSizeAndRatioBuckets(t *testing.T) {
	var sizes SizeBuckets
	sizes.Add(0)
	sizes.Add(1024)
	sizes.Add(9 << 20)
	s := sizes.Snapshot()
	if s[0] != 1 || s[1] != 1 || s[7] != 1 {
		t.Fatalf("unexpected size buckets: %#v", s)
	}

	var ratios RatioBuckets
	ratios.Add(400, 1000)
	ratios.Add(1000, 1000)
	ratios.Add(2000, 1000)
	r := ratios.Snapshot()
	if r[0] != 1 || r[3] != 1 || r[5] != 1 {
		t.Fatalf("unexpected ratio buckets: %#v", r)
	}
}
