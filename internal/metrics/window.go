package metrics

import (
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

const defaultDurationWindow = 512

type DurationSummary struct {
	Count int
	P50   time.Duration
	P95   time.Duration
	P99   time.Duration
}

type DurationWindow struct {
	mu     sync.Mutex
	values []time.Duration
	next   int
	full   bool
}

func (w *DurationWindow) Add(v time.Duration) {
	if v < 0 {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.values == nil {
		w.values = make([]time.Duration, 0, defaultDurationWindow)
	}
	if len(w.values) < cap(w.values) {
		w.values = append(w.values, v)
		return
	}
	w.values[w.next] = v
	w.next = (w.next + 1) % len(w.values)
	w.full = true
}

func (w *DurationWindow) Snapshot() DurationSummary {
	w.mu.Lock()
	if len(w.values) == 0 {
		w.mu.Unlock()
		return DurationSummary{}
	}
	values := make([]time.Duration, len(w.values))
	copy(values, w.values)
	w.mu.Unlock()

	sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })
	return DurationSummary{
		Count: len(values),
		P50:   percentile(values, 50),
		P95:   percentile(values, 95),
		P99:   percentile(values, 99),
	}
}

func percentile(values []time.Duration, p int) time.Duration {
	if len(values) == 0 {
		return 0
	}
	idx := (len(values)*p + 99) / 100
	if idx < 1 {
		idx = 1
	}
	if idx > len(values) {
		idx = len(values)
	}
	return values[idx-1]
}

func (s DurationSummary) StringMS() string {
	if s.Count == 0 {
		return "n/a"
	}
	return fmt.Sprintf("p50=%dms p95=%dms p99=%dms n=%d",
		s.P50.Milliseconds(), s.P95.Milliseconds(), s.P99.Milliseconds(), s.Count)
}

type SizeBuckets struct {
	buckets [8]atomic.Uint64
}

func (b *SizeBuckets) Add(size int) {
	idx := 0
	switch {
	case size <= 0:
		idx = 0
	case size <= 1<<10:
		idx = 1
	case size <= 8<<10:
		idx = 2
	case size <= 64<<10:
		idx = 3
	case size <= 256<<10:
		idx = 4
	case size <= 1<<20:
		idx = 5
	case size <= 4<<20:
		idx = 6
	default:
		idx = 7
	}
	b.buckets[idx].Add(1)
}

func (b *SizeBuckets) Snapshot() [8]uint64 {
	var out [8]uint64
	for i := range b.buckets {
		out[i] = b.buckets[i].Load()
	}
	return out
}

func (b *SizeBuckets) String() string {
	s := b.Snapshot()
	return fmt.Sprintf("0=%d <=1K=%d <=8K=%d <=64K=%d <=256K=%d <=1M=%d <=4M=%d >4M=%d",
		s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7])
}

type RatioBuckets struct {
	buckets [6]atomic.Uint64
}

func (b *RatioBuckets) Add(numerator, denominator int) {
	if denominator <= 0 {
		return
	}
	permille := (numerator * 1000) / denominator
	idx := 0
	switch {
	case permille < 500:
		idx = 0
	case permille < 800:
		idx = 1
	case permille < 1000:
		idx = 2
	case permille < 1200:
		idx = 3
	case permille < 1500:
		idx = 4
	default:
		idx = 5
	}
	b.buckets[idx].Add(1)
}

func (b *RatioBuckets) Snapshot() [6]uint64 {
	var out [6]uint64
	for i := range b.buckets {
		out[i] = b.buckets[i].Load()
	}
	return out
}

func (b *RatioBuckets) String() string {
	s := b.Snapshot()
	return fmt.Sprintf("<0.5=%d <0.8=%d <1.0=%d <1.2=%d <1.5=%d >=1.5=%d",
		s[0], s[1], s[2], s[3], s[4], s[5])
}
