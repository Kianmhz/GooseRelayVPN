package bench

import (
	"sync"
	"testing"
)

// BenchmarkSetup measures the cost of setting up a brand-new tunneled
// connection through the SOCKS5 entry point. Reports the SOCKS handshake +
// SYN round-trip time.
func BenchmarkSetup(b *testing.B) {
	rig, err := NewRig()
	if err != nil {
		b.Fatalf("rig: %v", err)
	}
	defer rig.Close()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		res, err := rig.Run(1)
		if err != nil {
			b.Fatalf("run: %v", err)
		}
		_ = res
	}
}

// BenchmarkTransferKB measures small-payload latency end-to-end (setup + TTFB
// + transfer). Mimics interactive traffic (HTTP request lines, TLS handshakes).
func BenchmarkTransferKB(b *testing.B) {
	rig, err := NewRig()
	if err != nil {
		b.Fatalf("rig: %v", err)
	}
	defer rig.Close()
	b.SetBytes(4 * 1024)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := rig.Run(4 * 1024); err != nil {
			b.Fatalf("run: %v", err)
		}
	}
}

// BenchmarkTransfer1MiB measures bulk-transfer throughput.
func BenchmarkTransfer1MiB(b *testing.B) {
	rig, err := NewRig()
	if err != nil {
		b.Fatalf("rig: %v", err)
	}
	defer rig.Close()
	b.SetBytes(1024 * 1024)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := rig.Run(1024 * 1024); err != nil {
			b.Fatalf("run: %v", err)
		}
	}
}

// BenchmarkParallelSetup measures fan-out: many concurrent SOCKS5 dials
// through the same carrier. Approximates browser tab burst (5-10 simultaneous
// SYNs), which is where head-of-line blocking historically hurt.
func BenchmarkParallelSetup(b *testing.B) {
	rig, err := NewRig()
	if err != nil {
		b.Fatalf("rig: %v", err)
	}
	defer rig.Close()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, err := rig.Run(1); err != nil {
				b.Errorf("run: %v", err)
				return
			}
		}
	})
}

// TestRigBasicRoundTrip verifies the harness itself functions before benches.
func TestRigBasicRoundTrip(t *testing.T) {
	rig, err := NewRig()
	if err != nil {
		t.Fatalf("rig: %v", err)
	}
	defer rig.Close()
	res, err := rig.Run(8 * 1024)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.Bytes != 8*1024 {
		t.Fatalf("expected 8 KiB transferred, got %d", res.Bytes)
	}
}

// TestRigConcurrentRoundTrips drives several concurrent transfers to confirm
// the harness handles parallel sessions cleanly (and also exercises the new
// drain-fairness round-robin cursor).
func TestRigConcurrentRoundTrips(t *testing.T) {
	rig, err := NewRig()
	if err != nil {
		t.Fatalf("rig: %v", err)
	}
	defer rig.Close()
	const N = 8
	var wg sync.WaitGroup
	wg.Add(N)
	errs := make(chan error, N)
	for i := 0; i < N; i++ {
		go func() {
			defer wg.Done()
			if _, err := rig.Run(64 * 1024); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("concurrent run: %v", err)
	}
}
