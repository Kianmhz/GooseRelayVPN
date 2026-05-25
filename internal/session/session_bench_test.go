package session

import (
	"bytes"
	"testing"

	"github.com/kianmhz/GooseRelayVPN/internal/frame"
)

func benchSID(b byte) [frame.SessionIDLen]byte {
	var out [frame.SessionIDLen]byte
	for i := range out {
		out[i] = b
	}
	return out
}

func BenchmarkSessionEnqueueDrain_128KiB(b *testing.B) {
	chunk := bytes.Repeat([]byte("x"), 128*1024)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		s := New(benchSID(1), "example.com:443", true)
		s.OnTx = func() {}
		s.EnqueueTx(chunk)
		_ = s.DrainTx(128 * 1024)
		s.Stop()
	}
}

func BenchmarkSessionEnqueueDrain_1MiB(b *testing.B) {
	chunk := bytes.Repeat([]byte("x"), 1024*1024)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		s := New(benchSID(2), "example.com:443", true)
		s.OnTx = func() {}
		s.EnqueueTx(chunk)
		_ = s.DrainTx(128 * 1024)
		s.Stop()
	}
}

func BenchmarkSessionDrainTxLimited_VariedBudget(b *testing.B) {
	chunk := bytes.Repeat([]byte("x"), 256*1024)
	cases := []struct {
		name      string
		maxFrames int
	}{
		{"unlimited", 0},
		{"frames_4", 4},
		{"frames_16", 16},
	}
	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				s := New(benchSID(4), "example.com:443", true)
				s.OnTx = func() {}
				s.EnqueueTx(chunk)
				_ = s.DrainTxLimited(64*1024, tc.maxFrames)
				s.Stop()
			}
		})
	}
}

func BenchmarkSessionProcessRx_Ordered(b *testing.B) {
	payload := bytes.Repeat([]byte("x"), 32*1024)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		s := New(benchSID(3), "", false)
		for seq := uint64(0); seq < 32; seq++ {
			s.ProcessRx(&frame.Frame{SessionID: s.ID, Seq: seq, Payload: payload})
			<-s.RxChan
		}
		s.ProcessRx(&frame.Frame{SessionID: s.ID, Seq: 32, Flags: frame.FlagFIN})
		<-s.RxChan
		s.Stop()
	}
}
