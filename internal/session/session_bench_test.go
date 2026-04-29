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
		s.SetOnTx(func() {})
		s.EnqueueTx(chunk)
		_ = s.DrainTx(128 * 1024)
	}
}

func BenchmarkSessionEnqueueDrain_1MiB(b *testing.B) {
	chunk := bytes.Repeat([]byte("x"), 1024*1024)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		s := New(benchSID(2), "example.com:443", true)
		s.SetOnTx(func() {})
		s.EnqueueTx(chunk)
		_ = s.DrainTx(128 * 1024)
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
	}
}
