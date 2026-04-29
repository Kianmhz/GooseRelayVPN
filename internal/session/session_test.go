package session

import (
	"bytes"
	"testing"
	"time"

	"github.com/kianmhz/GooseRelayVPN/internal/frame"
)

func sid(b byte) [frame.SessionIDLen]byte {
	var out [frame.SessionIDLen]byte
	for i := range out {
		out[i] = b
	}
	return out
}

func TestDrainTx_EmitsSYNFirst(t *testing.T) {
	s := New(sid(1), "example.com:80", true)
	s.EnqueueTx([]byte("GET / HTTP/1.1\r\n"))
	frames := s.DrainTx(64 * 1024)
	if len(frames) != 1 {
		t.Fatalf("want 1 frame, got %d", len(frames))
	}
	if !frames[0].HasFlag(frame.FlagSYN) {
		t.Fatal("first frame missing SYN")
	}
	if frames[0].Target != "example.com:80" {
		t.Fatalf("target=%q", frames[0].Target)
	}
	if !bytes.Equal(frames[0].Payload, []byte("GET / HTTP/1.1\r\n")) {
		t.Fatal("payload mismatch")
	}
}

func TestDrainTx_ChunksLargePayload(t *testing.T) {
	s := New(sid(1), "x:1", false)
	s.EnqueueTx(bytes.Repeat([]byte("A"), 250))
	frames := s.DrainTx(100)
	if len(frames) != 3 {
		t.Fatalf("want 3 chunks, got %d", len(frames))
	}
	if frames[0].Seq != 0 || frames[1].Seq != 1 || frames[2].Seq != 2 {
		t.Fatalf("seq mismatch: %d %d %d", frames[0].Seq, frames[1].Seq, frames[2].Seq)
	}
	total := len(frames[0].Payload) + len(frames[1].Payload) + len(frames[2].Payload)
	if total != 250 {
		t.Fatalf("total bytes %d", total)
	}
}

func TestDrainTxLimited_PartialAndResume(t *testing.T) {
	s := New(sid(8), "x:1", false)
	s.EnqueueTx(bytes.Repeat([]byte("B"), 250))

	first := s.DrainTxLimited(100, 2)
	if len(first) != 2 {
		t.Fatalf("want 2 frames on first drain, got %d", len(first))
	}
	if first[0].Seq != 0 || first[1].Seq != 1 {
		t.Fatalf("unexpected seq in first drain: %d %d", first[0].Seq, first[1].Seq)
	}
	if s.HasPendingTx() != true {
		t.Fatal("expected pending tx after limited drain")
	}

	second := s.DrainTxLimited(100, 2)
	if len(second) != 1 {
		t.Fatalf("want 1 frame on second drain, got %d", len(second))
	}
	if second[0].Seq != 2 {
		t.Fatalf("unexpected seq in second drain: %d", second[0].Seq)
	}
	if s.HasPendingTx() {
		t.Fatal("did not expect pending tx after draining all payload")
	}

	total := 0
	for _, f := range append(first, second...) {
		total += len(f.Payload)
	}
	if total != 250 {
		t.Fatalf("total drained bytes %d", total)
	}
}

func TestDrainTx_EmitsFINOnClose(t *testing.T) {
	s := New(sid(2), "x:1", false)
	s.EnqueueTx([]byte("hi"))
	s.RequestClose()
	frames := s.DrainTx(64 * 1024)
	if len(frames) != 2 {
		t.Fatalf("want 2 frames, got %d", len(frames))
	}
	if !frames[1].HasFlag(frame.FlagFIN) {
		t.Fatal("trailing frame should be FIN")
	}
	// Idempotent: another drain after FIN should produce nothing.
	if more := s.DrainTx(64 * 1024); len(more) != 0 {
		t.Fatalf("expected no frames after FIN, got %d", len(more))
	}
}

func TestProcessRx_OutOfOrderReassembly(t *testing.T) {
	s := New(sid(3), "", false)
	frames := []*frame.Frame{
		{SessionID: sid(3), Seq: 0, Payload: []byte("a")},
		{SessionID: sid(3), Seq: 2, Payload: []byte("c")},
		{SessionID: sid(3), Seq: 1, Payload: []byte("b")},
	}
	for _, f := range frames {
		s.ProcessRx(f)
	}
	got := []byte{}
	timeout := time.After(time.Second)
	for i := 0; i < 3; i++ {
		select {
		case b := <-s.RxChan:
			got = append(got, b...)
		case <-timeout:
			t.Fatalf("timeout, got %q", got)
		}
	}
	if string(got) != "abc" {
		t.Fatalf("got %q want %q", got, "abc")
	}
}

func TestProcessRx_DuplicateDropped(t *testing.T) {
	s := New(sid(4), "", false)
	s.ProcessRx(&frame.Frame{SessionID: sid(4), Seq: 0, Payload: []byte("x")})
	s.ProcessRx(&frame.Frame{SessionID: sid(4), Seq: 0, Payload: []byte("dup")})
	if got := <-s.RxChan; string(got) != "x" {
		t.Fatalf("got %q", got)
	}
	select {
	case got := <-s.RxChan:
		t.Fatalf("dup delivered: %q", got)
	case <-time.After(50 * time.Millisecond):
	}
}

func TestProcessRx_FINClosesRxChan(t *testing.T) {
	s := New(sid(5), "", false)
	s.ProcessRx(&frame.Frame{SessionID: sid(5), Seq: 0, Payload: []byte("hi")})
	s.ProcessRx(&frame.Frame{SessionID: sid(5), Seq: 1, Flags: frame.FlagFIN})
	if got := <-s.RxChan; string(got) != "hi" {
		t.Fatalf("got %q", got)
	}
	if _, ok := <-s.RxChan; ok {
		t.Fatal("RxChan should be closed after FIN")
	}
}

func TestEnqueueTx_BackpressureBlocksAndReleases(t *testing.T) {
	s := New(sid(6), "x:1", false)
	// Fill to high water + a smidge.
	s.EnqueueTx(bytes.Repeat([]byte("A"), TxBufHighWater+1))

	done := make(chan struct{})
	go func() {
		s.EnqueueTx([]byte("more"))
		close(done)
	}()

	select {
	case <-done:
		t.Fatal("EnqueueTx returned without blocking on backpressure")
	case <-time.After(50 * time.Millisecond):
	}

	// Drain everything; this should release the backpressured writer.
	_ = s.DrainTx(1024 * 1024)

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("blocked writer not released after drain")
	}
}

func TestOnTx_FiresOnEnqueue(t *testing.T) {
	s := New(sid(7), "x:1", false)
	notified := make(chan struct{}, 4)
	s.SetOnTx(func() { notified <- struct{}{} })
	s.EnqueueTx([]byte("hi"))
	select {
	case <-notified:
	case <-time.After(time.Second):
		t.Fatal("OnTx not invoked")
	}
}
