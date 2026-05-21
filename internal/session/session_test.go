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
	s.OnTx = func() { notified <- struct{}{} }
	s.EnqueueTx([]byte("hi"))
	select {
	case <-notified:
	case <-time.After(time.Second):
		t.Fatal("OnTx not invoked")
	}
}

// TestRollbackDrain_RestoresSYNAndPayload: when a drained batch cannot be
// transmitted, RollbackDrain must restore the session so that the next drain
// produces an equivalent set of frames. Previously, batch-send failures
// silently dropped the SYN+payload, leaving the session zombied for the rest
// of its lifetime.
func TestRollbackDrain_RestoresSYNAndPayload(t *testing.T) {
	s := New(sid(8), "example.com:80", true)
	s.EnqueueTx([]byte("hello"))

	first, snap := s.DrainTxLimitedTxn(64*1024, 0)
	if len(first) != 1 || !first[0].HasFlag(frame.FlagSYN) {
		t.Fatalf("first drain: want one SYN frame, got %#v", first)
	}
	if snap == nil {
		t.Fatal("expected non-nil snapshot when frames were drained")
	}

	// Without rollback, a second drain would yield nothing — that's the bug.
	emptyFrames, _ := s.DrainTxLimitedTxn(64*1024, 0)
	if len(emptyFrames) != 0 {
		t.Fatalf("post-drain: want 0 frames, got %d (pre-existing test invariant broken)", len(emptyFrames))
	}

	s.RollbackDrain(snap)

	again, _ := s.DrainTxLimitedTxn(64*1024, 0)
	if len(again) != 1 {
		t.Fatalf("after rollback: want one frame again, got %d", len(again))
	}
	if !again[0].HasFlag(frame.FlagSYN) {
		t.Fatal("after rollback: regenerated frame must carry SYN")
	}
	if !bytes.Equal(again[0].Payload, []byte("hello")) {
		t.Fatalf("after rollback: payload corruption — got %q want %q", again[0].Payload, "hello")
	}
	if again[0].Seq != first[0].Seq {
		t.Fatalf("after rollback: seq must be reused for retransmission. got %d want %d",
			again[0].Seq, first[0].Seq)
	}
}

// TestRollbackDrain_PreservesConcurrentEnqueue: if EnqueueTx happens between
// a drain and its rollback (the realistic case where new SOCKS data arrives
// while a batch is in flight), the rolled-back data goes first and the new
// data follows.
func TestRollbackDrain_PreservesConcurrentEnqueue(t *testing.T) {
	s := New(sid(9), "example.com:80", true)
	s.EnqueueTx([]byte("first"))

	_, snap := s.DrainTxLimitedTxn(64*1024, 0)

	// Simulate user code writing more bytes while the previous batch is in
	// flight. This is the normal case — EnqueueTx is unblocked by the txCond
	// broadcast inside drainTx.
	s.EnqueueTx([]byte("second"))

	s.RollbackDrain(snap)

	after, _ := s.DrainTxLimitedTxn(64*1024, 0)
	if len(after) == 0 {
		t.Fatal("want at least one frame after rollback")
	}
	var got []byte
	for _, f := range after {
		got = append(got, f.Payload...)
	}
	want := []byte("firstsecond")
	if !bytes.Equal(got, want) {
		t.Fatalf("merged payload: got %q want %q", got, want)
	}
}

// TestEnqueueInitialData_PreservesOrderAcrossMultipleCalls catches the regression
// where EnqueueInitialData prepended (instead of appending) while synNeeded was
// true. The SOCKS5 adapter calls this on every Write, and a fast local writer
// can fit many calls between session creation and the SYN drain. Prepend
// reversed byte order on the wire; for any protocol whose first bytes carry
// framing (TLS records, HTTP request lines, length prefixes), the upstream
// would either error or parse garbage. The bench harness's sized upload sink
// silently masked this by ACKing on a 0-length body when the body's leading
// zeros were read as the size header, producing wildly optimistic upload
// throughput measurements.
func TestEnqueueInitialData_PreservesOrderAcrossMultipleCalls(t *testing.T) {
	s := New(sid(10), "example.com:443", true)

	// Simulate a SOCKS5 writer calling Write multiple times before the
	// carrier's poll worker drains the SYN: a length-prefix header followed
	// by body chunks. The order matters; reverse order would put the body
	// before the header and the upstream would misparse.
	s.EnqueueInitialData([]byte("HDR_"))
	s.EnqueueInitialData([]byte("body_chunk_1_"))
	s.EnqueueInitialData([]byte("body_chunk_2"))

	frames := s.DrainTx(64 * 1024)
	if len(frames) != 1 {
		t.Fatalf("want 1 bundled frame, got %d", len(frames))
	}
	if !frames[0].HasFlag(frame.FlagSYN) {
		t.Fatal("first frame missing SYN")
	}
	want := []byte("HDR_body_chunk_1_body_chunk_2")
	if !bytes.Equal(frames[0].Payload, want) {
		t.Fatalf("payload ordering corrupt: got %q want %q", frames[0].Payload, want)
	}
}
