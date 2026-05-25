package session

import (
	"bytes"
	"errors"
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

func TestEnqueueInitialDataPreservesOrderAcrossMultipleCalls(t *testing.T) {
	s := New(sid(10), "example.com:443", true)

	if err := s.EnqueueInitialData([]byte("HDR_")); err != nil {
		t.Fatalf("enqueue header: %v", err)
	}
	if err := s.EnqueueInitialData([]byte("body_chunk_1_")); err != nil {
		t.Fatalf("enqueue body 1: %v", err)
	}
	if err := s.EnqueueInitialData([]byte("body_chunk_2")); err != nil {
		t.Fatalf("enqueue body 2: %v", err)
	}

	frames := s.DrainTx(64 * 1024)
	if len(frames) != 1 {
		t.Fatalf("want 1 bundled frame, got %d", len(frames))
	}
	if !frames[0].HasFlag(frame.FlagSYN) {
		t.Fatal("first frame missing SYN")
	}
	want := []byte("HDR_body_chunk_1_body_chunk_2")
	if !bytes.Equal(frames[0].Payload, want) {
		t.Fatalf("SYN payload = %q, want %q", frames[0].Payload, want)
	}
}

func TestEnqueueTxPreallocatesModerateBuffer(t *testing.T) {
	s := New(sid(0x12), "example.com:443", false)
	s.EnqueueTx([]byte("hello"))

	s.mu.Lock()
	gotCap := cap(s.txBuf)
	gotLen := len(s.txBuf)
	s.mu.Unlock()

	if gotLen != len("hello") {
		t.Fatalf("txBuf len = %d, want %d", gotLen, len("hello"))
	}
	if gotCap < 64*1024 {
		t.Fatalf("txBuf cap = %d, want at least 64KiB", gotCap)
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

func TestDrainTxLimitedByBudget_StopsAtByteBudgetAndResumesInOrder(t *testing.T) {
	s := New(sid(9), "x:1", false)
	s.EnqueueTx(bytes.Repeat([]byte("C"), 250))

	first := s.DrainTxLimitedByBudget(100, 10, 150)
	if len(first) != 2 {
		t.Fatalf("want 2 frames on first drain, got %d", len(first))
	}
	if len(first[0].Payload) != 100 || len(first[1].Payload) != 50 {
		t.Fatalf("first drain payload sizes = %d/%d, want 100/50", len(first[0].Payload), len(first[1].Payload))
	}
	if first[0].Seq != 0 || first[1].Seq != 1 {
		t.Fatalf("unexpected seq in first drain: %d %d", first[0].Seq, first[1].Seq)
	}
	if !s.HasPendingTx() {
		t.Fatal("expected pending tx after byte-limited drain")
	}

	second := s.DrainTxLimitedByBudget(100, 10, 150)
	if len(second) != 1 {
		t.Fatalf("want 1 frame on second drain, got %d", len(second))
	}
	if len(second[0].Payload) != 100 {
		t.Fatalf("second drain payload size = %d, want 100", len(second[0].Payload))
	}
	if second[0].Seq != 2 {
		t.Fatalf("unexpected seq in second drain: %d", second[0].Seq)
	}
	if s.HasPendingTx() {
		t.Fatal("did not expect pending tx after draining all payload")
	}
}

func TestTxBudgetBlocksAcrossSessionsAndReleasesOnDrain(t *testing.T) {
	budget := NewTxBudget(5)
	s1 := New(sid(0x31), "one.example:443", false)
	s2 := New(sid(0x32), "two.example:443", false)
	s1.SetTxBudget(budget)
	s2.SetTxBudget(budget)

	if err := s1.EnqueueTx([]byte("12345")); err != nil {
		t.Fatalf("enqueue s1: %v", err)
	}
	if got := budget.Used(); got != 5 {
		t.Fatalf("budget used = %d, want 5", got)
	}

	done := make(chan error, 1)
	go func() {
		done <- s2.EnqueueTx([]byte("x"))
	}()

	select {
	case err := <-done:
		t.Fatalf("second enqueue returned before budget release: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	frames := s1.DrainTx(64 * 1024)
	if len(frames) != 1 || string(frames[0].Payload) != "12345" {
		t.Fatalf("unexpected drained frames: %#v", frames)
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("second enqueue after release: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("second enqueue did not resume after budget release")
	}
	if got := budget.Used(); got != 1 {
		t.Fatalf("budget used after second enqueue = %d, want 1", got)
	}
}

func TestTxBudgetDrainReleasesOnlyDrainedBytes(t *testing.T) {
	budget := NewTxBudget(1024)
	s := New(sid(0x33), "partial.example:443", false)
	s.SetTxBudget(budget)
	if err := s.EnqueueTx(bytes.Repeat([]byte("A"), 250)); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	frames := s.DrainTxLimitedByBudget(100, 10, 150)
	if len(frames) != 2 {
		t.Fatalf("drain frames = %d, want 2", len(frames))
	}
	if got := budget.Used(); got != 100 {
		t.Fatalf("budget used after partial drain = %d, want 100", got)
	}
	_ = s.DrainTxLimitedByBudget(100, 10, 150)
	if got := budget.Used(); got != 0 {
		t.Fatalf("budget used after full drain = %d, want 0", got)
	}
}

func TestRollbackDrainByBudgetRestoresOnlyDrainedPrefixAndBudget(t *testing.T) {
	budget := NewTxBudget(1024)
	s := New(sid(0x37), "rollback.example:443", false)
	s.SetTxBudget(budget)
	if err := s.EnqueueTx([]byte("abcdefghij")); err != nil {
		t.Fatalf("enqueue initial: %v", err)
	}

	first, snap := s.DrainTxLimitedByBudgetTxn(4, 2, 6)
	if len(first) != 2 {
		t.Fatalf("first drain frames = %d, want 2", len(first))
	}
	if got := string(first[0].Payload) + string(first[1].Payload); got != "abcdef" {
		t.Fatalf("first drained payload = %q, want abcdef", got)
	}
	if got := budget.Used(); got != 4 {
		t.Fatalf("budget after partial drain = %d, want 4", got)
	}

	if err := s.EnqueueTx([]byte("XY")); err != nil {
		t.Fatalf("enqueue concurrent: %v", err)
	}
	if got := budget.Used(); got != 6 {
		t.Fatalf("budget after concurrent enqueue = %d, want 6", got)
	}

	s.RollbackDrain(snap)
	if got := budget.Used(); got != 12 {
		t.Fatalf("budget after rollback = %d, want 12", got)
	}

	again := s.DrainTxLimitedByBudget(64*1024, 0, 0)
	var got []byte
	for _, f := range again {
		got = append(got, f.Payload...)
	}
	if string(got) != "abcdefghijXY" {
		t.Fatalf("payload after rollback = %q, want abcdefghijXY", got)
	}
	if got := budget.Used(); got != 0 {
		t.Fatalf("budget after draining rolled-back data = %d, want 0", got)
	}
}

func TestRollbackDrainAfterAbortDoesNotRestoreTransmitState(t *testing.T) {
	budget := NewTxBudget(1024)
	s := New(sid(0x38), "rollback-abort.example:443", true)
	s.SetTxBudget(budget)
	if err := s.EnqueueTx([]byte("queued-before-abort")); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	frames, snap := s.DrainTxLimitedByBudgetTxn(64*1024, 0, 0)
	if len(frames) == 0 || snap == nil {
		t.Fatalf("drain frames=%d snap=%v, want drained snapshot", len(frames), snap)
	}

	s.Abort()
	s.RollbackDrain(snap)

	if err := s.EnqueueTx([]byte("after-abort")); !errors.Is(err, ErrClosed) {
		t.Fatalf("enqueue after rollback/abort err = %v, want ErrClosed", err)
	}
	if frames := s.DrainTx(64 * 1024); len(frames) != 0 {
		t.Fatalf("rollback after abort restored %d frame(s), want none", len(frames))
	}
	if got := budget.Used(); got != 0 {
		t.Fatalf("budget used after rollback/abort = %d, want 0", got)
	}
}

func TestRollbackDrainAfterRequestCloseRestoresPayloadAndFIN(t *testing.T) {
	budget := NewTxBudget(1024)
	s := New(sid(0x39), "rollback-close.example:443", false)
	s.SetTxBudget(budget)
	if err := s.EnqueueTx([]byte("tail")); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	s.RequestClose()

	frames, snap := s.DrainTxLimitedByBudgetTxn(64*1024, 0, 0)
	if len(frames) != 2 || snap == nil {
		t.Fatalf("first drain frames=%d snap=%v, want payload+FIN snapshot", len(frames), snap)
	}
	if got := string(frames[0].Payload); got != "tail" {
		t.Fatalf("first payload = %q, want tail", got)
	}
	if !frames[1].HasFlag(frame.FlagFIN) {
		t.Fatalf("second frame flags=%v, want FIN", frames[1].Flags)
	}

	s.RollbackDrain(snap)

	again := s.DrainTx(64 * 1024)
	if len(again) != 2 {
		t.Fatalf("second drain frames=%d, want payload+FIN restored", len(again))
	}
	if got := string(again[0].Payload); got != "tail" {
		t.Fatalf("restored payload = %q, want tail", got)
	}
	if !again[1].HasFlag(frame.FlagFIN) {
		t.Fatalf("restored second frame flags=%v, want FIN", again[1].Flags)
	}
	if again[0].Seq != frames[0].Seq || again[1].Seq != frames[1].Seq {
		t.Fatalf("restored seqs=%d,%d want original %d,%d", again[0].Seq, again[1].Seq, frames[0].Seq, frames[1].Seq)
	}
}

func TestTxBudgetAbortReleasesQueuedBytes(t *testing.T) {
	budget := NewTxBudget(1024)
	s := New(sid(0x34), "abort.example:443", false)
	s.SetTxBudget(budget)
	if err := s.EnqueueTx([]byte("queued")); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	s.Abort()
	if got := budget.Used(); got != 0 {
		t.Fatalf("budget used after abort = %d, want 0", got)
	}
}

func TestAbortReceiveClosesTransmitSide(t *testing.T) {
	s := New(sid(0x37), "abort-rx.example:443", false)
	defer s.Stop()
	if err := s.EnqueueTx([]byte("before")); err != nil {
		t.Fatalf("enqueue before abortReceive: %v", err)
	}
	called := false
	s.OnAbort = func(reason string) {
		called = true
		if reason != "rx overflow" {
			t.Fatalf("abort reason = %q, want rx overflow", reason)
		}
	}

	s.abortReceive("rx overflow")

	if !called {
		t.Fatal("OnAbort was not called")
	}
	if err := s.EnqueueTx([]byte("after")); !errors.Is(err, ErrClosed) {
		t.Fatalf("EnqueueTx after abortReceive err = %v, want ErrClosed", err)
	}
	if frames := s.DrainTx(64 * 1024); len(frames) != 0 {
		t.Fatalf("DrainTx after abortReceive returned %d frame(s), want none", len(frames))
	}
}

func TestTxBudgetWaiterReturnsWhenSessionCloses(t *testing.T) {
	budget := NewTxBudget(5)
	holder := New(sid(0x35), "holder.example:443", false)
	waiter := New(sid(0x36), "waiter.example:443", false)
	holder.SetTxBudget(budget)
	waiter.SetTxBudget(budget)
	if err := holder.EnqueueTx([]byte("12345")); err != nil {
		t.Fatalf("holder enqueue: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		done <- waiter.EnqueueTx([]byte("x"))
	}()

	select {
	case err := <-done:
		t.Fatalf("waiter returned before close: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	waiter.RequestClose()
	select {
	case err := <-done:
		if err != ErrClosed {
			t.Fatalf("waiter err = %v, want ErrClosed", err)
		}
	case <-time.After(time.Second):
		t.Fatal("waiter did not return after session close")
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

func TestProcessRx_DuplicateDuringBlockedDeliveryDoesNotAckEarly(t *testing.T) {
	s := New(sid(0x40), "", false)
	defer s.Stop()

	for i := 0; i < cap(s.RxChan); i++ {
		s.RxChan <- []byte("filler")
	}

	acks := make(chan uint64, 2)
	s.OnRxAdvance = func(nextSeq uint64) { acks <- nextSeq }
	s.ProcessRx(&frame.Frame{SessionID: s.ID, Seq: 0, Payload: []byte("blocked")})

	deadline := time.Now().Add(time.Second)
	for {
		s.mu.Lock()
		advanced := s.rxSeq == 1
		s.mu.Unlock()
		if advanced {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("rxSeq did not advance while delivery was blocked")
		}
		time.Sleep(time.Millisecond)
	}

	s.ProcessRx(&frame.Frame{SessionID: s.ID, Seq: 0, Payload: []byte("duplicate")})
	select {
	case got := <-acks:
		t.Fatalf("duplicate produced ACK %d before payload was queued to RxChan", got)
	case <-time.After(50 * time.Millisecond):
	}

	<-s.RxChan
	select {
	case got := <-acks:
		if got != 1 {
			t.Fatalf("ACK after unblocking delivery = %d, want 1", got)
		}
	case <-time.After(time.Second):
		t.Fatal("payload delivery did not emit ACK after RxChan had room")
	}
}

func TestProcessRx_CallsOnRxAdvanceAfterInOrderDelivery(t *testing.T) {
	s := New(sid(0x41), "", false)
	defer s.Stop()
	acks := make(chan uint64, 1)
	s.OnRxAdvance = func(nextSeq uint64) { acks <- nextSeq }

	s.ProcessRx(&frame.Frame{SessionID: sid(0x41), Seq: 0, Payload: []byte("hello")})

	if got := <-s.RxChan; string(got) != "hello" {
		t.Fatalf("payload = %q, want hello", got)
	}
	select {
	case got := <-acks:
		if got != 1 {
			t.Fatalf("ack next seq = %d, want 1", got)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for rx advance callback")
	}
}

func TestProcessRxCopiesPayloadBeforeDelivery(t *testing.T) {
	s := New(sid(0x45), "", false)
	defer s.Stop()

	payload := []byte("original")
	s.ProcessRx(&frame.Frame{SessionID: sid(0x45), Seq: 0, Payload: payload})
	payload[0] = 'X'

	select {
	case got := <-s.RxChan:
		if string(got) != "original" {
			t.Fatalf("delivered payload = %q, want original copy", got)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for delivered payload")
	}
}

func TestProcessRx_DoesNotAckOutOfOrderFutureFrame(t *testing.T) {
	s := New(sid(0x42), "", false)
	defer s.Stop()
	acks := make(chan uint64, 2)
	s.OnRxAdvance = func(nextSeq uint64) { acks <- nextSeq }

	s.ProcessRx(&frame.Frame{SessionID: sid(0x42), Seq: 1, Payload: []byte("future")})
	select {
	case got := <-acks:
		t.Fatalf("unexpected ack for future frame: %d", got)
	case <-time.After(50 * time.Millisecond):
	}

	s.ProcessRx(&frame.Frame{SessionID: sid(0x42), Seq: 0, Payload: []byte("first")})
	if got := <-s.RxChan; string(got) != "first" {
		t.Fatalf("first payload = %q", got)
	}
	if got := <-s.RxChan; string(got) != "future" {
		t.Fatalf("second payload = %q", got)
	}
	select {
	case got := <-acks:
		if got != 2 {
			t.Fatalf("ack next seq = %d, want 2", got)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for rx advance callback")
	}
}

func TestProcessRx_DuplicateAfterFINRefreshesACK(t *testing.T) {
	s := New(sid(0x43), "", false)
	acks := make(chan uint64, 4)
	s.OnRxAdvance = func(nextSeq uint64) { acks <- nextSeq }

	s.ProcessRx(&frame.Frame{SessionID: sid(0x43), Seq: 0, Payload: []byte("last"), Flags: frame.FlagFIN})
	if got := <-s.RxChan; string(got) != "last" {
		t.Fatalf("payload = %q, want last", got)
	}
	if _, ok := <-s.RxChan; ok {
		t.Fatal("RxChan should close after FIN")
	}
	select {
	case got := <-acks:
		if got != 1 {
			t.Fatalf("initial ack next seq = %d, want 1", got)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for initial ack")
	}

	s.ProcessRx(&frame.Frame{SessionID: sid(0x43), Seq: 0, Payload: []byte("dup"), Flags: frame.FlagFIN})
	select {
	case got := <-acks:
		if got != 1 {
			t.Fatalf("duplicate ack next seq = %d, want 1", got)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for duplicate ack")
	}
}

func TestProcessRx_ReorderOverflowClosesSession(t *testing.T) {
	s := New(sid(0x44), "", false)
	abortCh := make(chan string, 1)
	s.OnAbort = func(reason string) {
		abortCh <- reason
	}
	for i := 1; i <= rxReorderCap+1; i++ {
		s.ProcessRx(&frame.Frame{SessionID: sid(0x44), Seq: uint64(i), Payload: []byte("future")})
	}

	select {
	case _, ok := <-s.RxChan:
		if ok {
			t.Fatal("RxChan should close after reorder overflow")
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for reorder overflow to close session")
	}
	select {
	case reason := <-abortCh:
		if reason != "rx_reorder_overflow" {
			t.Fatalf("abort reason = %q, want rx_reorder_overflow", reason)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for abort reason")
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

func TestAbortClosesRxAndPreventsFurtherTx(t *testing.T) {
	s := New(sid(0xA), "example.com:443", true)
	s.EnqueueTx([]byte("before-abort"))

	s.Abort()

	if _, ok := <-s.RxChan; ok {
		t.Fatal("RxChan should be closed after Abort")
	}
	s.EnqueueTx([]byte("after-abort"))
	if frames := s.DrainTx(64 * 1024); len(frames) != 0 {
		t.Fatalf("Abort should prevent further TX, got %d frame(s)", len(frames))
	}
}

func TestCloseRxStopsLoopAndClosesRxChan(t *testing.T) {
	s := New(sid(0x1A), "example.com:443", true)

	s.CloseRx()

	select {
	case _, ok := <-s.RxChan:
		if ok {
			t.Fatal("RxChan yielded data after CloseRx")
		}
	case <-time.After(time.Second):
		t.Fatal("RxChan was not closed after CloseRx")
	}
}

func TestAbortUnblocksBackpressuredEnqueue(t *testing.T) {
	s := New(sid(0xB), "example.com:443", false)
	if err := s.EnqueueTx(bytes.Repeat([]byte("A"), TxBufHighWater+1)); err != nil {
		t.Fatalf("initial enqueue: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		done <- s.EnqueueTx([]byte("more"))
	}()
	select {
	case err := <-done:
		t.Fatalf("EnqueueTx returned before abort: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	s.Abort()
	select {
	case err := <-done:
		if err != ErrClosed {
			t.Fatalf("EnqueueTx err = %v, want ErrClosed", err)
		}
	case <-time.After(time.Second):
		t.Fatal("EnqueueTx did not unblock after Abort")
	}
}
