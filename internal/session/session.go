// Package session represents one tunneled TCP connection between a SOCKS5
// client and an upstream target. It owns the per-direction sequence counters,
// the out-of-order rx reassembly queue, the tx buffer with backpressure, and
// the rx channel that VirtualConn reads from.
//
// Ported from FlowDriver/internal/transport/session.go, simplified for the
// HTTP long-poll carrier (no timer-based flush — the carrier drives cadence).
package session

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kianmhz/GooseRelayVPN/internal/frame"
)

// TxBufHighWater is the soft ceiling on the per-session tx buffer; EnqueueTx
// blocks once exceeded so a fast SOCKS5 writer can't cause unbounded growth.
const TxBufHighWater = 8 * 1024 * 1024

const txBufInitialCap = 64 * 1024

var ErrClosed = errors.New("session: closed")

// TxBudget bounds queued client-side TX bytes across many sessions. A single
// write larger than the budget is allowed when the budget is otherwise empty,
// which prevents misconfigured small budgets from deadlocking one large write.
type TxBudget struct {
	mu    sync.Mutex
	cond  *sync.Cond
	limit int
	used  int
}

// NewTxBudget creates a shared TX byte budget. limit <= 0 disables the budget.
func NewTxBudget(limit int) *TxBudget {
	if limit <= 0 {
		return nil
	}
	b := &TxBudget{limit: limit}
	b.cond = sync.NewCond(&b.mu)
	return b
}

// Reserve waits until n bytes can be queued. shouldStop may abort the wait,
// for example when a session closes while a writer is blocked on the budget.
func (b *TxBudget) Reserve(n int, shouldStop func() bool) bool {
	return b.ReserveUntil(n, time.Time{}, shouldStop)
}

// ReserveUntil is Reserve with an optional deadline. It wakes blocked waiters
// when the deadline expires so callers implementing net.Conn deadlines do not
// wait forever when no drain occurs.
func (b *TxBudget) ReserveUntil(n int, deadline time.Time, shouldStop func() bool) bool {
	return b.ReserveUntilFunc(n, func() time.Time { return deadline }, shouldStop)
}

// ReserveUntilFunc is ReserveUntil with a deadline function that is re-read
// while blocked. It lets net.Conn SetWriteDeadline affect an in-progress write.
func (b *TxBudget) ReserveUntilFunc(n int, deadlineFn func() time.Time, shouldStop func() bool) bool {
	if b == nil || n <= 0 {
		return true
	}
	timer := newCondDeadlineTimer(b.cond)
	defer timer.stop()
	b.mu.Lock()
	defer b.mu.Unlock()
	for b.used > 0 && b.used+n > b.limit {
		if shouldStop != nil && shouldStop() {
			return false
		}
		deadline := currentDeadline(deadlineFn)
		if deadlineExpired(deadline) || !timer.refresh(deadline) {
			return false
		}
		b.cond.Wait()
	}
	if shouldStop != nil && shouldStop() {
		return false
	}
	if deadlineExpired(currentDeadline(deadlineFn)) {
		return false
	}
	b.used += n
	return true
}

// Release returns n queued bytes to the shared budget and wakes blocked writers.
func (b *TxBudget) Release(n int) {
	if b == nil || n <= 0 {
		return
	}
	b.mu.Lock()
	b.used -= n
	if b.used < 0 {
		b.used = 0
	}
	b.cond.Broadcast()
	b.mu.Unlock()
}

// Reclaim marks n bytes as queued again after a drained batch is rolled back.
// It intentionally does not block when this temporarily exceeds the limit:
// concurrent writers may have used the released capacity while the batch was
// in flight, and preserving already-accepted TCP bytes is more important than
// strict accounting at the instant of recovery. Later drains release the debt.
func (b *TxBudget) Reclaim(n int) {
	if b == nil || n <= 0 {
		return
	}
	b.mu.Lock()
	b.used += n
	b.mu.Unlock()
}

// Wake wakes budget waiters so they can observe their session close state.
func (b *TxBudget) Wake() {
	if b == nil {
		return
	}
	b.mu.Lock()
	b.cond.Broadcast()
	b.mu.Unlock()
}

func (b *TxBudget) Used() int {
	if b == nil {
		return 0
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.used
}

func (b *TxBudget) Limit() int {
	if b == nil {
		return 0
	}
	return b.limit
}

// sessionFinalTimeout is the maximum time to wait for the peer's FIN after
// we have sent ours. If the peer's FIN frame is lost (e.g. dropped poll
// response), the session would stay in the map forever without this timeout,
// causing the session table to grow unboundedly and the poll loop to slow
// down over time as it iterates more and more dead sessions.
const sessionFinalTimeout = 30 * time.Second

// rxInboxCap bounds how many in-flight frames can be queued from poll workers
// to the per-session rxLoop. Sized so a multi-user client absorbing a full
// busy-mode batch (144 frames) for one session across two simultaneous
// responses cannot overflow during a brief consumer pause. Received payloads
// are cloned before enqueue so replay/duplicate handling cannot be corrupted
// by response-buffer reuse; tune this alongside receive byte budgets.
const rxInboxCap = 1024

// rxInboxBlockTimeout is how long ProcessRx waits for rxInbox to drain when
// it is full before killing the session. Real consumer stalls are typically
// sub-second (GC pause, syscall blocked, page fault); only true deadlocks
// last longer, and those should drop the session.
const rxInboxBlockTimeout = 5 * time.Second

// rxReorderCap bounds future frames held while waiting for a missing sequence.
// If a relay response is lost, later frames cannot be delivered anyway; closing
// the session is better than letting an unbounded map grow until idle GC.
const rxReorderCap = 512

// Session is one logical TCP connection across the relay.
type Session struct {
	ID     [frame.SessionIDLen]byte
	Target string // "host:port", carried on the SYN frame

	mu       sync.Mutex
	txCond   *sync.Cond
	txBuf    []byte
	txBudget *TxBudget
	txSeq    uint64
	rxSeq    uint64
	rxAckSeq uint64
	rxQueue  map[uint64]*frame.Frame

	synNeeded     bool // first outgoing frame must carry SYN+Target
	closeReq      bool // VirtualConn.Close() called; FIN must be sent on next drain
	txClosed      atomic.Bool
	aborted       bool
	finSent       bool
	finSentAt     time.Time // when finSent was set; used for orphan reaping
	firstQueuedAt time.Time // timestamp of the oldest frame waiting to be sent
	rxClosed      bool      // RxChan has been closed (peer FIN received)

	RxChan chan []byte

	// OnTx is invoked when EnqueueTx adds data and when closeReq transitions
	// true. The carrier sets it to wake its long-poll loop.
	OnTx func()

	// OnAbort is invoked when the session self-terminates due to defensive
	// receive-side limits such as reorder overflow or a blocked RX inbox.
	OnAbort func(reason string)

	// OnRxAdvance is invoked when downstream frames have been accepted in
	// sequence and queued to RxChan. nextSeq is the next expected downstream
	// sequence number, so all frames with Seq < nextSeq are safe to ACK at the
	// tunnel layer even if the local SOCKS consumer has not read them yet.
	OnRxAdvance func(nextSeq uint64)

	// rxInbox is the per-session inbox for incoming frames. rxLoop drains it
	// so poll workers are never blocked by a slow SOCKS consumer on one session
	// holding up frame delivery for all other sessions.
	rxInbox  chan *frame.Frame
	rxDone   chan struct{}
	stopOnce sync.Once
}

// SetTxBudget attaches a shared queued-TX memory budget. Call before publishing
// the session to writers.
func (s *Session) SetTxBudget(b *TxBudget) {
	s.mu.Lock()
	s.txBudget = b
	s.mu.Unlock()
}

// New creates a session with a random ID is the caller's responsibility — pass
// it in. needsSYN should be true on the client side (so the first frame carries
// the SYN flag and Target), false on the server side (created from a received
// SYN).
func New(id [frame.SessionIDLen]byte, target string, needsSYN bool) *Session {
	s := &Session{
		ID:        id,
		Target:    target,
		rxQueue:   make(map[uint64]*frame.Frame),
		RxChan:    make(chan []byte, 1024),
		synNeeded: needsSYN,
		rxInbox:   make(chan *frame.Frame, rxInboxCap),
		rxDone:    make(chan struct{}),
	}
	if needsSYN {
		s.firstQueuedAt = time.Now()
	}
	s.txCond = sync.NewCond(&s.mu)
	go s.rxLoop()
	return s
}

// Stop signals the rxLoop goroutine to exit. Must be called after removing the
// session from the routing table so no new ProcessRx calls can arrive.
func (s *Session) Stop() {
	s.stopOnce.Do(func() { close(s.rxDone) })
}

// Abort tears the session down locally without emitting a FIN/RST frame. It is
// used when the carrier cannot reach any relay endpoint: the local SOCKS side
// needs EOF immediately so the calling VPN app reconnects instead of writing
// into a black hole.
func (s *Session) Abort() {
	s.mu.Lock()
	s.txClosed.Store(true)
	s.aborted = true
	releaseBytes := len(s.txBuf)
	budget := s.txBudget
	s.closeReq = true
	s.txBuf = nil
	s.synNeeded = false
	s.finSent = true
	s.firstQueuedAt = time.Time{}
	s.OnTx = nil
	s.txCond.Broadcast()
	s.mu.Unlock()
	budget.Release(releaseBytes)
	budget.Wake()
	s.Stop()
}

func (s *Session) abortReceive(reason string) {
	if s.OnAbort != nil {
		s.OnAbort(reason)
	}
	s.Abort()
}

// rxLoop is a per-session goroutine that delivers frames from rxInbox to RxChan
// in sequence order. Running it independently from poll workers means a slow
// SOCKS reader on one session cannot stall frame delivery for any other session.
func (s *Session) rxLoop() {
	defer func() {
		// Guarantee RxChan is closed when rxLoop exits for any reason (rxDone
		// fired, FIN processed, or session killed via ProcessRx overflow). This
		// unblocks any goroutine ranging over RxChan without a separate close call.
		s.mu.Lock()
		if !s.rxClosed {
			s.rxClosed = true
			close(s.RxChan)
		}
		s.mu.Unlock()
	}()
	for {
		select {
		case f := <-s.rxInbox:
			if s.deliverRx(f) {
				return
			}
		case <-s.rxDone:
			return
		}
	}
}

// EnqueueTx appends bytes to the session's tx buffer. Blocks while the buffer
// exceeds TxBufHighWater. Safe to call concurrently with DrainTx.
func (s *Session) EnqueueTx(data []byte) error {
	return s.EnqueueTxDeadline(data, time.Time{})
}

// EnqueueTxDeadline appends bytes to the tx buffer, respecting deadline when
// backpressure or the global TX budget blocks the write.
func (s *Session) EnqueueTxDeadline(data []byte, deadline time.Time) error {
	return s.EnqueueTxDeadlineFunc(data, func() time.Time { return deadline })
}

// EnqueueTxDeadlineFunc is EnqueueTxDeadline with a deadline function that is
// re-read while blocked. This supports net.Conn SetWriteDeadline semantics for
// writes that are already waiting on backpressure.
func (s *Session) EnqueueTxDeadlineFunc(data []byte, deadlineFn func() time.Time) error {
	s.mu.Lock()
	timer := newCondDeadlineTimer(s.txCond)
	defer timer.stop()
	for len(s.txBuf) > TxBufHighWater && !s.closeReq {
		deadline := currentDeadline(deadlineFn)
		if deadlineExpired(deadline) || !timer.refresh(deadline) {
			s.mu.Unlock()
			return context.DeadlineExceeded
		}
		s.txCond.Wait()
	}
	if s.closeReq {
		s.mu.Unlock()
		return ErrClosed
	}
	budget := s.txBudget
	s.mu.Unlock()

	if !budget.ReserveUntilFunc(len(data), deadlineFn, func() bool { return s.txClosed.Load() }) {
		if s.txClosed.Load() {
			return ErrClosed
		}
		if deadlineExpired(currentDeadline(deadlineFn)) {
			return context.DeadlineExceeded
		}
		return ErrClosed
	}

	s.mu.Lock()
	for len(s.txBuf) > TxBufHighWater && !s.closeReq {
		deadline := currentDeadline(deadlineFn)
		if deadlineExpired(deadline) || !timer.refresh(deadline) {
			s.mu.Unlock()
			budget.Release(len(data))
			return context.DeadlineExceeded
		}
		s.txCond.Wait()
	}
	if s.closeReq {
		s.mu.Unlock()
		budget.Release(len(data))
		return ErrClosed
	}
	if s.txBuf == nil {
		capHint := txBufInitialCap
		if len(data) > capHint {
			capHint = len(data)
		}
		s.txBuf = make([]byte, 0, capHint)
	}
	s.txBuf = append(s.txBuf, data...)
	if s.firstQueuedAt.IsZero() {
		s.firstQueuedAt = time.Now()
	}
	cb := s.OnTx
	s.mu.Unlock()
	if cb != nil {
		cb()
	}
	return nil
}

// EnqueueInitialData appends data to the tx buffer while synNeeded is still
// true, so the first DrainTx call bundles it into the SYN frame payload. The
// SOCKS adapter can call this multiple times before the carrier drains the SYN;
// appending preserves stream byte order across those calls.
func (s *Session) EnqueueInitialData(data []byte) error {
	return s.EnqueueInitialDataDeadline(data, time.Time{})
}

// EnqueueInitialDataDeadline is EnqueueInitialData with an optional write
// deadline for net.Conn compatibility.
func (s *Session) EnqueueInitialDataDeadline(data []byte, deadline time.Time) error {
	return s.EnqueueInitialDataDeadlineFunc(data, func() time.Time { return deadline })
}

// EnqueueInitialDataDeadlineFunc is EnqueueInitialDataDeadline with a deadline
// function that can change while the caller is blocked.
func (s *Session) EnqueueInitialDataDeadlineFunc(data []byte, deadlineFn func() time.Time) error {
	s.mu.Lock()
	if !s.synNeeded {
		// Too late, SYN already sent. Just regular enqueue.
		s.mu.Unlock()
		return s.EnqueueTxDeadlineFunc(data, deadlineFn)
	}
	timer := newCondDeadlineTimer(s.txCond)
	defer timer.stop()
	if s.closeReq {
		s.mu.Unlock()
		return ErrClosed
	}
	for len(s.txBuf) > TxBufHighWater && !s.closeReq {
		deadline := currentDeadline(deadlineFn)
		if deadlineExpired(deadline) || !timer.refresh(deadline) {
			s.mu.Unlock()
			return context.DeadlineExceeded
		}
		s.txCond.Wait()
	}
	if s.closeReq {
		s.mu.Unlock()
		return ErrClosed
	}
	budget := s.txBudget
	s.mu.Unlock()

	if !budget.ReserveUntilFunc(len(data), deadlineFn, func() bool { return s.txClosed.Load() }) {
		if s.txClosed.Load() {
			return ErrClosed
		}
		if deadlineExpired(currentDeadline(deadlineFn)) {
			return context.DeadlineExceeded
		}
		return ErrClosed
	}

	s.mu.Lock()
	for len(s.txBuf) > TxBufHighWater && !s.closeReq {
		deadline := currentDeadline(deadlineFn)
		if deadlineExpired(deadline) || !timer.refresh(deadline) {
			s.mu.Unlock()
			budget.Release(len(data))
			return context.DeadlineExceeded
		}
		s.txCond.Wait()
	}
	if s.closeReq {
		s.mu.Unlock()
		budget.Release(len(data))
		return ErrClosed
	}
	if s.txBuf == nil {
		capHint := txBufInitialCap
		if len(data) > capHint {
			capHint = len(data)
		}
		s.txBuf = make([]byte, 0, capHint)
	}
	s.txBuf = append(s.txBuf, data...)
	if s.firstQueuedAt.IsZero() {
		s.firstQueuedAt = time.Now()
	}
	cb := s.OnTx
	s.mu.Unlock()
	if cb != nil {
		cb()
	}
	return nil
}

// WakeTxWaiters wakes writers blocked on this session or its shared TX budget.
// It is used when a net.Conn write deadline changes while a Write is already
// blocked.
func (s *Session) WakeTxWaiters() {
	s.mu.Lock()
	budget := s.txBudget
	s.txCond.Broadcast()
	s.mu.Unlock()
	budget.Wake()
}

type condDeadlineTimer struct {
	cond     *sync.Cond
	timer    *time.Timer
	deadline time.Time
}

func newCondDeadlineTimer(cond *sync.Cond) *condDeadlineTimer {
	return &condDeadlineTimer{cond: cond}
}

func (t *condDeadlineTimer) refresh(deadline time.Time) bool {
	if deadline.IsZero() {
		t.stop()
		t.deadline = time.Time{}
		return true
	}
	if deadlineExpired(deadline) {
		return false
	}
	if t.timer != nil && t.deadline.Equal(deadline) {
		return true
	}
	t.stop()
	t.deadline = deadline
	d := time.Until(deadline)
	if d <= 0 {
		return false
	}
	t.timer = time.AfterFunc(d, func() {
		t.cond.Broadcast()
	})
	return true
}

func (t *condDeadlineTimer) stop() {
	if t.timer == nil {
		return
	}
	t.timer.Stop()
	t.timer = nil
}

func currentDeadline(deadlineFn func() time.Time) time.Time {
	if deadlineFn == nil {
		return time.Time{}
	}
	return deadlineFn()
}

func deadlineExpired(deadline time.Time) bool {
	return !deadline.IsZero() && !time.Now().Before(deadline)
}

// RequestClose marks the session for shutdown. The next DrainTx will emit a
// FIN frame, and EnqueueTx becomes a no-op.
func (s *Session) RequestClose() {
	s.mu.Lock()
	s.txClosed.Store(true)
	budget := s.txBudget
	s.closeReq = true
	if s.firstQueuedAt.IsZero() {
		s.firstQueuedAt = time.Now()
	}
	s.txCond.Broadcast()
	cb := s.OnTx
	s.mu.Unlock()
	budget.Wake()
	if cb != nil {
		cb()
	}
}

// CloseRx requests receive-side shutdown. The rxLoop owns RxChan closure; this
// method is kept for old callers without racing close(RxChan) against delivery.
func (s *Session) CloseRx() {
	s.Stop()
}

// HasPendingTx reports whether DrainTx would emit at least one frame.
func (s *Session) HasPendingTx() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.synNeeded || len(s.txBuf) > 0 || (s.closeReq && !s.finSent)
}

// HasPendingSYN reports whether the next drain will emit a SYN frame.
// Used by the carrier to prioritise new-connection setup over ongoing data
// transfers so a large upload/download cannot delay connection establishment.
func (s *Session) HasPendingSYN() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.synNeeded
}

// FirstQueuedAt returns the timestamp of the oldest frame waiting to be sent.
func (s *Session) FirstQueuedAt() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.firstQueuedAt
}

// IsDone reports whether both FIN frames (sent and received) have flowed,
// OR whether we sent our FIN but the peer's FIN never arrived within
// sessionFinalTimeout. The timeout prevents orphaned sessions from accumulating
// in the carrier's session map when a relay response carrying the peer's FIN
// is dropped.
func (s *Session) IsDone() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.finSent && s.rxClosed {
		return true
	}
	// Reap orphaned sessions: we sent our FIN but never received the peer's.
	if s.finSent && !s.finSentAt.IsZero() && time.Since(s.finSentAt) > sessionFinalTimeout {
		return true
	}
	return false
}

// DrainSnapshot captures the part of a drain that must be restored if the
// caller knows the batch did not reach the relay. The snapshot is opaque to
// callers; use RollbackDrain to apply it.
type DrainSnapshot struct {
	synNeeded     bool
	drainedTx     []byte
	txSeq         uint64
	finSent       bool
	finSentAt     time.Time
	firstQueuedAt time.Time
	budgetBytes   int
}

// DrainTx removes pending tx bytes and returns them as a sequence of frames,
// each capped at maxPayload bytes. Emits a SYN frame first if needed, and a
// trailing FIN frame if RequestClose was called and the FIN hasn't been sent yet.
func (s *Session) DrainTx(maxPayload int) []*frame.Frame {
	frames, _ := s.drainTx(maxPayload, 0, 0, false)
	return frames
}

// DrainTxLimited is like DrainTx but emits at most maxFrames frames in one
// call (0 means unlimited). Remaining bytes stay queued for later polls.
func (s *Session) DrainTxLimited(maxPayload, maxFrames int) []*frame.Frame {
	frames, _ := s.drainTx(maxPayload, maxFrames, 0, false)
	return frames
}

// DrainTxLimitedByBudget is like DrainTxLimited but also caps payload bytes
// emitted in one call (0 means unlimited). It may split the next payload frame
// below maxPayload to use the remaining byte budget while preserving sequence
// order.
func (s *Session) DrainTxLimitedByBudget(maxPayload, maxFrames, maxBytes int) []*frame.Frame {
	frames, _ := s.drainTx(maxPayload, maxFrames, maxBytes, false)
	return frames
}

// DrainTxLimitedByBudgetTxn is like DrainTxLimitedByBudget but also returns a
// snapshot that can restore drained bytes and sequence state if the caller
// knows the batch did not reach the relay.
func (s *Session) DrainTxLimitedByBudgetTxn(maxPayload, maxFrames, maxBytes int) ([]*frame.Frame, *DrainSnapshot) {
	return s.drainTx(maxPayload, maxFrames, maxBytes, true)
}

func (s *Session) drainTx(maxPayload, maxFrames, maxBytes int, withSnapshot bool) ([]*frame.Frame, *DrainSnapshot) {
	s.mu.Lock()
	defer s.mu.Unlock()
	drainedBytes := 0
	var snap *DrainSnapshot
	var preDrainTx []byte

	if withSnapshot {
		preDrainTx = s.txBuf
		snap = &DrainSnapshot{
			synNeeded:     s.synNeeded,
			txSeq:         s.txSeq,
			finSent:       s.finSent,
			finSentAt:     s.finSentAt,
			firstQueuedAt: s.firstQueuedAt,
		}
	}

	if !s.synNeeded && len(s.txBuf) == 0 && !(s.closeReq && !s.finSent) {
		return nil, nil
	}

	// Estimate capacity up front to avoid repeated slice growth under large
	// uploads/downloads that split into many payload chunks.
	estFrames := 0
	if s.synNeeded {
		estFrames++
	}
	if len(s.txBuf) > 0 {
		if maxPayload <= 0 {
			maxPayload = len(s.txBuf)
		}
		// First data chunk may ride on SYN, so payload-only frame count is
		// bounded by ceil(len(txBuf)/maxPayload).
		estFrames += (len(s.txBuf) + maxPayload - 1) / maxPayload
	}
	if s.closeReq && !s.finSent {
		estFrames++
	}
	if maxFrames > 0 && estFrames > maxFrames {
		estFrames = maxFrames
	}
	frames := make([]*frame.Frame, 0, estFrames)

	canAppend := func() bool {
		return maxFrames <= 0 || len(frames) < maxFrames
	}
	bytesLeft := maxBytes
	canAppendPayload := func() bool {
		return maxBytes <= 0 || bytesLeft > 0
	}
	nextPayloadSize := func(available int) int {
		n := available
		if n > maxPayload {
			n = maxPayload
		}
		if maxBytes > 0 && n > bytesLeft {
			n = bytesLeft
		}
		return n
	}

	// SYN (possibly with first chunk of payload).
	if s.synNeeded && canAppend() {
		f := &frame.Frame{
			SessionID: s.ID,
			Seq:       s.txSeq,
			Flags:     frame.FlagSYN,
			Target:    s.Target,
		}
		s.txSeq++
		s.synNeeded = false
		if len(s.txBuf) > 0 && canAppendPayload() {
			n := nextPayloadSize(len(s.txBuf))
			// Zero-copy slice into txBuf. EncodeBatch seals the plaintext before
			// the next drain, so the backing array is safe to reference here.
			f.Payload = s.txBuf[:n]
			s.txBuf = s.txBuf[n:]
			drainedBytes += n
			if maxBytes > 0 {
				bytesLeft -= n
			}
		}
		frames = append(frames, f)
	}

	// Remaining payload chunks.
	for len(s.txBuf) > 0 && canAppend() && canAppendPayload() {
		n := nextPayloadSize(len(s.txBuf))
		f := &frame.Frame{
			SessionID: s.ID,
			Seq:       s.txSeq,
			Payload:   s.txBuf[:n], // zero-copy slice; safe (see SYN comment above)
		}
		s.txSeq++
		s.txBuf = s.txBuf[n:]
		drainedBytes += n
		if maxBytes > 0 {
			bytesLeft -= n
		}
		frames = append(frames, f)
	}

	// When the buffer is fully drained, nil it so the backing array can be
	// GC'd. txBuf advances via txBuf[n:] slicing, which keeps the original
	// large allocation alive even after all data is consumed. Niling releases
	// the reference; the next EnqueueTx will allocate a fresh slice.
	// Note: zero-copy Frame.Payload slices above still reference the old
	// backing array — they keep it alive until EncodeBatch serializes them.
	if len(s.txBuf) == 0 {
		s.txBuf = nil
	}

	// Trailing FIN.
	if s.closeReq && !s.finSent && canAppend() {
		frames = append(frames, &frame.Frame{
			SessionID: s.ID,
			Seq:       s.txSeq,
			Flags:     frame.FlagFIN,
		})
		s.txSeq++
		s.finSent = true
		s.finSentAt = time.Now()
	}

	// If everything was drained, clear the queue timestamp.
	if !s.synNeeded && len(s.txBuf) == 0 && !(s.closeReq && !s.finSent) {
		s.firstQueuedAt = time.Time{}
	}

	s.txCond.Broadcast() // wake any backpressured writers
	s.txBudget.Release(drainedBytes)
	if len(frames) == 0 {
		snap = nil
	} else if snap != nil && drainedBytes > 0 {
		snap.drainedTx = preDrainTx[:drainedBytes]
		snap.budgetBytes = drainedBytes
	}
	return frames, snap
}

// RollbackDrain restores sequence/control state and prepends the drained byte
// prefix to any bytes queued while the batch was in flight. It is only safe for
// failures where the caller knows the relay did not accept the batch.
func (s *Session) RollbackDrain(snap *DrainSnapshot) {
	s.rollbackDrain(snap, true)
}

// RollbackDrainNoNotify restores a drain without invoking OnTx. It is for
// callers that must restore several queues/control frames atomically before
// waking the owner.
func (s *Session) RollbackDrainNoNotify(snap *DrainSnapshot) {
	s.rollbackDrain(snap, false)
}

func (s *Session) rollbackDrain(snap *DrainSnapshot, notify bool) {
	if snap == nil {
		return
	}
	s.mu.Lock()
	if s.aborted {
		s.txCond.Broadcast()
		s.mu.Unlock()
		s.txBudget.Wake()
		return
	}
	if len(snap.drainedTx) > 0 {
		if len(s.txBuf) == 0 {
			s.txBuf = snap.drainedTx
		} else {
			merged := make([]byte, 0, len(snap.drainedTx)+len(s.txBuf))
			merged = append(merged, snap.drainedTx...)
			merged = append(merged, s.txBuf...)
			s.txBuf = merged
		}
	}
	s.synNeeded = snap.synNeeded
	s.txSeq = snap.txSeq
	s.finSent = snap.finSent
	s.finSentAt = snap.finSentAt
	if !snap.firstQueuedAt.IsZero() {
		if s.firstQueuedAt.IsZero() || snap.firstQueuedAt.Before(s.firstQueuedAt) {
			s.firstQueuedAt = snap.firstQueuedAt
		}
	}
	s.txBudget.Reclaim(snap.budgetBytes)
	cb := s.OnTx
	s.txCond.Broadcast()
	s.mu.Unlock()
	if notify && cb != nil {
		cb()
	}
}

// ProcessRx enqueues f to the per-session rxLoop goroutine. The fast path is
// non-blocking. If rxInbox is saturated (slow SOCKS consumer or large burst),
// we wait up to rxInboxBlockTimeout to absorb the transient backpressure
// before declaring the session dead and killing it. Blocking briefly is far
// preferable to nuking an entire connection over a few-millisecond consumer
// stall — the original kill-on-overflow behavior caused mid-stream session
// drops under multi-user fan-out and brief GC pauses.
func (s *Session) ProcessRx(f *frame.Frame) {
	s.mu.Lock()
	if f.Seq < s.rxSeq {
		ackNext := s.rxAckSeq
		cb := s.OnRxAdvance
		s.mu.Unlock()
		if cb != nil && ackNext > f.Seq {
			cb(ackNext)
		}
		return
	}
	if s.rxClosed {
		s.mu.Unlock()
		return
	}
	f = cloneRxFramePayload(f)
	s.mu.Unlock()
	// Fast path: enqueue without blocking when there is room.
	select {
	case s.rxInbox <- f:
		return
	case <-s.rxDone:
		return
	default:
	}
	// Slow path: rxInbox is full. Block briefly so transient consumer pauses
	// (GC, syscall, page fault) don't tear down the session. Only kill on a
	// genuine deadlock that exceeds rxInboxBlockTimeout.
	t := time.NewTimer(rxInboxBlockTimeout)
	defer t.Stop()
	select {
	case s.rxInbox <- f:
	case <-s.rxDone:
	case <-t.C:
		s.abortReceive("rx_inbox_timeout")
	}
}

// deliverRx performs in-order reassembly and delivers payloads to RxChan.
// Called exclusively by rxLoop. Returns true when a FIN frame is processed
// and the session's rx side is done.
func (s *Session) deliverRx(f *frame.Frame) bool {
	s.mu.Lock()
	if f.Seq < s.rxSeq {
		ackNext := s.rxAckSeq
		cb := s.OnRxAdvance
		s.mu.Unlock()
		if cb != nil && ackNext > f.Seq {
			cb(ackNext)
		}
		return false
	}
	if s.rxClosed {
		s.mu.Unlock()
		return true
	}
	if f.Seq > s.rxSeq {
		if _, exists := s.rxQueue[f.Seq]; !exists {
			if len(s.rxQueue) >= rxReorderCap {
				s.mu.Unlock()
				s.abortReceive("rx_reorder_overflow")
				return true
			}
			s.rxQueue[f.Seq] = f
		}
		s.mu.Unlock()
		return false
	}

	var toSend [][]byte
	var closeAfter bool
	var ackNext uint64
	for {
		if len(f.Payload) > 0 {
			toSend = append(toSend, f.Payload)
		}
		s.rxSeq++
		ackNext = s.rxSeq
		if f.HasFlag(frame.FlagFIN) {
			s.rxClosed = true
			closeAfter = true
			break
		}
		next, ok := s.rxQueue[s.rxSeq]
		if !ok {
			break
		}
		delete(s.rxQueue, s.rxSeq)
		f = next
	}
	s.mu.Unlock()

	for _, p := range toSend {
		select {
		case s.RxChan <- p:
		case <-s.rxDone:
			// Session was killed (e.g. rxInbox overflow). If a FIN was already
			// decoded, close RxChan now; otherwise rxLoop's defer handles it.
			if closeAfter {
				close(s.RxChan)
			}
			return true
		}
	}
	s.mu.Lock()
	if ackNext > s.rxAckSeq {
		s.rxAckSeq = ackNext
	}
	cb := s.OnRxAdvance
	s.mu.Unlock()
	if cb != nil && ackNext > 0 {
		cb(ackNext)
	}
	if closeAfter {
		close(s.RxChan)
		s.Stop()
	}
	return closeAfter
}

func cloneRxFramePayload(f *frame.Frame) *frame.Frame {
	if len(f.Payload) == 0 {
		return f
	}
	cp := *f
	cp.Payload = clonePayload(f.Payload)
	return &cp
}

func clonePayload(p []byte) []byte {
	if len(p) == 0 {
		return nil
	}
	cp := make([]byte, len(p))
	copy(cp, p)
	return cp
}
