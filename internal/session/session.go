// Package session represents one tunneled TCP connection between a SOCKS5
// client and an upstream target. It owns the per-direction sequence counters,
// the out-of-order rx reassembly queue, the tx buffer with backpressure, and
// the rx channel that VirtualConn reads from.
//
// Ported from FlowDriver/internal/transport/session.go, simplified for the
// HTTP long-poll carrier (no timer-based flush — the carrier drives cadence).
package session

import (
	"sync"
	"time"

	"github.com/kianmhz/GooseRelayVPN/internal/frame"
)

// TxBufHighWater is the soft ceiling on the per-session tx buffer; EnqueueTx
// blocks once exceeded so a fast SOCKS5 writer can't cause unbounded growth.
const TxBufHighWater = 8 * 1024 * 1024

// sessionFinalTimeout is the maximum time to wait for the peer's FIN after
// we have sent ours. If the peer's FIN frame is lost (e.g. dropped poll
// response), the session would stay in the map forever without this timeout,
// causing the session table to grow unboundedly and the poll loop to slow
// down over time as it iterates more and more dead sessions.
const sessionFinalTimeout = 30 * time.Second

// rxInboxCap bounds how many in-flight frames can be queued from poll workers
// to the per-session rxLoop. Sized so a multi-user client absorbing a full
// busy-mode batch (144 frames) for one session across two simultaneous
// responses cannot overflow during a brief consumer pause. With 256KB max
// payload this is at most rxInboxCap × 256KB worth of pointers (the payloads
// themselves are zero-copy slices into the response body, GC'd as drained).
const rxInboxCap = 1024

// rxInboxBlockTimeout is how long ProcessRx waits for rxInbox to drain when
// it is full before killing the session. Real consumer stalls are typically
// sub-second (GC pause, syscall blocked, page fault); only true deadlocks
// last longer, and those should drop the session.
const rxInboxBlockTimeout = 5 * time.Second

// Session is one logical TCP connection across the relay.
type Session struct {
	ID     [frame.SessionIDLen]byte
	Target string // "host:port", carried on the SYN frame

	mu      sync.Mutex
	txCond  *sync.Cond
	txBuf   []byte
	txSeq   uint64
	rxSeq   uint64
	rxQueue map[uint64]*frame.Frame

	synNeeded     bool // first outgoing frame must carry SYN+Target
	closeReq      bool // VirtualConn.Close() called; FIN must be sent on next drain
	finSent       bool
	finSentAt     time.Time // when finSent was set; used for orphan reaping
	firstQueuedAt time.Time // timestamp of the oldest frame waiting to be sent
	rxClosed      bool      // RxChan has been closed (peer FIN received)

	RxChan chan []byte

	// OnTx is invoked when EnqueueTx adds data and when closeReq transitions
	// true. The carrier sets it to wake its long-poll loop.
	OnTx func()

	// rxInbox is the per-session inbox for incoming frames. rxLoop drains it
	// so poll workers are never blocked by a slow SOCKS consumer on one session
	// holding up frame delivery for all other sessions.
	rxInbox  chan *frame.Frame
	rxDone   chan struct{}
	stopOnce sync.Once
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
func (s *Session) EnqueueTx(data []byte) {
	s.mu.Lock()
	for len(s.txBuf) > TxBufHighWater && !s.closeReq {
		s.txCond.Wait()
	}
	if s.closeReq {
		s.mu.Unlock()
		return
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
}

// EnqueueInitialData appends data to the tx buffer while synNeeded is still
// true, so the first DrainTx call bundles it into the SYN frame's payload
// (the connect_data optimization — saves one round-trip on every TLS
// handshake and HTTP request).
//
// Previously this prepended, on the assumption it'd be called once before
// any other write. But the SOCKS5 adapter calls it on every Write, and the
// local write loop is frequently faster than poll workers — multiple calls
// land before the SYN drains, and prepending REVERSES byte order. For a
// payload whose first bytes carry framing/length (a TLS record header, an
// HTTP request line, the bench harness's 8-byte size prefix), reordering
// silently corrupts the upstream stream. The bug also rendered every
// upload-throughput benchmark we have meaningless: with a size-prefixed
// payload of zeros, the upstream parsed a body chunk's leading zeros as
// "expect 0 bytes" and ACKed immediately, making upload look ~5× faster
// than it actually was.
func (s *Session) EnqueueInitialData(data []byte) {
	s.mu.Lock()
	if !s.synNeeded {
		// Too late, SYN already sent. Just regular enqueue.
		s.mu.Unlock()
		s.EnqueueTx(data)
		return
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
}

// RequestClose marks the session for shutdown. The next DrainTx will emit a
// FIN frame, and EnqueueTx becomes a no-op.
func (s *Session) RequestClose() {
	s.mu.Lock()
	s.closeReq = true
	if s.firstQueuedAt.IsZero() {
		s.firstQueuedAt = time.Now()
	}
	s.txCond.Broadcast()
	cb := s.OnTx
	s.mu.Unlock()
	if cb != nil {
		cb()
	}
}

// CloseRx closes RxChan if not already closed. Idempotent.
func (s *Session) CloseRx() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.rxClosed {
		s.rxClosed = true
		close(s.RxChan)
	}
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

// DrainSnapshot captures the pre-drain state of a session so the caller can
// roll back via RollbackDrain if the batch carrying the drained frames cannot
// be transmitted. The snapshot is opaque to callers.
type DrainSnapshot struct {
	synNeeded     bool
	txBuf         []byte
	txSeq         uint64
	finSent       bool
	finSentAt     time.Time
	firstQueuedAt time.Time
}

// DrainTx removes pending tx bytes and returns them as a sequence of frames,
// each capped at maxPayload bytes. Emits a SYN frame first if needed, and a
// trailing FIN frame if RequestClose was called and the FIN hasn't been sent yet.
func (s *Session) DrainTx(maxPayload int) []*frame.Frame {
	frames, _ := s.drainTx(maxPayload, 0, false)
	return frames
}

// DrainTxLimited is like DrainTx but emits at most maxFrames frames in one
// call (0 means unlimited). Remaining bytes stay queued for later polls.
func (s *Session) DrainTxLimited(maxPayload, maxFrames int) []*frame.Frame {
	frames, _ := s.drainTx(maxPayload, maxFrames, false)
	return frames
}

// DrainTxLimitedTxn is like DrainTxLimited but also returns a snapshot of the
// pre-drain state. If the caller cannot transmit the returned frames (HTTP
// error, decode failure, classified quota response, etc.), pass the snapshot
// to RollbackDrain to restore the session. If the transmission succeeds, the
// snapshot is discarded — the drained state is already applied.
//
// Any data enqueued via EnqueueTx between this call and a RollbackDrain is
// preserved; rollback restores the unsent prefix and then keeps the new data
// after it.
func (s *Session) DrainTxLimitedTxn(maxPayload, maxFrames int) ([]*frame.Frame, *DrainSnapshot) {
	return s.drainTx(maxPayload, maxFrames, true)
}

func (s *Session) drainTx(maxPayload, maxFrames int, withSnapshot bool) ([]*frame.Frame, *DrainSnapshot) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var snap *DrainSnapshot
	if withSnapshot {
		snap = &DrainSnapshot{
			synNeeded:     s.synNeeded,
			txBuf:         s.txBuf,
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
		if len(s.txBuf) > 0 {
			n := len(s.txBuf)
			if n > maxPayload {
				n = maxPayload
			}
			// Zero-copy slice into txBuf. EncodeBatch seals the plaintext before
			// the next drain, so the backing array is safe to reference here.
			f.Payload = s.txBuf[:n]
			s.txBuf = s.txBuf[n:]
		}
		frames = append(frames, f)
	}

	// Remaining payload chunks.
	for len(s.txBuf) > 0 && canAppend() {
		n := len(s.txBuf)
		if n > maxPayload {
			n = maxPayload
		}
		f := &frame.Frame{
			SessionID: s.ID,
			Seq:       s.txSeq,
			Payload:   s.txBuf[:n], // zero-copy slice; safe (see SYN comment above)
		}
		s.txSeq++
		s.txBuf = s.txBuf[n:]
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
	if len(frames) == 0 {
		// No frames produced — caller has nothing to roll back.
		snap = nil
	}
	return frames, snap
}

// RollbackDrain restores the session to the state captured in snap, undoing a
// previous DrainTxLimitedTxn whose frames could not be transmitted. Any data
// enqueued in the meantime is preserved (appended after the restored bytes).
// Calling with a nil snapshot is a no-op.
func (s *Session) RollbackDrain(snap *DrainSnapshot) {
	if snap == nil {
		return
	}
	s.mu.Lock()
	// Merge: snapshot bytes (drained but unsent) first, then any new bytes
	// queued during the in-flight window.
	if len(snap.txBuf) > 0 {
		if len(s.txBuf) == 0 {
			s.txBuf = snap.txBuf
		} else {
			merged := make([]byte, 0, len(snap.txBuf)+len(s.txBuf))
			merged = append(merged, snap.txBuf...)
			merged = append(merged, s.txBuf...)
			s.txBuf = merged
		}
	}
	if snap.synNeeded {
		s.synNeeded = true
	}
	// txSeq must reset so retransmitted frames carry the same seq numbers the
	// server would have seen on the first (lost) attempt.
	s.txSeq = snap.txSeq
	if !snap.finSent {
		s.finSent = false
		s.finSentAt = time.Time{}
	}
	if !snap.firstQueuedAt.IsZero() {
		if s.firstQueuedAt.IsZero() || snap.firstQueuedAt.Before(s.firstQueuedAt) {
			s.firstQueuedAt = snap.firstQueuedAt
		}
	}
	cb := s.OnTx
	s.txCond.Broadcast()
	s.mu.Unlock()
	if cb != nil {
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
	if s.rxClosed {
		s.mu.Unlock()
		return
	}
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
		s.Stop()
	}
}

// deliverRx performs in-order reassembly and delivers payloads to RxChan.
// Called exclusively by rxLoop. Returns true when a FIN frame is processed
// and the session's rx side is done.
func (s *Session) deliverRx(f *frame.Frame) bool {
	s.mu.Lock()
	if s.rxClosed {
		s.mu.Unlock()
		return true
	}
	if f.Seq < s.rxSeq {
		s.mu.Unlock()
		return false
	}
	if f.Seq > s.rxSeq {
		s.rxQueue[f.Seq] = f
		s.mu.Unlock()
		return false
	}

	var toSend [][]byte
	var closeAfter bool
	for {
		if len(f.Payload) > 0 {
			toSend = append(toSend, f.Payload)
		}
		s.rxSeq++
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
	if closeAfter {
		close(s.RxChan)
		s.Stop()
	}
	return closeAfter
}
