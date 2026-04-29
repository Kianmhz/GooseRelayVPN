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
	"sync/atomic"
	"time"

	"github.com/kianmhz/GooseRelayVPN/internal/frame"
)

// TxBufHighWater is the soft ceiling on the per-session tx buffer; EnqueueTx
// blocks once exceeded so a fast SOCKS5 writer can't cause unbounded growth.
// Stop() / RequestClose() set closeReq + broadcast txCond so a blocked
// EnqueueTx caller never deadlocks if the carrier dies.
const TxBufHighWater = 8 * 1024 * 1024

// rxInboxByteCap bounds the per-session inbox of *delivered-but-not-yet-decoded
// frames* (bytes pending in rxLoop). When exceeded ProcessRx returns false so
// the caller can RST the session instead of blocking the poll worker.
const rxInboxByteCap = 8 * 1024 * 1024

// rxQueueFrameCap bounds the per-session out-of-order reassembly queue. A
// peer that sends ever-future Seq values without filling the gap would
// otherwise grow this map unboundedly. When exceeded the session is
// force-closed.
const rxQueueFrameCap = 256

// sessionFinalTimeout is the maximum time to wait for the peer's FIN after
// we have sent ours. If the peer's FIN frame is lost (e.g. dropped poll
// response), the session would stay in the map forever without this timeout,
// causing the session table to grow unboundedly and the poll loop to slow
// down over time as it iterates more and more dead sessions.
const sessionFinalTimeout = 30 * time.Second

// Session is one logical TCP connection across the relay.
type Session struct {
	ID     [frame.SessionIDLen]byte
	Target string // "host:port", carried on the SYN frame

	mu      sync.Mutex
	txCond  *sync.Cond
	rxCond  *sync.Cond
	txBuf   []byte
	txSeq   uint64
	rxSeq   uint64
	rxQueue map[uint64]*frame.Frame

	synNeeded bool // first outgoing frame must carry SYN+Target
	closeReq  bool // VirtualConn.Close() called; FIN must be sent on next drain
	finSent   bool
	finSentAt time.Time // when finSent was set; used for orphan reaping
	rxClosed  bool      // RxChan has been closed (peer FIN received)

	// Per-session inbox of frames waiting for in-order reassembly + delivery.
	// rxLoop is the sole consumer; ProcessRx is the producer. Memory-bounded
	// by rxInboxBytes, never blocks ProcessRx — overflow returns false so the
	// caller can RST the session rather than wedge the poll worker.
	rxInbox        []*frame.Frame
	rxInboxHead    int
	rxInboxBytes   int
	rxInboxStopped bool
	rxOverflowed   atomic.Bool

	RxChan chan []byte

	// onTx is invoked when EnqueueTx adds data and when closeReq transitions
	// true. The carrier sets it to wake its long-poll loop.
	//
	// Stored as atomic.Pointer to remove the historical (subtle, unsynchronized)
	// race between SetOnTx and concurrent EnqueueTx calls.
	onTx atomic.Pointer[func()]

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
		rxDone:    make(chan struct{}),
	}
	s.txCond = sync.NewCond(&s.mu)
	s.rxCond = sync.NewCond(&s.mu)
	go s.rxLoop()
	return s
}

// SetOnTx publishes the tx-wake callback. Safe to call from any goroutine
// before or after the session is registered with the carrier.
func (s *Session) SetOnTx(fn func()) {
	if fn == nil {
		s.onTx.Store(nil)
		return
	}
	s.onTx.Store(&fn)
}

// OnTxFunc returns the registered callback, or nil if none.
func (s *Session) OnTxFunc() func() {
	p := s.onTx.Load()
	if p == nil {
		return nil
	}
	return *p
}

// Stop signals the rxLoop goroutine to exit and wakes any goroutine blocked
// in EnqueueTx so it cannot deadlock if the carrier dies. Safe to call
// multiple times.
func (s *Session) Stop() {
	s.stopOnce.Do(func() { close(s.rxDone) })
	s.mu.Lock()
	s.closeReq = true
	s.rxInboxStopped = true
	// Drop any queued frames — rxLoop is exiting.
	for i := range s.rxInbox {
		s.rxInbox[i] = nil
	}
	s.rxInbox = nil
	s.rxInboxHead = 0
	s.rxInboxBytes = 0
	s.txCond.Broadcast()
	s.rxCond.Broadcast()
	s.mu.Unlock()
}

// RxOverflowed reports whether ProcessRx ever returned false because the
// per-session rx inbox or out-of-order queue exceeded its memory bound. The
// carrier uses this to send a single RST and remove the session.
func (s *Session) RxOverflowed() bool {
	return s.rxOverflowed.Load()
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
		s.mu.Lock()
		for len(s.rxInbox)-s.rxInboxHead == 0 && !s.rxInboxStopped && !s.rxClosed {
			s.rxCond.Wait()
		}
		if s.rxInboxStopped || s.rxClosed {
			s.mu.Unlock()
			return
		}
		f := s.rxInbox[s.rxInboxHead]
		s.rxInbox[s.rxInboxHead] = nil
		s.rxInboxHead++
		s.rxInboxBytes -= len(f.Payload)
		// Compact the slice once the head has eaten >50% of the backing array
		// so we don't hold an arbitrarily long allocation alive.
		if s.rxInboxHead > 0 && s.rxInboxHead*2 > len(s.rxInbox) {
			rem := s.rxInbox[s.rxInboxHead:]
			ns := make([]*frame.Frame, len(rem))
			copy(ns, rem)
			s.rxInbox = ns
			s.rxInboxHead = 0
		}
		s.mu.Unlock()
		if s.deliverRx(f) {
			return
		}
	}
}

// EnqueueTx appends bytes to the session's tx buffer. Blocks while the buffer
// exceeds TxBufHighWater. Safe to call concurrently with DrainTx.
//
// Stop() / RequestClose() guarantee a blocked writer is woken and returns
// without enqueueing further bytes — the previous design could deadlock if
// the carrier's poll loop died with TxBufHighWater bytes queued.
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
	s.mu.Unlock()
	if cb := s.OnTxFunc(); cb != nil {
		cb()
	}
}

// RequestClose marks the session for shutdown. The next DrainTx will emit a
// FIN frame, and EnqueueTx becomes a no-op.
func (s *Session) RequestClose() {
	s.mu.Lock()
	s.closeReq = true
	s.txCond.Broadcast()
	s.mu.Unlock()
	if cb := s.OnTxFunc(); cb != nil {
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
		s.rxCond.Broadcast()
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

// DrainTx removes pending tx bytes and returns them as a sequence of frames,
// each capped at maxPayload bytes. Emits a SYN frame first if needed, and a
// trailing FIN frame if RequestClose was called and the FIN hasn't been sent yet.
func (s *Session) DrainTx(maxPayload int) []*frame.Frame {
	return s.drainTx(maxPayload, 0)
}

// DrainTxLimited is like DrainTx but emits at most maxFrames frames in one
// call (0 means unlimited). Remaining bytes stay queued for later polls.
func (s *Session) DrainTxLimited(maxPayload, maxFrames int) []*frame.Frame {
	return s.drainTx(maxPayload, maxFrames)
}

func (s *Session) drainTx(maxPayload, maxFrames int) []*frame.Frame {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.synNeeded && len(s.txBuf) == 0 && !(s.closeReq && !s.finSent) {
		return nil
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

	s.txCond.Broadcast() // wake any backpressured writers
	return frames
}

// ProcessRx queues f for delivery. Returns true if the frame was accepted (or
// silently dropped because the session is already closed) and false only when
// the per-session rx inbox exceeded its memory bound — the caller must then
// RST the session and remove it from its routing table.
//
// Never blocks: this is the change that makes one slow SOCKS reader unable to
// stall poll workers handling unrelated sessions. The slice-backed inbox is
// memory-bounded by total payload bytes (rxInboxByteCap), not by frame count,
// so a stream of small frames cannot evade the cap.
func (s *Session) ProcessRx(f *frame.Frame) bool {
	payloadLen := len(f.Payload)
	s.mu.Lock()
	if s.rxClosed || s.rxInboxStopped {
		s.mu.Unlock()
		return true // dropped, but not an overflow signal
	}
	if s.rxInboxBytes+payloadLen > rxInboxByteCap {
		s.rxInboxStopped = true
		s.rxOverflowed.Store(true)
		s.rxCond.Broadcast()
		s.mu.Unlock()
		return false
	}
	s.rxInbox = append(s.rxInbox, f)
	s.rxInboxBytes += payloadLen
	s.rxCond.Signal()
	s.mu.Unlock()
	return true
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
		if len(s.rxQueue) >= rxQueueFrameCap {
			// Out-of-order queue would grow unboundedly — drop the session.
			s.rxOverflowed.Store(true)
			s.rxClosed = true
			close(s.RxChan)
			s.mu.Unlock()
			return true
		}
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
