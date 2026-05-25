package exit

import (
	"sort"
	"sync"
	"time"

	"github.com/kianmhz/GooseRelayVPN/internal/frame"
	"github.com/kianmhz/GooseRelayVPN/internal/protocol"
)

const (
	defaultDownstreamReplayPerSessionBytes = protocol.DownstreamReplayPerSessionBytes
	defaultDownstreamReplayPerClientBytes  = 64 * 1024 * 1024
	defaultDownstreamReplayGlobalBytes     = 256 * 1024 * 1024
	defaultDownstreamReplayMaxAge          = 5 * time.Minute
	defaultDownstreamReplayRetryDelay      = 3 * time.Second
	defaultDownstreamReplayMaxFrames       = maxDrainFramesPerBatchBusy
	defaultDownstreamReplayPerClientFrames = defaultDownstreamReplayMaxFrames * 64
	defaultDownstreamReplayGlobalFrames    = defaultDownstreamReplayPerClientFrames * 4
)

type downstreamReplaySession struct {
	frames   []*frame.Frame
	bytes    int
	created  time.Time
	lastSent time.Time
}

type downstreamReplayManager struct {
	mu sync.Mutex

	perSessionCap int
	perClientCap  int
	globalCap     int
	maxAge        time.Duration
	retryDelay    time.Duration
	maxFrames     int

	perSessionFrameCap int
	perClientFrameCap  int
	globalFrameCap     int

	byOwner     map[[frame.ClientIDLen]byte]map[[frame.SessionIDLen]byte]*downstreamReplaySession
	ownerBytes  map[[frame.ClientIDLen]byte]int
	ownerFrames map[[frame.ClientIDLen]byte]int
	totalBytes  int
	totalFrames int
}

func newDownstreamReplayManager(perSessionCap, perClientCap, globalCap int, maxAge, retryDelay time.Duration) *downstreamReplayManager {
	if perSessionCap <= 0 {
		perSessionCap = defaultDownstreamReplayPerSessionBytes
	}
	if perClientCap <= 0 {
		perClientCap = defaultDownstreamReplayPerClientBytes
	}
	if globalCap <= 0 {
		globalCap = defaultDownstreamReplayGlobalBytes
	}
	if maxAge <= 0 {
		maxAge = defaultDownstreamReplayMaxAge
	}
	if retryDelay <= 0 {
		retryDelay = defaultDownstreamReplayRetryDelay
	}
	return &downstreamReplayManager{
		perSessionCap:      perSessionCap,
		perClientCap:       perClientCap,
		globalCap:          globalCap,
		maxAge:             maxAge,
		retryDelay:         retryDelay,
		maxFrames:          defaultDownstreamReplayMaxFrames,
		perSessionFrameCap: defaultDownstreamReplayMaxFrames,
		perClientFrameCap:  defaultDownstreamReplayPerClientFrames,
		globalFrameCap:     defaultDownstreamReplayGlobalFrames,
		byOwner:            make(map[[frame.ClientIDLen]byte]map[[frame.SessionIDLen]byte]*downstreamReplaySession),
		ownerBytes:         make(map[[frame.ClientIDLen]byte]int),
		ownerFrames:        make(map[[frame.ClientIDLen]byte]int),
	}
}

func (m *downstreamReplayManager) track(owner [frame.ClientIDLen]byte, frames []*frame.Frame, now time.Time) [][frame.SessionIDLen]byte {
	if m == nil || len(frames) == 0 {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var dropped [][frame.SessionIDLen]byte
	droppedSeen := make(map[[frame.SessionIDLen]byte]struct{})
	for _, f := range frames {
		if f == nil || f.HasFlag(frame.FlagACK) {
			continue
		}
		// RST frames are terminal control frames. The client closes the local
		// session immediately on receipt and does not emit a downstream ACK for
		// them, so retaining them in the ACK-gated replay buffer can leave an
		// unackable pending item that blocks direct-stream handoff until expiry.
		if f.HasFlag(frame.FlagRST) {
			continue
		}
		if _, dropped := droppedSeen[f.SessionID]; dropped {
			continue
		}
		ownerSessions := m.byOwner[owner]
		if ownerSessions == nil {
			ownerSessions = make(map[[frame.SessionIDLen]byte]*downstreamReplaySession)
			m.byOwner[owner] = ownerSessions
		}
		payloadBytes := len(f.Payload)
		buf := ownerSessions[f.SessionID]
		bufBytes := 0
		bufFrames := 0
		if buf != nil {
			bufBytes = buf.bytes
			bufFrames = len(buf.frames)
			insertAt := sort.Search(len(buf.frames), func(i int) bool {
				return buf.frames[i].Seq >= f.Seq
			})
			if insertAt < len(buf.frames) && buf.frames[insertAt].Seq == f.Seq {
				// The same sent frame is already replayable; avoid duplicate
				// delivery and duplicate memory accounting.
				continue
			}
		}
		if bufBytes+payloadBytes > m.perSessionCap ||
			m.ownerBytes[owner]+payloadBytes > m.perClientCap ||
			m.totalBytes+payloadBytes > m.globalCap ||
			bufFrames+1 > m.perSessionFrameCap ||
			m.ownerFrames[owner]+1 > m.perClientFrameCap ||
			m.totalFrames+1 > m.globalFrameCap {
			m.dropLocked(owner, f.SessionID)
			if _, ok := droppedSeen[f.SessionID]; !ok {
				dropped = append(dropped, f.SessionID)
				droppedSeen[f.SessionID] = struct{}{}
			}
			continue
		}
		if buf == nil {
			buf = &downstreamReplaySession{created: now}
			ownerSessions[f.SessionID] = buf
		}
		cloned := cloneReplayFrame(f)
		insertAt := sort.Search(len(buf.frames), func(i int) bool {
			return buf.frames[i].Seq >= cloned.Seq
		})
		buf.frames = append(buf.frames, nil)
		copy(buf.frames[insertAt+1:], buf.frames[insertAt:])
		buf.frames[insertAt] = cloned
		buf.bytes += payloadBytes
		buf.lastSent = now
		m.ownerBytes[owner] += payloadBytes
		m.totalBytes += payloadBytes
		m.ownerFrames[owner]++
		m.totalFrames++
	}
	if len(m.byOwner[owner]) == 0 {
		delete(m.byOwner, owner)
		delete(m.ownerBytes, owner)
		delete(m.ownerFrames, owner)
	}
	return dropped
}

func (m *downstreamReplayManager) ack(owner [frame.ClientIDLen]byte, sessionID [frame.SessionIDLen]byte, ackNextSeq uint64) int {
	return m.ackAt(owner, sessionID, ackNextSeq, time.Now())
}

func (m *downstreamReplayManager) ackAt(owner [frame.ClientIDLen]byte, sessionID [frame.SessionIDLen]byte, ackNextSeq uint64, now time.Time) int {
	if m == nil {
		return 0
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	ownerSessions := m.byOwner[owner]
	if ownerSessions == nil {
		return 0
	}
	buf := ownerSessions[sessionID]
	if buf == nil {
		return 0
	}
	pruned := 0
	prunedBytes := 0
	prunedFrames := 0
	kept := buf.frames[:0]
	for _, f := range buf.frames {
		if f.Seq < ackNextSeq {
			prunedBytes += len(f.Payload)
			pruned++
			prunedFrames++
			continue
		}
		kept = append(kept, f)
	}
	if pruned == 0 {
		return 0
	}
	for i := len(kept); i < len(buf.frames); i++ {
		buf.frames[i] = nil
	}
	buf.frames = kept
	buf.bytes -= prunedBytes
	m.ownerBytes[owner] -= prunedBytes
	m.totalBytes -= prunedBytes
	m.ownerFrames[owner] -= prunedFrames
	m.totalFrames -= prunedFrames
	if buf.bytes < 0 {
		buf.bytes = 0
	}
	if m.ownerBytes[owner] < 0 {
		m.ownerBytes[owner] = 0
	}
	if m.totalBytes < 0 {
		m.totalBytes = 0
	}
	if m.ownerFrames[owner] < 0 {
		m.ownerFrames[owner] = 0
	}
	if m.totalFrames < 0 {
		m.totalFrames = 0
	}
	if len(buf.frames) == 0 {
		delete(ownerSessions, sessionID)
		if len(ownerSessions) == 0 {
			delete(m.byOwner, owner)
			delete(m.ownerBytes, owner)
			delete(m.ownerFrames, owner)
		}
	} else {
		// The ACK proves the client made progress. If a previous replay response
		// could only fit part of this buffer, the remaining frames may never have
		// been retried; allow them on the next poll instead of forcing another
		// full retryDelay wait.
		buf.created = now
		buf.lastSent = time.Time{}
	}
	return pruned
}

func (m *downstreamReplayManager) expireOwner(owner [frame.ClientIDLen]byte, now time.Time) [][frame.SessionIDLen]byte {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	ownerSessions := m.byOwner[owner]
	if ownerSessions == nil {
		return nil
	}
	expired := make([][frame.SessionIDLen]byte, 0)
	for sessionID, buf := range ownerSessions {
		if len(buf.frames) == 0 {
			continue
		}
		if now.Sub(buf.created) <= m.maxAge {
			continue
		}
		expired = append(expired, sessionID)
	}
	for _, sessionID := range expired {
		m.dropLocked(owner, sessionID)
	}
	return expired
}

func (m *downstreamReplayManager) ready(owner [frame.ClientIDLen]byte, byteBudget int, now time.Time) []*frame.Frame {
	if m == nil || byteBudget <= 0 {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	ownerSessions := m.byOwner[owner]
	if ownerSessions == nil {
		return nil
	}
	frameBudget := m.maxFrames
	if frameBudget <= 0 {
		frameBudget = defaultDownstreamReplayMaxFrames
	}
	var out []*frame.Frame
	for _, buf := range ownerSessions {
		if len(buf.frames) == 0 || now.Sub(buf.lastSent) < m.retryDelay {
			continue
		}
		emitted := false
		for _, f := range buf.frames {
			if len(out) >= frameBudget {
				break
			}
			payloadBytes := len(f.Payload)
			if payloadBytes > byteBudget && len(out) > 0 {
				break
			}
			out = append(out, cloneReplayFrame(f))
			byteBudget -= payloadBytes
			emitted = true
			if byteBudget <= 0 {
				break
			}
		}
		if emitted {
			buf.lastSent = now
		}
		if byteBudget <= 0 {
			break
		}
		if len(out) >= frameBudget {
			break
		}
	}
	return out
}

func (m *downstreamReplayManager) readyForStream(owner [frame.ClientIDLen]byte, byteBudget int) []*frame.Frame {
	if m == nil || byteBudget <= 0 {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	ownerSessions := m.byOwner[owner]
	if ownerSessions == nil {
		return nil
	}
	frameBudget := m.maxFrames
	if frameBudget <= 0 {
		frameBudget = defaultDownstreamReplayMaxFrames
	}
	var out []*frame.Frame
	for _, buf := range ownerSessions {
		if len(buf.frames) == 0 {
			continue
		}
		for _, f := range buf.frames {
			if len(out) >= frameBudget {
				break
			}
			payloadBytes := len(f.Payload)
			if payloadBytes > byteBudget && len(out) > 0 {
				break
			}
			out = append(out, cloneReplayFrame(f))
			byteBudget -= payloadBytes
			if byteBudget <= 0 {
				break
			}
		}
		if byteBudget <= 0 || len(out) >= frameBudget {
			break
		}
	}
	return out
}

func (m *downstreamReplayManager) forceReady(owner [frame.ClientIDLen]byte) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	ownerSessions := m.byOwner[owner]
	if ownerSessions == nil {
		return
	}
	for _, buf := range ownerSessions {
		if buf != nil && len(buf.frames) > 0 {
			buf.lastSent = time.Time{}
		}
	}
}

func (m *downstreamReplayManager) nextReadyDelay(owner [frame.ClientIDLen]byte, now time.Time) (time.Duration, bool) {
	if m == nil {
		return 0, false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	ownerSessions := m.byOwner[owner]
	if ownerSessions == nil {
		return 0, false
	}
	var (
		best time.Duration
		ok   bool
	)
	for _, buf := range ownerSessions {
		if len(buf.frames) == 0 {
			continue
		}
		delay := m.retryDelay - now.Sub(buf.lastSent)
		if delay <= 0 {
			return 0, true
		}
		if !ok || delay < best {
			best = delay
			ok = true
		}
	}
	return best, ok
}

func (m *downstreamReplayManager) hasPending(owner [frame.ClientIDLen]byte, sessionID [frame.SessionIDLen]byte) bool {
	if m == nil {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if ownerSessions := m.byOwner[owner]; ownerSessions != nil {
		if buf := ownerSessions[sessionID]; buf != nil && len(buf.frames) > 0 {
			return true
		}
	}
	return false
}

func (m *downstreamReplayManager) pendingOwnerSessions(owner [frame.ClientIDLen]byte) [][frame.SessionIDLen]byte {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	ownerSessions := m.byOwner[owner]
	if ownerSessions == nil {
		return nil
	}
	ids := make([][frame.SessionIDLen]byte, 0, len(ownerSessions))
	for sessionID, buf := range ownerSessions {
		if len(buf.frames) > 0 {
			ids = append(ids, sessionID)
		}
	}
	return ids
}

func (m *downstreamReplayManager) remove(owner [frame.ClientIDLen]byte, sessionID [frame.SessionIDLen]byte) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.dropLocked(owner, sessionID)
}

func (m *downstreamReplayManager) bufferBytes() int {
	if m == nil {
		return 0
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.totalBytes
}

func (m *downstreamReplayManager) dropLocked(owner [frame.ClientIDLen]byte, sessionID [frame.SessionIDLen]byte) {
	ownerSessions := m.byOwner[owner]
	if ownerSessions == nil {
		return
	}
	buf := ownerSessions[sessionID]
	if buf == nil {
		return
	}
	m.ownerBytes[owner] -= buf.bytes
	m.totalBytes -= buf.bytes
	m.ownerFrames[owner] -= len(buf.frames)
	m.totalFrames -= len(buf.frames)
	if m.ownerBytes[owner] < 0 {
		m.ownerBytes[owner] = 0
	}
	if m.totalBytes < 0 {
		m.totalBytes = 0
	}
	if m.ownerFrames[owner] < 0 {
		m.ownerFrames[owner] = 0
	}
	if m.totalFrames < 0 {
		m.totalFrames = 0
	}
	delete(ownerSessions, sessionID)
	if len(ownerSessions) == 0 {
		delete(m.byOwner, owner)
		delete(m.ownerBytes, owner)
		delete(m.ownerFrames, owner)
	}
}

func cloneReplayFrame(f *frame.Frame) *frame.Frame {
	if f == nil {
		return nil
	}
	cp := *f
	if len(f.Payload) > 0 {
		cp.Payload = append([]byte(nil), f.Payload...)
	}
	return &cp
}
