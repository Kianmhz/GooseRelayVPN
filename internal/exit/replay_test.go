package exit

import (
	"testing"
	"time"

	"github.com/kianmhz/GooseRelayVPN/internal/frame"
)

func TestDownstreamReplayManagerStoresPrunesAndReplays(t *testing.T) {
	m := newDownstreamReplayManager(1024, 4096, 4096, time.Minute, time.Second)
	owner := [frame.ClientIDLen]byte{0x01}
	sid := [frame.SessionIDLen]byte{0x02}
	now := time.Unix(100, 0)

	dropped := m.track(owner, []*frame.Frame{
		{SessionID: sid, Seq: 0, Payload: []byte("first")},
		{SessionID: sid, Seq: 1, Payload: []byte("second")},
	}, now)
	if len(dropped) != 0 {
		t.Fatalf("track dropped %d session(s), want none", len(dropped))
	}
	if got := m.bufferBytes(); got != len("first")+len("second") {
		t.Fatalf("buffer bytes = %d", got)
	}
	if got := m.ready(owner, 4096, now.Add(500*time.Millisecond)); len(got) != 0 {
		t.Fatalf("ready before retry delay returned %d frame(s)", len(got))
	}

	ready := m.ready(owner, 4096, now.Add(time.Second))
	if len(ready) != 2 {
		t.Fatalf("ready frames = %d, want 2", len(ready))
	}
	if string(ready[0].Payload) != "first" || string(ready[1].Payload) != "second" {
		t.Fatalf("ready payloads = %q/%q", ready[0].Payload, ready[1].Payload)
	}

	pruned := m.ack(owner, sid, 1)
	if pruned != 1 {
		t.Fatalf("pruned = %d, want 1", pruned)
	}
	ready = m.ready(owner, 4096, now.Add(2*time.Second))
	if len(ready) != 1 || ready[0].Seq != 1 || string(ready[0].Payload) != "second" {
		t.Fatalf("ready after ack = %#v, want seq 1 only", ready)
	}
}

func TestDownstreamReplayManagerPartialReplayAckAllowsImmediateRemainder(t *testing.T) {
	m := newDownstreamReplayManager(1024, 4096, 4096, time.Minute, time.Second)
	owner := [frame.ClientIDLen]byte{0x21}
	sid := [frame.SessionIDLen]byte{0x22}
	now := time.Unix(100, 0)

	m.track(owner, []*frame.Frame{
		{SessionID: sid, Seq: 0, Payload: []byte("1111")},
		{SessionID: sid, Seq: 1, Payload: []byte("2222")},
		{SessionID: sid, Seq: 2, Payload: []byte("3333")},
	}, now)

	ready := m.ready(owner, 4, now.Add(time.Second))
	if len(ready) != 1 || ready[0].Seq != 0 {
		t.Fatalf("first partial ready = %#v, want only seq 0", ready)
	}
	if pruned := m.ack(owner, sid, 1); pruned != 1 {
		t.Fatalf("pruned = %d, want 1", pruned)
	}

	ready = m.ready(owner, 4096, now.Add(time.Second+time.Millisecond))
	if len(ready) != 2 || ready[0].Seq != 1 || ready[1].Seq != 2 {
		t.Fatalf("ready after partial ACK = %#v, want seq 1 and 2 without waiting another retry delay", ready)
	}
}

func TestDownstreamReplayManagerOrdersAndPrunesOutOfOrderFrames(t *testing.T) {
	m := newDownstreamReplayManager(1024, 4096, 4096, time.Minute, time.Second)
	owner := [frame.ClientIDLen]byte{0x31}
	sid := [frame.SessionIDLen]byte{0x32}
	now := time.Unix(100, 0)

	m.track(owner, []*frame.Frame{
		{SessionID: sid, Seq: 1, Payload: []byte("one")},
	}, now)
	m.track(owner, []*frame.Frame{
		{SessionID: sid, Seq: 0, Payload: []byte("zero")},
	}, now.Add(time.Millisecond))

	ready := m.ready(owner, 4096, now.Add(time.Second+time.Millisecond))
	if len(ready) != 2 || ready[0].Seq != 0 || ready[1].Seq != 1 {
		t.Fatalf("ready = %#v, want seq 0 then seq 1", ready)
	}
	if pruned := m.ack(owner, sid, 1); pruned != 1 {
		t.Fatalf("pruned = %d, want 1", pruned)
	}
	ready = m.ready(owner, 4096, now.Add(2*time.Second))
	if len(ready) != 1 || ready[0].Seq != 1 {
		t.Fatalf("ready after ack = %#v, want only seq 1", ready)
	}
}

func TestDownstreamReplayManagerSkipsTerminalRST(t *testing.T) {
	m := newDownstreamReplayManager(1024, 4096, 4096, time.Minute, time.Second)
	owner := [frame.ClientIDLen]byte{0x33}
	sid := [frame.SessionIDLen]byte{0x34}
	now := time.Unix(100, 0)

	dropped := m.track(owner, []*frame.Frame{{
		SessionID: sid,
		Flags:     frame.FlagRST,
		Seq:       7,
	}}, now)
	if len(dropped) != 0 {
		t.Fatalf("track dropped %d session(s), want none", len(dropped))
	}
	if ready := m.ready(owner, 4096, now.Add(time.Second)); len(ready) != 0 {
		t.Fatalf("ready = %#v, want terminal RST skipped", ready)
	}
}

func TestDownstreamReplayManagerSkipsVersionControlRSTPayload(t *testing.T) {
	m := newDownstreamReplayManager(1024, 4096, 4096, time.Minute, time.Second)
	owner := [frame.ClientIDLen]byte{0x35}
	sid := [frame.SessionIDLen]byte{0x36}
	now := time.Unix(100, 0)

	m.track(owner, []*frame.Frame{{
		SessionID: sid,
		Flags:     frame.FlagRST,
		Payload:   []byte("version-control"),
	}}, now)
	if ready := m.ready(owner, 4096, now.Add(time.Second)); len(ready) != 0 {
		t.Fatalf("ready = %#v, want non-terminal control RST skipped", ready)
	}
}

func TestDownstreamReplayManagerCapsReadyFrameCount(t *testing.T) {
	m := newDownstreamReplayManager(1024, 4096, 4096, time.Minute, time.Second)
	m.maxFrames = 2
	owner := [frame.ClientIDLen]byte{0x37}
	sid := [frame.SessionIDLen]byte{0x38}
	now := time.Unix(100, 0)

	m.track(owner, []*frame.Frame{
		{SessionID: sid, Seq: 0, Payload: []byte("a")},
		{SessionID: sid, Seq: 1, Payload: []byte("b")},
		{SessionID: sid, Seq: 2, Payload: []byte("c")},
	}, now)

	ready := m.ready(owner, 4096, now.Add(time.Second))
	if len(ready) != 2 || ready[0].Seq != 0 || ready[1].Seq != 1 {
		t.Fatalf("ready = %#v, want first two frames only", ready)
	}
}

func TestDownstreamReplayManagerCapsStoredFramesPerSession(t *testing.T) {
	m := newDownstreamReplayManager(1024, 4096, 4096, time.Minute, time.Second)
	m.perSessionFrameCap = 2
	owner := [frame.ClientIDLen]byte{0x39}
	sid := [frame.SessionIDLen]byte{0x3a}
	now := time.Unix(100, 0)

	dropped := m.track(owner, []*frame.Frame{
		{SessionID: sid, Seq: 0, Flags: frame.FlagFIN},
		{SessionID: sid, Seq: 1, Flags: frame.FlagFIN},
		{SessionID: sid, Seq: 2, Flags: frame.FlagFIN},
	}, now)
	if len(dropped) != 1 || dropped[0] != sid {
		t.Fatalf("dropped = %x, want session %x", dropped, sid)
	}
	if ready := m.ready(owner, 4096, now.Add(time.Second)); len(ready) != 0 {
		t.Fatalf("ready = %#v, want capped session removed", ready)
	}
}

func TestDownstreamReplayManagerCapsStoredFramesPerClient(t *testing.T) {
	m := newDownstreamReplayManager(1024, 4096, 4096, time.Minute, time.Second)
	m.perSessionFrameCap = 16
	m.perClientFrameCap = 2
	owner := [frame.ClientIDLen]byte{0x3b}
	sidA := [frame.SessionIDLen]byte{0x3c}
	sidB := [frame.SessionIDLen]byte{0x3d}
	sidC := [frame.SessionIDLen]byte{0x3e}
	now := time.Unix(100, 0)

	dropped := m.track(owner, []*frame.Frame{
		{SessionID: sidA, Seq: 0, Flags: frame.FlagFIN},
		{SessionID: sidB, Seq: 0, Flags: frame.FlagFIN},
		{SessionID: sidC, Seq: 0, Flags: frame.FlagFIN},
	}, now)
	if len(dropped) != 1 || dropped[0] != sidC {
		t.Fatalf("dropped = %x, want only session %x", dropped, sidC)
	}
	ready := m.ready(owner, 4096, now.Add(time.Second))
	if len(ready) != 2 {
		t.Fatalf("ready = %#v, want two preserved frames", ready)
	}
	got := map[[frame.SessionIDLen]byte]bool{ready[0].SessionID: true, ready[1].SessionID: true}
	if !got[sidA] || !got[sidB] || got[sidC] {
		t.Fatalf("ready sessions = %#v, want A and B only", got)
	}
}

func TestDownstreamReplayManagerCapsPerSession(t *testing.T) {
	m := newDownstreamReplayManager(4, 4096, 4096, time.Minute, time.Second)
	owner := [frame.ClientIDLen]byte{0x03}
	sid := [frame.SessionIDLen]byte{0x04}

	dropped := m.track(owner, []*frame.Frame{
		{SessionID: sid, Seq: 0, Payload: []byte("too-large")},
	}, time.Unix(100, 0))
	if len(dropped) != 1 || dropped[0] != sid {
		t.Fatalf("dropped = %x, want session %x", dropped, sid)
	}
	if got := m.bufferBytes(); got != 0 {
		t.Fatalf("buffer bytes after cap drop = %d, want 0", got)
	}
}

func TestDownstreamReplayManagerCapDropSkipsLaterSameSessionInBatch(t *testing.T) {
	m := newDownstreamReplayManager(4, 4096, 4096, time.Minute, time.Second)
	owner := [frame.ClientIDLen]byte{0x0d}
	sid := [frame.SessionIDLen]byte{0x0e}
	now := time.Unix(100, 0)

	dropped := m.track(owner, []*frame.Frame{
		{SessionID: sid, Seq: 0, Payload: []byte("too-large")},
		{SessionID: sid, Seq: 1, Payload: []byte("ok")},
	}, now)
	if len(dropped) != 1 || dropped[0] != sid {
		t.Fatalf("dropped = %x, want session %x", dropped, sid)
	}
	if got := m.bufferBytes(); got != 0 {
		t.Fatalf("buffer bytes after same-session cap drop = %d, want 0", got)
	}
	if ready := m.ready(owner, 4096, now.Add(time.Second)); len(ready) != 0 {
		t.Fatalf("ready = %#v, want capped session to stay dropped", ready)
	}
}

func TestDownstreamReplayManagerContinuesTrackingAfterCapDrop(t *testing.T) {
	m := newDownstreamReplayManager(4, 4096, 4096, time.Minute, time.Second)
	owner := [frame.ClientIDLen]byte{0x13}
	oversized := [frame.SessionIDLen]byte{0x14}
	valid := [frame.SessionIDLen]byte{0x15}
	now := time.Unix(100, 0)

	dropped := m.track(owner, []*frame.Frame{
		{SessionID: oversized, Seq: 0, Payload: []byte("too-large")},
		{SessionID: valid, Seq: 0, Payload: []byte("ok")},
	}, now)
	if len(dropped) != 1 || dropped[0] != oversized {
		t.Fatalf("dropped = %x, want only oversized session %x", dropped, oversized)
	}
	if got := m.bufferBytes(); got != len("ok") {
		t.Fatalf("buffer bytes = %d, want %d", got, len("ok"))
	}
	ready := m.ready(owner, 4096, now.Add(time.Second))
	if len(ready) != 1 || ready[0].SessionID != valid || string(ready[0].Payload) != "ok" {
		t.Fatalf("ready = %#v, want valid session replay frame", ready)
	}
}

func TestDownstreamReplayManagerCapsGlobalBytes(t *testing.T) {
	m := newDownstreamReplayManager(1024, 4096, 4, time.Minute, time.Second)
	ownerA := [frame.ClientIDLen]byte{0x16}
	ownerB := [frame.ClientIDLen]byte{0x17}
	sidA := [frame.SessionIDLen]byte{0x18}
	sidB := [frame.SessionIDLen]byte{0x19}
	now := time.Unix(100, 0)

	if dropped := m.track(ownerA, []*frame.Frame{{SessionID: sidA, Seq: 0, Payload: []byte("1234")}}, now); len(dropped) != 0 {
		t.Fatalf("first track dropped = %x, want none", dropped)
	}
	dropped := m.track(ownerB, []*frame.Frame{{SessionID: sidB, Seq: 0, Payload: []byte("x")}}, now)
	if len(dropped) != 1 || dropped[0] != sidB {
		t.Fatalf("global cap dropped = %x, want session %x", dropped, sidB)
	}
	if got := m.bufferBytes(); got != 4 {
		t.Fatalf("buffer bytes = %d, want original 4 bytes preserved", got)
	}
	if ready := m.ready(ownerA, 1024, now.Add(time.Second)); len(ready) != 1 || ready[0].SessionID != sidA {
		t.Fatalf("owner A ready = %#v, want original frame preserved", ready)
	}
	if ready := m.ready(ownerB, 1024, now.Add(time.Second)); len(ready) != 0 {
		t.Fatalf("owner B ready = %#v, want globally capped frame dropped", ready)
	}
}

func TestDownstreamReplayManagerExpiresOldSessions(t *testing.T) {
	m := newDownstreamReplayManager(1024, 4096, 4096, time.Second, time.Millisecond)
	owner := [frame.ClientIDLen]byte{0x05}
	sid := [frame.SessionIDLen]byte{0x06}
	now := time.Unix(100, 0)

	m.track(owner, []*frame.Frame{
		{SessionID: sid, Seq: 0, Payload: []byte("old")},
	}, now)

	expired := m.expireOwner(owner, now.Add(2*time.Second))
	if len(expired) != 1 || expired[0] != sid {
		t.Fatalf("expired = %x, want session %x", expired, sid)
	}
	if got := m.bufferBytes(); got != 0 {
		t.Fatalf("buffer bytes after expiry = %d, want 0", got)
	}
}

func TestDownstreamReplayManagerACKProgressRefreshesExpiryAge(t *testing.T) {
	m := newDownstreamReplayManager(1024, 4096, 4096, time.Second, time.Millisecond)
	owner := [frame.ClientIDLen]byte{0x45}
	sid := [frame.SessionIDLen]byte{0x46}
	old := time.Unix(100, 0)
	ackTime := old.Add(2 * time.Second)

	m.track(owner, []*frame.Frame{
		{SessionID: sid, Seq: 0, Payload: []byte("acked")},
		{SessionID: sid, Seq: 1, Payload: []byte("remaining")},
	}, old)
	if pruned := m.ackAt(owner, sid, 1, ackTime); pruned != 1 {
		t.Fatalf("pruned = %d, want 1", pruned)
	}
	if expired := m.expireOwner(owner, ackTime.Add(500*time.Millisecond)); len(expired) != 0 {
		t.Fatalf("expired after ACK progress = %x, want none", expired)
	}
	if expired := m.expireOwner(owner, ackTime.Add(2*time.Second)); len(expired) != 1 || expired[0] != sid {
		t.Fatalf("expired after refreshed max age = %x, want session %x", expired, sid)
	}
}

func TestDownstreamReplayManagerNextReadyDelay(t *testing.T) {
	m := newDownstreamReplayManager(1024, 4096, 4096, time.Minute, 3*time.Second)
	owner := [frame.ClientIDLen]byte{0x07}
	sid := [frame.SessionIDLen]byte{0x08}
	now := time.Unix(100, 0)

	if _, ok := m.nextReadyDelay(owner, now); ok {
		t.Fatal("nextReadyDelay ok with empty manager, want false")
	}
	m.track(owner, []*frame.Frame{
		{SessionID: sid, Seq: 0, Payload: []byte("pending")},
	}, now)

	delay, ok := m.nextReadyDelay(owner, now.Add(time.Second))
	if !ok || delay != 2*time.Second {
		t.Fatalf("delay = %s ok=%v, want 2s true", delay, ok)
	}
	delay, ok = m.nextReadyDelay(owner, now.Add(3*time.Second))
	if !ok || delay != 0 {
		t.Fatalf("ready delay = %s ok=%v, want 0 true", delay, ok)
	}
}

func TestDownstreamReplayManagerPendingOwnerSessions(t *testing.T) {
	m := newDownstreamReplayManager(1024, 4096, 4096, time.Minute, time.Second)
	owner := [frame.ClientIDLen]byte{0x09}
	otherOwner := [frame.ClientIDLen]byte{0x0a}
	sid := [frame.SessionIDLen]byte{0x0b}
	otherSID := [frame.SessionIDLen]byte{0x0c}

	m.track(owner, []*frame.Frame{
		{SessionID: sid, Seq: 0, Payload: []byte("pending")},
	}, time.Unix(100, 0))
	m.track(otherOwner, []*frame.Frame{
		{SessionID: otherSID, Seq: 0, Payload: []byte("other")},
	}, time.Unix(100, 0))

	ids := m.pendingOwnerSessions(owner)
	if len(ids) != 1 || ids[0] != sid {
		t.Fatalf("pending owner sessions = %x, want %x", ids, sid)
	}
}
