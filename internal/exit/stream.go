package exit

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/coder/websocket"
	"github.com/kianmhz/GooseRelayVPN/internal/frame"
)

const streamPreAuthReadLimit = 64 * 1024

var streamHelloTimeout = 10 * time.Second

type exitStreamWriter interface {
	Write(context.Context, websocket.MessageType, []byte) error
}

func (s *Server) handleStream(w http.ResponseWriter, r *http.Request) {
	s.stats.requests.Add(1)
	releaseHandshake, ok := acquireSlot(s.unauthStreamHandshakes)
	if !ok {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	defer func() {
		if releaseHandshake != nil {
			releaseHandshake()
		}
	}()
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		log.Printf("[exit] stream accept: %v", err)
		return
	}
	defer conn.CloseNow()
	conn.SetReadLimit(streamPreAuthReadLimit)

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	if s.streamStopCh != nil {
		go func() {
			select {
			case <-s.streamStopCh:
				cancel()
			case <-ctx.Done():
			}
		}()
	}

	ownerCh := make(chan [frame.ClientIDLen]byte, 1)
	errCh := make(chan error, 2)
	go func() { errCh <- s.readStream(ctx, conn, ownerCh) }()

	var owner [frame.ClientIDLen]byte
	var readErrBeforeRegister error
	helloTimer := time.NewTimer(streamHelloTimeout)
	defer helloTimer.Stop()
	select {
	case <-ctx.Done():
		return
	case <-helloTimer.C:
		log.Printf("[exit] stream closed: encrypted hello not received within %s", streamHelloTimeout)
		return
	case err := <-errCh:
		select {
		case owner = <-ownerCh:
			readErrBeforeRegister = err
		default:
			if err != nil {
				log.Printf("[exit] stream read before hello: %v", err)
			}
			return
		}
	case owner = <-ownerCh:
	}
	releaseHandshake()
	releaseHandshake = nil
	conn.SetReadLimit(int64(s.maxRequestBodyBytes))
	log.Printf("[exit] stream connected owner=%x", owner[:4])
	streamGen := s.registerStream(owner)
	defer func() {
		closedAt := time.Now()
		cancel()
		s.unregisterStream(owner, streamGen)
		go func() {
			timer := time.NewTimer(streamDisconnectGrace)
			defer timer.Stop()
			<-timer.C
			s.cleanupDisconnectedStream(owner, streamGen, closedAt)
		}()
	}()
	if readErrBeforeRegister != nil {
		log.Printf("[exit] stream owner=%x closed after hello: %v", owner[:4], readErrBeforeRegister)
		return
	}
	go func() { errCh <- s.writeStream(ctx, conn, owner, streamGen) }()

	select {
	case <-ctx.Done():
	case err := <-errCh:
		if err != nil && ctx.Err() == nil {
			log.Printf("[exit] stream owner=%x closed: %v", owner[:4], err)
		}
	}
}

func (s *Server) streamBlockedByReplay(owner [frame.ClientIDLen]byte) bool {
	if s.replay == nil {
		return false
	}
	s.expireReplayForOwner(owner, time.Now())
	return len(s.replay.pendingOwnerSessions(owner)) > 0
}

func (s *Server) readStream(ctx context.Context, conn *websocket.Conn, ownerCh chan<- [frame.ClientIDLen]byte) error {
	var (
		owner     [frame.ClientIDLen]byte
		haveOwner bool
	)
	for {
		typ, body, err := conn.Read(ctx)
		if err != nil {
			return err
		}
		if typ != websocket.MessageBinary {
			return fmt.Errorf("unexpected stream message type %v", typ)
		}
		clientID, rxFrames, err := s.decodeRequestBatch(body, true)
		if err != nil {
			s.stats.decodeFailures.Add(1)
			return fmt.Errorf("decode stream batch: %w", err)
		}
		if !haveOwner {
			owner = clientID
			haveOwner = true
			ownerCh <- owner
			close(ownerCh)
		} else if clientID != owner {
			return fmt.Errorf("stream client id changed from %x to %x", owner[:4], clientID[:4])
		}
		if len(rxFrames) > 0 {
			var bytesIn uint64
			for _, f := range rxFrames {
				bytesIn += uint64(len(f.Payload))
			}
			s.stats.framesIn.Add(uint64(len(rxFrames)))
			s.stats.bytesIn.Add(bytesIn)
		}
		s.routeIncomingBatchContext(ctx, rxFrames, owner)
	}
}

func (s *Server) writeStream(ctx context.Context, conn exitStreamWriter, owner [frame.ClientIDLen]byte, gen uint64) error {
	wakeCh := s.activityFor(owner)
	for {
		if !s.isCurrentStream(owner, gen) {
			s.kick(owner)
			return nil
		}
		// Promote pending POST replay onto the stream before fresh frames. This
		// preserves per-session sequence order when a client recovers from POST
		// fallback to a direct WebSocket.
		txFrames, replayed := s.drainReplayForStream(owner, s.maxResponseBytesPreEncode)
		var rollback streamDrainRollback
		if len(txFrames) == 0 {
			txFrames, _, rollback = s.drainAllForStreamTxn(owner, s.maxResponseBytesPreEncode)
		}
		if len(txFrames) > 0 {
			if !replayed && !s.isCurrentStream(owner, gen) {
				s.rollbackFreshStreamBatch(owner, txFrames, rollback)
				return nil
			}
			respBody, err := s.encodeResponseBatch(owner, txFrames, true)
			if err != nil {
				if replayed {
					return fmt.Errorf("encode stream replay batch: %w", err)
				}
				s.rollbackFreshStreamBatch(owner, txFrames, rollback)
				return fmt.Errorf("encode stream batch: %w", err)
			}
			if !replayed && !s.isCurrentStream(owner, gen) {
				s.rollbackFreshStreamBatch(owner, txFrames, rollback)
				return nil
			}
			if err := conn.Write(ctx, websocket.MessageBinary, respBody); err != nil {
				if replayed {
					return fmt.Errorf("write stream replay batch: %w", err)
				}
				s.rollbackFreshStreamBatch(owner, txFrames, rollback)
				return fmt.Errorf("write stream batch: %w", err)
			}
			if !s.isCurrentStream(owner, gen) {
				if !replayed {
					s.rollbackFreshStreamBatch(owner, txFrames, rollback)
				} else {
					s.kick(owner)
				}
				return nil
			}
			if replayed {
				// Direct streams do not send downstream ACK frames. A successful
				// WebSocket write is the stream-mode delivery boundary, matching
				// how fresh stream frames are handled.
				s.markStreamReplayDelivered(owner, txFrames)
			} else {
				s.commitStreamDrain(rollback)
			}
			var bytesOut uint64
			for _, f := range txFrames {
				bytesOut += uint64(len(f.Payload))
			}
			s.stats.framesOut.Add(uint64(len(txFrames)))
			s.stats.bytesOut.Add(bytesOut)
			continue
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-wakeCh:
		}
	}
}

func (s *Server) rollbackFreshStreamBatch(owner [frame.ClientIDLen]byte, frames []*frame.Frame, rollback streamDrainRollback) {
	ctrl, rsts := cloneRSTControlFrames(frames)
	s.rollbackStreamDrainWithControl(rollback, ctrl, rsts)
}
