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

func (s *Server) handleStream(w http.ResponseWriter, r *http.Request) {
	s.stats.requests.Add(1)
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		InsecureSkipVerify: true,
		CompressionMode:    websocket.CompressionDisabled,
	})
	if err != nil {
		log.Printf("[exit] stream accept: %v", err)
		return
	}
	defer conn.CloseNow()
	conn.SetReadLimit(int64(s.maxRequestBodyBytes))

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	ownerCh := make(chan [frame.ClientIDLen]byte, 1)
	errCh := make(chan error, 2)
	go func() { errCh <- s.readStream(ctx, conn, ownerCh) }()

	var owner [frame.ClientIDLen]byte
	select {
	case <-ctx.Done():
		return
	case err := <-errCh:
		if err != nil {
			log.Printf("[exit] stream read before hello: %v", err)
		}
		return
	case owner = <-ownerCh:
	}
	log.Printf("[exit] stream connected owner=%x", owner[:4])
	streamGen := s.registerStream(owner)
	defer func() {
		cancel()
		go func() {
			timer := time.NewTimer(streamDisconnectGrace)
			defer timer.Stop()
			<-timer.C
			if s.isCurrentStream(owner, streamGen) {
				s.abortOwnerSessions(owner, "direct stream disconnected")
			}
		}()
	}()
	go func() { errCh <- s.writeStream(ctx, conn, owner) }()

	select {
	case <-ctx.Done():
	case err := <-errCh:
		if err != nil && ctx.Err() == nil {
			log.Printf("[exit] stream owner=%x closed: %v", owner[:4], err)
		}
	}
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

func (s *Server) writeStream(ctx context.Context, conn *websocket.Conn, owner [frame.ClientIDLen]byte) error {
	wakeCh := s.activityFor(owner)
	for {
		txFrames, _ := s.drainAll(owner, s.maxResponseBytesPreEncode)
		if len(txFrames) > 0 {
			respBody, err := s.encodeResponseBatch(owner, txFrames, true)
			if err != nil {
				s.abortDownstreamSessions(owner, frameSessionIDs(txFrames), "stream response encode failed after draining frames")
				return fmt.Errorf("encode stream batch: %w", err)
			}
			if err := conn.Write(ctx, websocket.MessageBinary, respBody); err != nil {
				s.abortDownstreamSessions(owner, frameSessionIDs(txFrames), "stream response write failed after draining frames")
				return fmt.Errorf("write stream batch: %w", err)
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
