package carrier

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/coder/websocket"
	"github.com/kianmhz/GooseRelayVPN/internal/frame"
)

func (c *Client) runStreamLoop(ctx context.Context) {
	if !c.streamEnabled() {
		return
	}
	next := 0
	reconnectTimer := time.NewTimer(time.Hour)
	if !reconnectTimer.Stop() {
		<-reconnectTimer.C
	}
	defer reconnectTimer.Stop()
	for ctx.Err() == nil {
		url := c.directStreamURLs[next%len(c.directStreamURLs)]
		next++
		if err := c.runStreamConnection(ctx, url); err != nil && ctx.Err() == nil {
			c.stats.streamFail.Add(1)
			log.Printf("[carrier] direct stream %s unavailable: %v", url, err)
			if !c.postEnabled() {
				c.abortAllSessions("direct stream unavailable")
			} else {
				c.stats.postFallbacks.Add(1)
			}
		}
		c.streamActive.Store(false)
		c.wake.Broadcast()
		resetTimer(reconnectTimer, c.streamReconnectBackoff)
		select {
		case <-ctx.Done():
			stopTimer(reconnectTimer)
			return
		case <-reconnectTimer.C:
		}
	}
}

func (c *Client) runStreamConnection(ctx context.Context, url string) error {
	dialCtx, cancel := context.WithTimeout(ctx, c.streamConnectTimeout)
	defer cancel()
	conn, _, err := websocket.Dial(dialCtx, url, &websocket.DialOptions{
		CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		return err
	}
	defer conn.CloseNow()
	conn.SetReadLimit(maxRelayResponseBodyBytes)

	streamCtx, streamCancel := context.WithCancel(ctx)
	defer streamCancel()

	errCh := make(chan error, 2)
	c.streamActive.Store(true)
	c.stats.streamOK.Add(1)
	log.Printf("[carrier] direct stream connected via %s", url)

	hello, err := c.encodeStreamBatch(nil)
	if err != nil {
		return fmt.Errorf("encode stream hello: %w", err)
	}
	if err := conn.Write(streamCtx, websocket.MessageBinary, hello); err != nil {
		return fmt.Errorf("write stream hello: %w", err)
	}
	c.wake.Broadcast()

	go func() { errCh <- c.readStream(streamCtx, conn) }()
	go func() { errCh <- c.writeStream(streamCtx, conn) }()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-errCh:
		streamCancel()
		if err != nil {
			c.stats.streamDrops.Add(1)
			return err
		}
		return nil
	}
}

func (c *Client) readStream(ctx context.Context, conn *websocket.Conn) error {
	for {
		typ, body, err := conn.Read(ctx)
		if err != nil {
			return err
		}
		if typ != websocket.MessageBinary {
			return fmt.Errorf("unexpected stream message type %v", typ)
		}
		start := time.Now()
		_, rxFrames, err := frame.DecodeBatchBinary(c.aead, body)
		c.stats.decode.Add(time.Since(start))
		c.stats.respSize.Add(len(body))
		if err != nil {
			return fmt.Errorf("decode stream batch: %w", err)
		}
		for _, f := range rxFrames {
			c.routeRx(f)
		}
		countFrameBytes(&c.stats.framesIn, &c.stats.bytesIn, rxFrames)
	}
}

func (c *Client) writeStream(ctx context.Context, conn *websocket.Conn) error {
	ping := time.NewTicker(c.streamPingInterval)
	defer ping.Stop()
	for {
		frames, drainedIDs := c.drainAll()
		if len(frames) > 0 {
			body, err := c.encodeStreamBatch(frames)
			if len(drainedIDs) > 0 {
				c.releaseInFlight(drainedIDs)
			}
			if err != nil {
				c.abortSessions(drainedIDs, "direct stream encode failed after draining frames")
				return fmt.Errorf("encode stream batch: %w", err)
			}
			if err := conn.Write(ctx, websocket.MessageBinary, body); err != nil {
				c.abortSessions(drainedIDs, "direct stream write failed after draining frames")
				return fmt.Errorf("write stream batch: %w", err)
			}
			countFrameBytes(&c.stats.framesOut, &c.stats.bytesOut, frames)
			continue
		}
		wakeCh := c.wake.C()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-wakeCh:
		case <-ping.C:
			pingCtx, cancel := context.WithTimeout(ctx, c.streamConnectTimeout)
			err := conn.Ping(pingCtx)
			cancel()
			if err != nil {
				return fmt.Errorf("stream ping: %w", err)
			}
		}
	}
}

func (c *Client) encodeStreamBatch(frames []*frame.Frame) ([]byte, error) {
	start := time.Now()
	plainSize := encodedBatchPlainSize(frames)
	body, err := frame.EncodeBatchBinary(c.aead, c.clientID, frames)
	c.stats.encode.Add(time.Since(start))
	if err == nil {
		c.stats.reqSize.Add(len(body))
		c.stats.wireRatio.Add(len(body), plainSize)
	}
	return body, err
}
