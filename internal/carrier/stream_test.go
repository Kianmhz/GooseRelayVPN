package carrier

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/kianmhz/GooseRelayVPN/internal/frame"
)

func streamEchoServer(t *testing.T, aead *frame.Crypto) *httptest.Server {
	t.Helper()
	var (
		mu             sync.Mutex
		rxSeqBySession = map[[frame.SessionIDLen]byte]uint64{}
	)
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			t.Errorf("accept websocket: %v", err)
			return
		}
		defer conn.CloseNow()
		for {
			typ, body, err := conn.Read(r.Context())
			if err != nil {
				return
			}
			if typ != websocket.MessageBinary {
				t.Errorf("websocket message type = %v, want binary", typ)
				return
			}
			clientID, in, err := frame.DecodeBatchBinary(aead, body)
			if err != nil {
				t.Errorf("decode stream batch: %v", err)
				return
			}
			if len(in) == 0 {
				continue
			}
			out := make([]*frame.Frame, 0, len(in))
			mu.Lock()
			for _, f := range in {
				seq := rxSeqBySession[f.SessionID]
				rxSeqBySession[f.SessionID] = seq + 1
				out = append(out, &frame.Frame{
					SessionID: f.SessionID,
					Seq:       seq,
					Payload:   f.Payload,
				})
			}
			mu.Unlock()
			resp, err := frame.EncodeBatchBinary(aead, clientID, out)
			if err != nil {
				t.Errorf("encode stream batch: %v", err)
				return
			}
			if err := conn.Write(r.Context(), websocket.MessageBinary, resp); err != nil {
				return
			}
		}
	}))
}

func wsURLFromHTTPURL(url string) string {
	return "ws" + strings.TrimPrefix(url, "http") + "/stream"
}

func TestCarrier_DirectStreamRoundTripEcho(t *testing.T) {
	aead, err := frame.NewCryptoFromHexKey(testKeyHex)
	if err != nil {
		t.Fatalf("crypto: %v", err)
	}
	srv := streamEchoServer(t, aead)
	defer srv.Close()

	c, err := New(Config{
		TransportMode:    "direct_stream",
		DirectStreamURLs: []string{wsURLFromHTTPURL(srv.URL)},
		AESKeyHex:        testKeyHex,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		_ = c.Run(ctx)
		close(done)
	}()

	s := c.NewSession("example.com:80")
	s.EnqueueTx([]byte("hello-stream"))

	select {
	case got := <-s.RxChan:
		if string(got) != "hello-stream" {
			t.Fatalf("got %q want hello-stream", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for stream echo")
	}

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run() did not return after cancel")
	}
}

func TestCarrier_AbortSessionsClosesOnlyAffectedSessions(t *testing.T) {
	c, err := New(Config{
		TransportMode:    "direct_stream",
		DirectStreamURLs: []string{"ws://127.0.0.1:1/stream"},
		AESKeyHex:        testKeyHex,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	affected := c.NewSession("affected.example:443")
	untouched := c.NewSession("untouched.example:443")
	c.mu.Lock()
	c.inFlight[affected.ID] = true
	c.inFlight[untouched.ID] = true
	c.mu.Unlock()

	if n := c.abortSessions([][frame.SessionIDLen]byte{affected.ID}, "test abort"); n != 1 {
		t.Fatalf("abortSessions closed %d sessions, want 1", n)
	}

	select {
	case _, ok := <-affected.RxChan:
		if ok {
			t.Fatal("affected RxChan received data, want closed")
		}
	case <-time.After(time.Second):
		t.Fatal("affected RxChan was not closed")
	}

	select {
	case _, ok := <-untouched.RxChan:
		if !ok {
			t.Fatal("untouched RxChan closed")
		}
	default:
	}

	c.mu.Lock()
	_, affectedSessionPresent := c.sessions[affected.ID]
	_, affectedInFlight := c.inFlight[affected.ID]
	_, untouchedSessionPresent := c.sessions[untouched.ID]
	_, untouchedInFlight := c.inFlight[untouched.ID]
	c.mu.Unlock()
	if affectedSessionPresent || affectedInFlight {
		t.Fatal("affected session still present in carrier maps")
	}
	if !untouchedSessionPresent || !untouchedInFlight {
		t.Fatal("untouched session was removed from carrier maps")
	}
}
