package frame

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
)

// Crypto wraps an AES-256-GCM AEAD with the relay-tunnel envelope format:
//
//	nonce (12 bytes) || ciphertext+tag (Seal output, tag is the trailing 16 bytes)
type Crypto struct {
	aead cipher.AEAD
}

// NewCryptoFromHexKey parses a 64-char hex string into a 32-byte AES-256 key
// and constructs a Crypto. The same key must be configured on both client and VPS server.
func NewCryptoFromHexKey(hexKey string) (*Crypto, error) {
	key, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, fmt.Errorf("crypto: invalid hex key: %w", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("crypto: key must be 32 bytes (AES-256), got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("crypto: aes new cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("crypto: new gcm: %w", err)
	}
	return &Crypto{aead: gcm}, nil
}

// Seal encrypts plaintext and returns nonce||ciphertext (tag appended by GCM).
func (c *Crypto) Seal(plaintext []byte) ([]byte, error) {
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("crypto: nonce read: %w", err)
	}
	ct := c.aead.Seal(nil, nonce, plaintext, nil)
	out := make([]byte, 0, len(nonce)+len(ct))
	out = append(out, nonce...)
	out = append(out, ct...)
	return out, nil
}

// Open inverts Seal. Returns an error on auth-tag failure (tampered ciphertext,
// nonce, or tag, or wrong key).
func (c *Crypto) Open(envelope []byte) ([]byte, error) {
	ns := c.aead.NonceSize()
	if len(envelope) < ns+c.aead.Overhead() {
		return nil, errors.New("crypto: envelope too short")
	}
	nonce := envelope[:ns]
	ct := envelope[ns:]
	pt, err := c.aead.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, fmt.Errorf("crypto: open: %w", err)
	}
	return pt, nil
}

// ClientIDLen is the length of the per-process client identifier prepended to
// every batch. Clients pick a random ClientID once at startup; the server uses
// it to partition sessions so that downstream frames generated for one client
// are never delivered to a different client polling the same server.
const ClientIDLen = 16

// batchPool reuses the marshaled-slice scratch and the plaintext header
// buffer across EncodeBatch calls. Without pooling, each batch allocates two
// fresh buffers (the plain header + the marshaled-frame slice header), which
// is meaningful at our drain rate (≤ every 350 ms per worker, 3 workers).
var (
	encPlainPool = sync.Pool{New: func() interface{} {
		buf := make([]byte, 0, 64*1024)
		return &buf
	}}
	encMarshaledPool = sync.Pool{New: func() interface{} {
		buf := make([][]byte, 0, 32)
		return &buf
	}}
)

// EncodeBatch packs zero or more frames into a base64-encoded HTTP body.
//
// Wire format (before base64):
//
//	nonce (12 bytes) || AES-GCM ciphertext+tag over:
//	    client_id (16 bytes)
//	    u16 frame_count
//	    for each frame: u32 marshaled_len || marshaled_frame_bytes
//
// The entire batch is sealed once, replacing the old per-frame envelope scheme.
// This reduces crypto overhead from O(N) nonces+tags to one, cutting both CPU
// and wire bytes significantly for large batches.
// base64 is retained for Apps Script's ContentService text requirement.
//
// The client_id is sent inside the encrypted plaintext (not as an HTTP header)
// because the Apps Script forwarder only relays the request body — headers do
// not survive the hop. Sealing it under AES-GCM also means a passive observer
// of the relay traffic cannot tell two clients apart by their IDs.
func EncodeBatch(c *Crypto, clientID [ClientIDLen]byte, frames []*Frame) ([]byte, error) {
	if len(frames) > 0xFFFF {
		return nil, fmt.Errorf("batch: too many frames: %d", len(frames))
	}

	// Marshal all frames first so we know the exact plaintext size.
	marshaledP := encMarshaledPool.Get().(*[][]byte)
	marshaled := (*marshaledP)[:0]
	defer func() {
		for i := range marshaled {
			marshaled[i] = nil
		}
		marshaled = marshaled[:0]
		*marshaledP = marshaled
		encMarshaledPool.Put(marshaledP)
	}()

	plainSize := ClientIDLen + 2 // client_id + u16 frame count
	for _, f := range frames {
		raw, err := f.Marshal()
		if err != nil {
			return nil, fmt.Errorf("batch: marshal frame: %w", err)
		}
		marshaled = append(marshaled, raw)
		plainSize += 4 + len(raw) // u32 length prefix + frame bytes
	}

	// Pull a plaintext scratch buffer from the pool; grow if needed.
	plainP := encPlainPool.Get().(*[]byte)
	plain := (*plainP)[:0]
	if cap(plain) < plainSize {
		plain = make([]byte, 0, plainSize)
	}
	defer func() {
		// Reset and return to pool. The capacity is preserved so the next
		// EncodeBatch reuses the same underlying allocation.
		plain = plain[:0]
		*plainP = plain
		encPlainPool.Put(plainP)
	}()

	plain = append(plain, clientID[:]...)
	plain = append(plain, byte(len(frames)>>8), byte(len(frames)))
	for _, raw := range marshaled {
		plain = append(plain,
			byte(len(raw)>>24), byte(len(raw)>>16), byte(len(raw)>>8), byte(len(raw)))
		plain = append(plain, raw...)
	}

	sealed, err := c.Seal(plain)
	if err != nil {
		return nil, fmt.Errorf("batch: seal: %w", err)
	}
	return []byte(base64.StdEncoding.EncodeToString(sealed)), nil
}

// DecodeBatch is the inverse of EncodeBatch. The entire batch is authenticated
// as a single unit; any corruption causes the whole batch to be rejected.
//
// Zero-copy contract: Frame.Payload slices returned here point directly into
// the plaintext buffer allocated by c.Open. Callers must not modify that buffer.
// Since c.Open always allocates a fresh slice, this is safe as long as callers
// treat Frame.Payload as read-only — which session.ProcessRx and upstream.Write
// both do.
func DecodeBatch(c *Crypto, body []byte) ([ClientIDLen]byte, []*Frame, error) {
	var zeroID [ClientIDLen]byte
	if len(body) == 0 {
		return zeroID, nil, nil
	}
	// bytes.TrimSpace returns a subslice (no alloc); Decode writes into a
	// pre-allocated buffer — together this is one allocation instead of three.
	trimmed := bytes.TrimSpace(body)
	sealed := make([]byte, base64.StdEncoding.DecodedLen(len(trimmed)))
	n, err := base64.StdEncoding.Decode(sealed, trimmed)
	if err != nil {
		return zeroID, nil, fmt.Errorf("batch: base64 decode: %w", err)
	}
	sealed = sealed[:n]

	plain, err := c.Open(sealed)
	if err != nil {
		return zeroID, nil, fmt.Errorf("batch: open: %w", err)
	}

	if len(plain) < ClientIDLen+2 {
		return zeroID, nil, errors.New("batch: short header")
	}
	var clientID [ClientIDLen]byte
	copy(clientID[:], plain[:ClientIDLen])
	off := ClientIDLen
	count := int(binary.BigEndian.Uint16(plain[off : off+2]))
	off += 2
	frames := make([]*Frame, 0, count)
	for i := 0; i < count; i++ {
		if len(plain) < off+4 {
			return zeroID, nil, errors.New("batch: short frame length")
		}
		flen := int(binary.BigEndian.Uint32(plain[off:]))
		off += 4
		if len(plain) < off+flen {
			return zeroID, nil, errors.New("batch: short frame body")
		}
		f, _, err := Unmarshal(plain[off : off+flen])
		if err != nil {
			return zeroID, nil, fmt.Errorf("batch: unmarshal frame %d: %w", i, err)
		}
		frames = append(frames, f)
		off += flen
	}
	return clientID, frames, nil
}
