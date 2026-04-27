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
)

// Crypto wraps an AES-256-GCM AEAD with the relay-tunnel envelope format:
//
//	nonce (12 bytes) || ciphertext+tag (Seal output, tag is the trailing 16 bytes)
type Crypto struct {
	aead cipher.AEAD
}

// NewCryptoFromHexKey parses a 64-char hex string into a 32-byte AES-256 key
// and constructs a Crypto. The same key must be configured on both client and DO server.
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

// EncodeBatch packs zero or more frames into a base64-encoded HTTP body.
//
// Wire format (before base64):
//
//	nonce (12 bytes) || AES-GCM ciphertext+tag over:
//	    u16 frame_count
//	    for each frame: u32 marshaled_len || marshaled_frame_bytes
//
// The entire batch is sealed once, replacing the old per-frame envelope scheme.
// This reduces crypto overhead from O(N) nonces+tags to one, cutting both CPU
// and wire bytes significantly for large batches.
// base64 is retained for Apps Script's ContentService text requirement.
func EncodeBatch(c *Crypto, frames []*Frame) ([]byte, error) {
	if len(frames) > 0xFFFF {
		return nil, fmt.Errorf("batch: too many frames: %d", len(frames))
	}

	// Marshal all frames first so we know the exact plaintext size.
	marshaled := make([][]byte, len(frames))
	plainSize := 2 // u16 frame count
	for i, f := range frames {
		raw, err := f.Marshal()
		if err != nil {
			return nil, fmt.Errorf("batch: marshal frame: %w", err)
		}
		marshaled[i] = raw
		plainSize += 4 + len(raw) // u32 length prefix + frame bytes
	}

	plain := make([]byte, 0, plainSize)
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
func DecodeBatch(c *Crypto, body []byte) ([]*Frame, error) {
	if len(body) == 0 {
		return nil, nil
	}
	// bytes.TrimSpace returns a subslice (no alloc); Decode writes into a
	// pre-allocated buffer — together this is one allocation instead of three.
	trimmed := bytes.TrimSpace(body)
	sealed := make([]byte, base64.StdEncoding.DecodedLen(len(trimmed)))
	n, err := base64.StdEncoding.Decode(sealed, trimmed)
	if err != nil {
		return nil, fmt.Errorf("batch: base64 decode: %w", err)
	}
	sealed = sealed[:n]

	plain, err := c.Open(sealed)
	if err != nil {
		return nil, fmt.Errorf("batch: open: %w", err)
	}

	if len(plain) < 2 {
		return nil, errors.New("batch: short header")
	}
	count := int(binary.BigEndian.Uint16(plain[:2]))
	off := 2
	frames := make([]*Frame, 0, count)
	for i := 0; i < count; i++ {
		if len(plain) < off+4 {
			return nil, errors.New("batch: short frame length")
		}
		flen := int(binary.BigEndian.Uint32(plain[off:]))
		off += 4
		if len(plain) < off+flen {
			return nil, errors.New("batch: short frame body")
		}
		f, _, err := Unmarshal(plain[off : off+flen])
		if err != nil {
			return nil, fmt.Errorf("batch: unmarshal frame %d: %w", i, err)
		}
		frames = append(frames, f)
		off += flen
	}
	return frames, nil
}
