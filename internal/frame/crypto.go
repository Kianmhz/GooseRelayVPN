package frame

import (
	"bytes"
	"compress/flate"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"

	"github.com/klauspost/compress/zstd"
)

// Crypto wraps an AES-256-GCM AEAD with the relay-tunnel envelope format:
//
//	nonce (12 bytes) || ciphertext+tag (Seal output, tag is the trailing 16 bytes)
type Crypto struct {
	aead         cipher.AEAD
	nonceSalt    [12]byte
	nonceCounter atomic.Uint64
}

// b64Encoding is the encoding used on the wire. RawStdEncoding (no '=' padding)
// shaves ~0.5–1.5% of bytes off every batch versus StdEncoding. The decoder is
// tolerant of either form (it strips trailing '=' before decoding) so an
// upgraded peer can still talk to a legacy peer that emits padded output.
var b64Encoding = base64.RawStdEncoding

// NewCryptoFromHexKey parses a 64-char hex string into a 32-byte AES-256 key
// and constructs a Crypto. The same key must be configured on both client and
// VPS server.
//
// Nonces use a per-process 96-bit crypto/rand salt plus an atomic counter.
// That keeps nonce reuse probability negligible even when multiple processes
// share the same AES key; deterministic/replay-detecting nonce schemes would
// need a different protocol.
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
	c := &Crypto{aead: gcm}
	if _, err := rand.Read(c.nonceSalt[:]); err != nil {
		return nil, fmt.Errorf("crypto: nonce salt: %w", err)
	}
	return c, nil
}

// Seal encrypts plaintext and returns nonce||ciphertext (tag appended by GCM).
func (c *Crypto) Seal(plaintext []byte) ([]byte, error) {
	return c.sealTo(plaintext, nil)
}

func (c *Crypto) sealTo(plaintext, dst []byte) ([]byte, error) {
	ns := c.aead.NonceSize()
	needed := ns + len(plaintext) + c.aead.Overhead()
	var out []byte
	if cap(dst) < needed {
		out = make([]byte, ns, needed)
	} else {
		out = dst[:ns]
	}
	nonce := out[:ns]
	copy(nonce, c.nonceSalt[:])
	n := c.nonceCounter.Add(1)
	binary.BigEndian.PutUint64(nonce[ns-8:], binary.BigEndian.Uint64(nonce[ns-8:])^n)
	return c.aead.Seal(out, nonce, plaintext, nil), nil
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
	encSealedPool = sync.Pool{New: func() interface{} {
		buf := make([]byte, 0, 64*1024)
		return &buf
	}}
	decSealedPool = sync.Pool{New: func() interface{} {
		buf := make([]byte, 0, 64*1024)
		return &buf
	}}
	// zstdEncPool and zstdDecPool are used by EncodeBatch/DecodeBatch.
	// Pooling avoids re-initialising the encoder's internal state on every batch.
	// SpeedFastest (level 1) is ~2× faster than DEFLATE BestSpeed and produces
	// 10–15% smaller output on compressible text/HTTP traffic.
	zstdEncPool = sync.Pool{New: func() interface{} {
		enc, _ := zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedFastest))
		return enc
	}}
	zstdDecPool = sync.Pool{New: func() interface{} {
		dec, _ := zstd.NewReader(nil, zstd.WithDecoderMaxMemory(maxDecodedBatchPlainSize))
		return dec
	}}
)

const (
	// batchFlagRaw marks an uncompressed plaintext payload.
	batchFlagRaw = byte(0x00)
	// batchFlagFlate is the legacy DEFLATE flag. No longer emitted by this
	// version; retained so updated binaries can still decode batches sent by
	// older peers that have not been redeployed yet.
	batchFlagFlate = byte(0x01)
	// batchFlagZstd marks a Zstandard-compressed plaintext payload.
	batchFlagZstd = byte(0x02)

	// compressMinSize is the minimum payload size (excluding the flags byte)
	// before compression is attempted. Tiny batches (SYN/FIN/keepalive) are
	// unlikely to benefit.
	compressMinSize = 512

	// maxDecodedBatchPlainSize caps expanded plaintext after decompression.
	// Batches are authenticated, but the tunnel key is also the auth boundary:
	// a compromised or misconfigured peer should not be able to inflate one
	// small compressed batch into unbounded memory on the other side.
	maxDecodedBatchPlainSize = 64 * 1024 * 1024

	// maxPooledSealedCap keeps the Apps Script text path from allocating a new
	// ciphertext buffer for every large response while avoiding unbounded heap
	// retention if someone raises response limits. It covers the default
	// 22 MiB response budget plus nonce/tag overhead.
	maxPooledSealedCap = 24 * 1024 * 1024
	maxPooledPlainCap  = 24 * 1024 * 1024

	// maxPooledDecodedSealedCap covers the normal decoded base64 response size
	// for the default response budget, but drops pathological one-off buffers
	// instead of pinning them in the pool after bulk transfers.
	maxPooledDecodedSealedCap = 24 * 1024 * 1024
)

// EncodeBatch packs zero or more frames into a base64-encoded HTTP body.
//
// Wire format (before base64):
//
//	nonce (12 bytes) || AES-GCM ciphertext+tag over:
//	    flags (1 byte) - 0x00 raw | 0x01 legacy DEFLATE | 0x02 Zstandard body
//	    client_id (16 bytes)
//	    u16 frame_count
//	    for each frame: u32 marshaled_len || marshaled_frame_bytes
//	    (above three fields are compressed when flags selects compression)
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
	body, _, err := EncodeBatchWithStats(c, clientID, frames)
	return body, err
}

// EncodeBatchWithStats is EncodeBatch plus observability about compression and
// wire size. It does not change the wire format.
func EncodeBatchWithStats(c *Crypto, clientID [ClientIDLen]byte, frames []*Frame) ([]byte, BatchEncodeStats, error) {
	sealedP := encSealedPool.Get().(*[]byte)
	sealedBuf := (*sealedP)[:0]
	sealed, stats, err := encodeBatchSealedWithBuffer(c, clientID, frames, sealedBuf)
	if err != nil {
		*sealedP = sealedBuf[:0]
		putPooledSealedBuffer(sealedP)
		return nil, stats, err
	}
	defer func() {
		*sealedP = sealed[:0]
		putPooledSealedBuffer(sealedP)
	}()

	// Pre-size the destination so we encode directly into a []byte rather
	// than the EncodeToString -> string -> []byte intermediate copy.
	out := make([]byte, b64Encoding.EncodedLen(len(sealed)))
	b64Encoding.Encode(out, sealed)
	stats.WireBytes = len(out)
	return out, stats, nil
}

// EncodeBatchBinary packs frames into the same AES-GCM envelope as EncodeBatch
// but returns raw nonce||ciphertext bytes instead of base64 text. It is only
// safe for direct transports; Apps Script must keep using EncodeBatch.
func EncodeBatchBinary(c *Crypto, clientID [ClientIDLen]byte, frames []*Frame) ([]byte, error) {
	body, _, err := EncodeBatchBinaryWithStats(c, clientID, frames)
	return body, err
}

// EncodeBatchBinaryWithStats is EncodeBatchBinary plus compression/wire stats.
func EncodeBatchBinaryWithStats(c *Crypto, clientID [ClientIDLen]byte, frames []*Frame) ([]byte, BatchEncodeStats, error) {
	sealed, stats, err := encodeBatchSealedWithBuffer(c, clientID, frames, nil)
	if err != nil {
		return nil, stats, err
	}
	stats.WireBytes = len(sealed)
	return sealed, stats, nil
}

// BatchEncodeStats describes how a batch was encoded. Sizes are plaintext
// before AES-GCM except WireBytes, which is the returned body length.
type BatchEncodeStats struct {
	Mode                 string
	RawBytes             int
	EncodedBytes         int
	WireBytes            int
	SavedBytes           int
	LostBytes            int
	CompressionAttempted bool
	CompressionUsed      bool
	CompressionSkipped   bool
}

func encodeBatchSealedWithBuffer(c *Crypto, clientID [ClientIDLen]byte, frames []*Frame, sealedBuf []byte) ([]byte, BatchEncodeStats, error) {
	stats := BatchEncodeStats{Mode: "raw"}
	if len(frames) > 0xFFFF {
		return nil, stats, fmt.Errorf("batch: too many frames: %d", len(frames))
	}

	plainSize := 1 + ClientIDLen + 2 // flags byte + client_id + u16 frame count
	for _, f := range frames {
		if len(f.Target) > maxTargetLen {
			return nil, stats, fmt.Errorf("batch: marshal frame: target too long: %d > %d", len(f.Target), maxTargetLen)
		}
		if len(f.Payload) > maxPayloadSize {
			return nil, stats, fmt.Errorf("batch: marshal frame: payload too large: %d", len(f.Payload))
		}
		plainSize += 4 + f.EncodedLen() // u32 length prefix + frame bytes
	}
	stats.RawBytes = plainSize

	// Pull a plaintext scratch buffer from the pool; grow if needed.
	plainP := encPlainPool.Get().(*[]byte)
	plain := (*plainP)[:0]
	if cap(plain) < plainSize {
		plain = make([]byte, 0, plainSize)
	}
	defer func() {
		*plainP = plain
		putPooledPlainBuffer(plainP)
	}()

	plain = append(plain, 0x00) // flags placeholder at index 0
	plain = append(plain, clientID[:]...)
	plain = append(plain, byte(len(frames)>>8), byte(len(frames)))
	for _, f := range frames {
		frameLen := f.EncodedLen()
		plain = append(plain,
			byte(frameLen>>24), byte(frameLen>>16), byte(frameLen>>8), byte(frameLen))
		var err error
		plain, err = f.AppendMarshal(plain)
		if err != nil {
			return nil, stats, fmt.Errorf("batch: marshal frame: %w", err)
		}
	}

	// Attempt Zstandard compression on the payload section (everything after
	// the flags byte at index 0). Only worthwhile for batches large enough that
	// the overhead is amortised; small control batches (SYN/FIN/keepalive) are
	// sent raw. If compression does not shrink the data (e.g. already-encrypted
	// TLS payloads) we fall back to raw transparently.
	sealInput := plain // default: raw, flags byte already 0x00
	if shouldAttemptCompression(plain[1:]) {
		stats.CompressionAttempted = true
		enc := zstdEncPool.Get().(*zstd.Encoder)
		// EncodeAll appends compressed bytes to dst. The [:1:1] cap trick gives
		// us a fresh backing array with the flags placeholder at [0], so the
		// pool-owned plain buffer is never modified.
		compressed := enc.EncodeAll(plain[1:], plain[:1:1])
		zstdEncPool.Put(enc)
		if len(compressed)-1 < len(plain)-1 {
			compressed[0] = batchFlagZstd
			sealInput = compressed
			stats.Mode = "zstd"
			stats.CompressionUsed = true
			stats.SavedBytes = len(plain) - len(compressed)
		} else {
			plain[0] = batchFlagRaw
			stats.LostBytes = (len(compressed) - 1) - (len(plain) - 1)
		}
	} else {
		plain[0] = batchFlagRaw
		stats.CompressionSkipped = true
	}
	stats.EncodedBytes = len(sealInput)

	sealed, err := c.sealTo(sealInput, sealedBuf)
	if err != nil {
		return nil, stats, fmt.Errorf("batch: seal: %w", err)
	}
	return sealed, stats, nil
}

func putPooledSealedBuffer(p *[]byte) {
	buf := (*p)[:0]
	if cap(buf) > maxPooledSealedCap {
		buf = make([]byte, 0, 64*1024)
	}
	*p = buf
	encSealedPool.Put(p)
}

func putPooledPlainBuffer(p *[]byte) {
	buf := (*p)[:0]
	if cap(buf) > maxPooledPlainCap {
		buf = make([]byte, 0, 64*1024)
	}
	*p = buf
	encPlainPool.Put(p)
}

func putPooledDecodedSealedBuffer(p *[]byte) {
	buf := (*p)[:0]
	if cap(buf) > maxPooledDecodedSealedCap {
		buf = make([]byte, 0, 64*1024)
	}
	*p = buf
	decSealedPool.Put(p)
}

func shouldAttemptCompression(payload []byte) bool {
	if len(payload) < compressMinSize {
		return false
	}
	sample := payload
	if len(sample) > 4096 {
		sample = sample[:4096]
	}
	var seen [4]uint64
	unique := 0
	for _, b := range sample {
		word := b >> 6
		mask := uint64(1) << (b & 63)
		if seen[word]&mask == 0 {
			seen[word] |= mask
			unique++
		}
	}
	// Near-uniform byte diversity is a strong signal for encrypted/video-like
	// data. Zstd will usually lose there, so avoid spending CPU just to fall
	// back to raw.
	return unique < 224
}

// DecodeBatch is the inverse of EncodeBatch. The entire batch is authenticated
// as a single unit; any corruption causes the whole batch to be rejected.
//
// Zero-copy contract: when the batch is uncompressed (batchFlagRaw), Frame.Payload
// slices point directly into the plaintext buffer allocated by c.Open — callers
// must treat them as read-only. For compressed batches (batchFlagFlate) the
// payloads point into the decompressed buffer, which is also heap-allocated and
// must not be modified by callers.
func DecodeBatch(c *Crypto, body []byte) ([ClientIDLen]byte, []*Frame, error) {
	var zeroID [ClientIDLen]byte
	if len(body) == 0 {
		return zeroID, nil, errors.New("batch: empty envelope")
	}
	// bytes.TrimSpace returns a subslice (no alloc); Decode writes into a
	// pre-allocated buffer — together this is one allocation instead of three.
	// Strip trailing '=' so we can decode either RawStdEncoding (preferred,
	// what we now emit) or legacy StdEncoding (with padding) bodies. This
	// keeps the upgrade backward-compatible: an updated client/server can
	// still talk to a peer that hasn't been redeployed.
	trimmed := bytes.TrimRight(bytes.TrimSpace(body), "=")
	if len(trimmed) == 0 {
		return zeroID, nil, errors.New("batch: empty envelope")
	}
	sealedP := decSealedPool.Get().(*[]byte)
	sealed := (*sealedP)[:0]
	needed := b64Encoding.DecodedLen(len(trimmed))
	if cap(sealed) < needed {
		sealed = make([]byte, needed)
	} else {
		sealed = sealed[:needed]
	}
	defer func() {
		*sealedP = sealed
		putPooledDecodedSealedBuffer(sealedP)
	}()
	n, err := b64Encoding.Decode(sealed, trimmed)
	if err != nil {
		return zeroID, nil, fmt.Errorf("batch: base64 decode: %w", err)
	}
	if n == 0 {
		return zeroID, nil, errors.New("batch: empty envelope")
	}
	return DecodeBatchBinary(c, sealed[:n])
}

func DecodeBatchBinary(c *Crypto, sealed []byte) ([ClientIDLen]byte, []*Frame, error) {
	var zeroID [ClientIDLen]byte
	if len(sealed) == 0 {
		return zeroID, nil, errors.New("batch: empty envelope")
	}
	rawPlain, err := c.Open(sealed)
	if err != nil {
		return zeroID, nil, fmt.Errorf("batch: open: %w", err)
	}

	// Decode the leading flags byte. Both peers must run the same version;
	// an unrecognised flag byte is rejected so a protocol mismatch surfaces
	// immediately rather than producing silent corruption.
	if len(rawPlain) == 0 {
		return zeroID, nil, errors.New("batch: empty plaintext")
	}
	var plain []byte
	switch rawPlain[0] {
	case batchFlagRaw:
		plain = rawPlain[1:]
	case batchFlagFlate:
		// Legacy path: decode batches from older peers that still emit DEFLATE.
		r := flate.NewReader(bytes.NewReader(rawPlain[1:]))
		decompressed, err := readAllLimited(r, maxDecodedBatchPlainSize)
		if closeErr := r.Close(); err == nil && closeErr != nil {
			err = closeErr
		}
		if err != nil {
			return zeroID, nil, fmt.Errorf("batch: flate decompress: %w", err)
		}
		plain = decompressed
	case batchFlagZstd:
		dec := zstdDecPool.Get().(*zstd.Decoder)
		decompressed, err := dec.DecodeAll(rawPlain[1:], nil)
		zstdDecPool.Put(dec)
		if err != nil {
			return zeroID, nil, fmt.Errorf("batch: zstd decompress: %w", err)
		}
		plain = decompressed
	default:
		return zeroID, nil, fmt.Errorf("batch: unknown flags byte 0x%02x", rawPlain[0])
	}
	if len(plain) > maxDecodedBatchPlainSize {
		return zeroID, nil, fmt.Errorf("batch: expanded plaintext too large (%d bytes > %d)", len(plain), maxDecodedBatchPlainSize)
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
		f, consumed, err := Unmarshal(plain[off : off+flen])
		if err != nil {
			return zeroID, nil, fmt.Errorf("batch: unmarshal frame %d: %w", i, err)
		}
		if consumed != flen {
			return zeroID, nil, fmt.Errorf("batch: frame %d trailing body bytes (%d)", i, flen-consumed)
		}
		frames = append(frames, f)
		off += flen
	}
	if off != len(plain) {
		return zeroID, nil, fmt.Errorf("batch: trailing plaintext (%d bytes)", len(plain)-off)
	}
	return clientID, frames, nil
}

func readAllLimited(r io.Reader, limit int) ([]byte, error) {
	lr := &io.LimitedReader{R: r, N: int64(limit) + 1}
	out, err := io.ReadAll(lr)
	if err != nil {
		return nil, err
	}
	if len(out) > limit {
		return nil, fmt.Errorf("expanded payload too large (%d bytes > %d)", len(out), limit)
	}
	return out, nil
}
