package frame

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"encoding/binary"
	"strings"
	"testing"
)

const testKeyHex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func newTestCrypto(t *testing.T) *Crypto {
	t.Helper()
	c, err := NewCryptoFromHexKey(testKeyHex)
	if err != nil {
		t.Fatalf("new crypto: %v", err)
	}
	return c
}

func TestCryptoSealOpenRoundTrip(t *testing.T) {
	c := newTestCrypto(t)
	pt := []byte("the quick brown fox")
	env, err := c.Seal(pt)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	out, err := c.Open(env)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if !bytes.Equal(out, pt) {
		t.Fatalf("mismatch: %q vs %q", out, pt)
	}
}

func TestCryptoOpen_TamperedCiphertext(t *testing.T) {
	c := newTestCrypto(t)
	env, _ := c.Seal([]byte("hello"))
	env[len(env)-1] ^= 0x01 // flip a bit in the tag region
	if _, err := c.Open(env); err == nil {
		t.Fatal("expected auth error on tampered ciphertext")
	}
}

func TestCryptoOpen_TamperedNonce(t *testing.T) {
	c := newTestCrypto(t)
	env, _ := c.Seal([]byte("hello"))
	env[0] ^= 0x80
	if _, err := c.Open(env); err == nil {
		t.Fatal("expected auth error on tampered nonce")
	}
}

func TestCryptoSealUsesUniqueNonces(t *testing.T) {
	c := newTestCrypto(t)
	a, err := c.Seal([]byte("hello"))
	if err != nil {
		t.Fatalf("seal a: %v", err)
	}
	b, err := c.Seal([]byte("hello"))
	if err != nil {
		t.Fatalf("seal b: %v", err)
	}
	if bytes.Equal(a[:12], b[:12]) {
		t.Fatalf("nonce repeated: %x", a[:12])
	}
}

func TestCryptoOpen_WrongKey(t *testing.T) {
	a := newTestCrypto(t)
	b, _ := NewCryptoFromHexKey(strings.Repeat("ff", 32))
	env, _ := a.Seal([]byte("hello"))
	if _, err := b.Open(env); err == nil {
		t.Fatal("expected auth error on wrong key")
	}
}

func TestCryptoSealAllocatesOnlyEnvelope(t *testing.T) {
	c := newTestCrypto(t)
	payload := bytes.Repeat([]byte("x"), 1024)

	allocs := testing.AllocsPerRun(1000, func() {
		if _, err := c.Seal(payload); err != nil {
			t.Fatalf("seal: %v", err)
		}
	})
	if allocs > 1 {
		t.Fatalf("Seal allocations = %.2f, want <= 1", allocs)
	}
}

func TestCryptoSealToReusesProvidedBuffer(t *testing.T) {
	c := newTestCrypto(t)
	payload := bytes.Repeat([]byte("x"), 1024)
	buf := make([]byte, 0, c.aead.NonceSize()+len(payload)+c.aead.Overhead())

	allocs := testing.AllocsPerRun(1000, func() {
		out, err := c.sealTo(payload, buf)
		if err != nil {
			t.Fatalf("sealTo: %v", err)
		}
		if cap(out) != cap(buf) {
			t.Fatalf("sealTo did not reuse provided buffer")
		}
	})
	if allocs != 0 {
		t.Fatalf("sealTo allocations = %.2f, want 0 with sufficient buffer", allocs)
	}
}

func TestPutPooledSealedBufferDropsOversizedCapacity(t *testing.T) {
	buf := make([]byte, 0, maxPooledSealedCap+1)
	putPooledSealedBuffer(&buf)
	if cap(buf) > maxPooledSealedCap {
		t.Fatalf("pooled sealed buffer cap = %d, want <= %d", cap(buf), maxPooledSealedCap)
	}
}

func TestPutPooledPlainBufferDropsOversizedCapacity(t *testing.T) {
	buf := make([]byte, 0, maxPooledPlainCap+1)
	putPooledPlainBuffer(&buf)
	if cap(buf) > maxPooledPlainCap {
		t.Fatalf("pooled plain buffer cap = %d, want <= %d", cap(buf), maxPooledPlainCap)
	}
}

func TestPutPooledDecodedSealedBufferDropsOversizedCapacity(t *testing.T) {
	buf := make([]byte, 0, maxPooledDecodedSealedCap+1)
	putPooledDecodedSealedBuffer(&buf)
	if cap(buf) > maxPooledDecodedSealedCap {
		t.Fatalf("pooled decoded sealed buffer cap = %d, want <= %d", cap(buf), maxPooledDecodedSealedCap)
	}
}

func TestNewCryptoFromHexKey_Errors(t *testing.T) {
	if _, err := NewCryptoFromHexKey("zz"); err == nil {
		t.Fatal("expected hex error")
	}
	if _, err := NewCryptoFromHexKey("0123"); err == nil {
		t.Fatal("expected length error")
	}
}

func TestEncodeDecodeBatch_RoundTrip(t *testing.T) {
	c := newTestCrypto(t)
	in := []*Frame{
		{SessionID: sid(1), Seq: 0, Flags: FlagSYN, Target: "example.com:80", Payload: []byte("a")},
		{SessionID: sid(1), Seq: 1, Payload: []byte("bb")},
		{SessionID: sid(2), Seq: 0, Flags: FlagACK},
	}
	wantClient := [ClientIDLen]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	body, err := EncodeBatch(c, wantClient, in)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	gotClient, out, err := DecodeBatch(c, body)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if gotClient != wantClient {
		t.Fatalf("clientID: got %x want %x", gotClient, wantClient)
	}
	if len(out) != len(in) {
		t.Fatalf("count: got %d want %d", len(out), len(in))
	}
	for i := range in {
		if out[i].SessionID != in[i].SessionID || out[i].Seq != in[i].Seq || out[i].Flags != in[i].Flags {
			t.Fatalf("frame %d header mismatch", i)
		}
		if !bytes.Equal(out[i].Payload, in[i].Payload) {
			t.Fatalf("frame %d payload mismatch", i)
		}
	}
}

func TestEncodeDecodeBatchBinary_RoundTrip(t *testing.T) {
	c := newTestCrypto(t)
	in := []*Frame{
		{SessionID: sid(1), Seq: 0, Flags: FlagSYN, Target: "example.com:80", Payload: []byte("binary")},
		{SessionID: sid(1), Seq: 1, Payload: []byte("payload")},
	}
	wantClient := [ClientIDLen]byte{9, 8, 7, 6}

	body, err := EncodeBatchBinary(c, wantClient, in)
	if err != nil {
		t.Fatalf("encode binary: %v", err)
	}
	textBody, err := EncodeBatch(c, wantClient, in)
	if err != nil {
		t.Fatalf("encode text: %v", err)
	}
	if len(body) >= len(textBody) {
		t.Fatalf("binary body len = %d, want smaller than base64 text len %d", len(body), len(textBody))
	}
	gotClient, out, err := DecodeBatchBinary(c, body)
	if err != nil {
		t.Fatalf("decode binary: %v", err)
	}
	if gotClient != wantClient {
		t.Fatalf("clientID: got %x want %x", gotClient, wantClient)
	}
	if len(out) != len(in) {
		t.Fatalf("frame count = %d, want %d", len(out), len(in))
	}
	for i := range in {
		if out[i].SessionID != in[i].SessionID || out[i].Seq != in[i].Seq || !bytes.Equal(out[i].Payload, in[i].Payload) {
			t.Fatalf("frame %d mismatch", i)
		}
	}
}

func TestDecodeBatchBinaryRejectsTrailingPlaintext(t *testing.T) {
	c := newTestCrypto(t)
	clientID := [ClientIDLen]byte{1, 2, 3}
	plain := []byte{batchFlagRaw}
	plain = append(plain, clientID[:]...)
	var count [2]byte
	binary.BigEndian.PutUint16(count[:], 0)
	plain = append(plain, count[:]...)
	plain = append(plain, 0x99)
	sealed, err := c.Seal(plain)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	if _, _, err := DecodeBatchBinary(c, sealed); err == nil {
		t.Fatal("DecodeBatchBinary accepted authenticated trailing plaintext")
	}
}

func TestDecodeBatchBinaryRejectsTrailingBytesInsideFrameBody(t *testing.T) {
	c := newTestCrypto(t)
	clientID := [ClientIDLen]byte{1, 2, 3}
	f := &Frame{SessionID: sid(1), Seq: 0, Payload: []byte("ok")}
	fb, err := f.Marshal()
	if err != nil {
		t.Fatalf("marshal frame: %v", err)
	}
	fb = append(fb, 0x99)

	plain := []byte{batchFlagRaw}
	plain = append(plain, clientID[:]...)
	var count [2]byte
	binary.BigEndian.PutUint16(count[:], 1)
	plain = append(plain, count[:]...)
	var flen [4]byte
	binary.BigEndian.PutUint32(flen[:], uint32(len(fb)))
	plain = append(plain, flen[:]...)
	plain = append(plain, fb...)
	sealed, err := c.Seal(plain)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	if _, _, err := DecodeBatchBinary(c, sealed); err == nil {
		t.Fatal("DecodeBatchBinary accepted trailing bytes inside a framed body")
	}
}

func TestShouldAttemptCompressionSkipsHighEntropyPayload(t *testing.T) {
	payload := make([]byte, 4096)
	for i := range payload {
		payload[i] = byte((i*251 + 17) & 0xff)
	}
	if shouldAttemptCompression(payload) {
		t.Fatal("high-entropy payload should skip compression")
	}
}

func TestShouldAttemptCompressionAllowsRepetitivePayload(t *testing.T) {
	payload := bytes.Repeat([]byte("compress-me-"), 512)
	if !shouldAttemptCompression(payload) {
		t.Fatal("repetitive payload should attempt compression")
	}
}

func TestDecodeBatch_EmptyBody(t *testing.T) {
	c := newTestCrypto(t)
	if _, _, err := DecodeBatch(c, nil); err == nil {
		t.Fatal("DecodeBatch(nil) succeeded; want empty envelope error")
	}
}

func TestDecodeBatch_RejectsNonEmptyEmptyEnvelope(t *testing.T) {
	c := newTestCrypto(t)
	for _, body := range [][]byte{
		[]byte(" \r\n\t "),
		[]byte("===="),
	} {
		if _, _, err := DecodeBatch(c, body); err == nil {
			t.Fatalf("DecodeBatch(%q) succeeded; want empty envelope error", string(body))
		}
	}
	if _, _, err := DecodeBatchBinary(c, nil); err == nil {
		t.Fatal("DecodeBatchBinary(nil) succeeded; want empty envelope error")
	}
}

func TestReadAllLimitedRejectsExpandedPayload(t *testing.T) {
	if _, err := readAllLimited(bytes.NewReader([]byte("abcdef")), 5); err == nil {
		t.Fatal("readAllLimited succeeded for over-limit payload")
	}
	got, err := readAllLimited(bytes.NewReader([]byte("abcde")), 5)
	if err != nil {
		t.Fatalf("readAllLimited: %v", err)
	}
	if string(got) != "abcde" {
		t.Fatalf("got %q, want abcde", got)
	}
}

func benchSealOpenBatch(b *testing.B, frames int, payloadSize int) {
	c, err := NewCryptoFromHexKey(testKeyHex)
	if err != nil {
		b.Fatalf("crypto: %v", err)
	}
	in := make([]*Frame, frames)
	pl := bytes.Repeat([]byte{'p'}, payloadSize)
	for i := range in {
		in[i] = &Frame{SessionID: sid(byte(i)), Seq: uint64(i), Payload: pl}
	}
	var benchClient [ClientIDLen]byte
	body, err := EncodeBatch(c, benchClient, in)
	if err != nil {
		b.Fatalf("encode: %v", err)
	}
	b.SetBytes(int64(len(body)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		body, err := EncodeBatch(c, benchClient, in)
		if err != nil {
			b.Fatalf("encode: %v", err)
		}
		if _, _, err := DecodeBatch(c, body); err != nil {
			b.Fatalf("decode: %v", err)
		}
	}
}

func BenchmarkSealOpenBatch_8x4KiB(b *testing.B)  { benchSealOpenBatch(b, 8, 4*1024) }
func BenchmarkSealOpenBatch_64x4KiB(b *testing.B) { benchSealOpenBatch(b, 64, 4*1024) }

// Tampering any byte in the ciphertext must cause the entire batch to be
// rejected — the batch is authenticated as a single unit.
func TestDecodeBatch_TamperedBatchFails(t *testing.T) {
	c := newTestCrypto(t)
	in := []*Frame{
		{SessionID: sid(1), Seq: 0, Payload: []byte("good1")},
		{SessionID: sid(1), Seq: 1, Payload: []byte("good2")},
	}
	var zeroClient [ClientIDLen]byte
	body, _ := EncodeBatch(c, zeroClient, in)
	raw, _ := b64Encoding.DecodeString(string(body))
	raw[len(raw)/2] ^= 0x01 // flip a bit in the middle of the ciphertext
	out := make([]byte, b64Encoding.EncodedLen(len(raw)))
	b64Encoding.Encode(out, raw)
	if _, _, err := DecodeBatch(c, out); err == nil {
		t.Fatal("expected auth error on tampered batch, got nil")
	}
}

func TestDecodeBatch_LegacyPadding(t *testing.T) {
	c := newTestCrypto(t)
	in := []*Frame{{SessionID: sid(1), Payload: []byte("legacy")}}
	var zeroClient [ClientIDLen]byte

	// Manually construct a batch in the new plaintext format but with
	// StdEncoding (padded) base64 — older binaries emitted padded output.
	rawFrame, _ := in[0].Marshal()
	plain := make([]byte, 0)
	plain = append(plain, batchFlagRaw)     // flags byte
	plain = append(plain, zeroClient[:]...) // client_id
	plain = append(plain, 0, 1)             // frame count = 1
	plain = append(plain, byte(len(rawFrame)>>24), byte(len(rawFrame)>>16), byte(len(rawFrame)>>8), byte(len(rawFrame)))
	plain = append(plain, rawFrame...)

	sealed, _ := c.Seal(plain)
	legacyBody := []byte(base64.StdEncoding.EncodeToString(sealed))

	// Should still decode correctly despite padded base64.
	gotClient, out, err := DecodeBatch(c, legacyBody)
	if err != nil {
		t.Fatalf("decode legacy: %v", err)
	}
	if gotClient != zeroClient {
		t.Fatal("clientID mismatch")
	}
	if len(out) != 1 || !bytes.Equal(out[0].Payload, in[0].Payload) {
		t.Fatal("payload mismatch")
	}
}

func TestEncodeDecodeBatch_Compressed(t *testing.T) {
	c := newTestCrypto(t)
	// Repeat highly compressible data to exceed compressMinSize (512 bytes).
	payload := bytes.Repeat([]byte("Hello, compressible test payload! "), 20)
	if len(payload) < compressMinSize {
		t.Fatalf("payload too small to trigger compression: %d bytes", len(payload))
	}
	in := []*Frame{
		{SessionID: sid(1), Seq: 0, Flags: FlagSYN, Target: "example.com:443", Payload: payload},
		{SessionID: sid(1), Seq: 1, Payload: payload},
	}
	var clientID [ClientIDLen]byte
	for i := range clientID {
		clientID[i] = byte(i + 1)
	}
	body, err := EncodeBatch(c, clientID, in)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	gotClient, out, err := DecodeBatch(c, body)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if gotClient != clientID {
		t.Fatalf("clientID mismatch: got %x want %x", gotClient, clientID)
	}
	if len(out) != len(in) {
		t.Fatalf("frame count: got %d want %d", len(out), len(in))
	}
	for i := range in {
		if out[i].SessionID != in[i].SessionID || out[i].Seq != in[i].Seq ||
			out[i].Flags != in[i].Flags || out[i].Target != in[i].Target {
			t.Fatalf("frame %d header mismatch", i)
		}
		if !bytes.Equal(out[i].Payload, in[i].Payload) {
			t.Fatalf("frame %d payload mismatch", i)
		}
	}
	// Verify that the compressed wire body is smaller than it would be
	// uncompressed (proves compression actually fired for this payload).
	plainSize := 1 + ClientIDLen + 2 + len(in)*(4+SessionIDLen+8+1+1+4+len(payload))
	if len(body) >= plainSize {
		t.Logf("note: wire body (%d) not smaller than estimated uncompressed (%d) — check threshold", len(body), plainSize)
	}
}

// TestZstdFlagEmitted verifies that batches large enough to compress are
// sealed with batchFlagZstd (0x02) and not with the old batchFlagFlate (0x01).
// It also checks that round-tripping through DecodeBatch produces identical
// frames, and that the zstd wire body is strictly smaller than the raw body.
func TestZstdFlagEmitted(t *testing.T) {
	c := newTestCrypto(t)

	// Highly compressible payload well above compressMinSize.
	payload := bytes.Repeat([]byte("GooseRelayVPN zstd test payload — repeated for compressibility. "), 20)
	if len(payload) < compressMinSize {
		t.Fatalf("payload too small to trigger compression: %d < %d", len(payload), compressMinSize)
	}

	frames := []*Frame{
		{SessionID: sid(1), Seq: 0, Flags: FlagSYN, Target: "example.com:443", Payload: payload},
		{SessionID: sid(1), Seq: 1, Payload: payload},
		{SessionID: sid(1), Seq: 2, Payload: payload},
	}
	var clientID [ClientIDLen]byte
	for i := range clientID {
		clientID[i] = byte(i + 1)
	}

	body, err := EncodeBatch(c, clientID, frames)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	// Peek inside: base64-decode then AES-decrypt to read the flags byte.
	trimmed := bytes.TrimRight(bytes.TrimSpace(body), "=")
	sealed := make([]byte, b64Encoding.DecodedLen(len(trimmed)))
	n, err := b64Encoding.Decode(sealed, trimmed)
	if err != nil {
		t.Fatalf("base64 decode: %v", err)
	}
	rawPlain, err := c.Open(sealed[:n])
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if len(rawPlain) == 0 {
		t.Fatal("empty plaintext after open")
	}
	if rawPlain[0] != batchFlagZstd {
		t.Errorf("flags byte = 0x%02x, want batchFlagZstd (0x%02x)", rawPlain[0], batchFlagZstd)
	}
	t.Logf("flags byte = 0x%02x (zstd) ✓", rawPlain[0])

	// Round-trip must reproduce identical frames.
	gotClient, out, err := DecodeBatch(c, body)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if gotClient != clientID {
		t.Fatalf("clientID mismatch: got %x want %x", gotClient, clientID)
	}
	if len(out) != len(frames) {
		t.Fatalf("frame count: got %d want %d", len(out), len(frames))
	}
	for i, f := range frames {
		if out[i].SessionID != f.SessionID || out[i].Seq != f.Seq ||
			out[i].Flags != f.Flags || out[i].Target != f.Target {
			t.Fatalf("frame %d header mismatch", i)
		}
		if !bytes.Equal(out[i].Payload, f.Payload) {
			t.Fatalf("frame %d payload mismatch", i)
		}
	}

	// zstd wire body must be smaller than the estimated raw size.
	rawEstimate := 1 + ClientIDLen + 2 + len(frames)*(4+SessionIDLen+8+1+1+4+len(payload))
	ratio := 100.0 * float64(len(body)) / float64(rawEstimate)
	t.Logf("wire body = %d bytes, raw estimate = %d bytes, ratio = %.1f%% (%.1f%% reduction)",
		len(body), rawEstimate, ratio, 100-ratio)
	if len(body) >= rawEstimate {
		t.Errorf("zstd body (%d) is not smaller than raw estimate (%d) — compression did not fire or helped nothing",
			len(body), rawEstimate)
	}
}

func TestEncodeBatchWithStatsReportsCompressionOutcome(t *testing.T) {
	c, err := NewCryptoFromHexKey(testKeyHex)
	if err != nil {
		t.Fatal(err)
	}
	clientID := [ClientIDLen]byte{1, 2, 3}

	compressible := bytes.Repeat([]byte("compressible-payload-"), 128)
	body, stats, err := EncodeBatchWithStats(c, clientID, []*Frame{{
		SessionID: [SessionIDLen]byte{1},
		Payload:   compressible,
	}})
	if err != nil {
		t.Fatalf("EncodeBatchWithStats compressible: %v", err)
	}
	if len(body) != stats.WireBytes {
		t.Fatalf("WireBytes = %d, want body len %d", stats.WireBytes, len(body))
	}
	if stats.Mode != "zstd" || !stats.CompressionUsed || !stats.CompressionAttempted {
		t.Fatalf("compressible stats = %#v, want zstd used", stats)
	}
	if stats.SavedBytes == 0 || stats.LostBytes != 0 {
		t.Fatalf("compressible saved/lost = %d/%d, want saved>0 lost=0", stats.SavedBytes, stats.LostBytes)
	}

	smallBody, smallStats, err := EncodeBatchWithStats(c, clientID, []*Frame{{
		SessionID: [SessionIDLen]byte{2},
		Payload:   []byte("tiny"),
	}})
	if err != nil {
		t.Fatalf("EncodeBatchWithStats small: %v", err)
	}
	if len(smallBody) != smallStats.WireBytes {
		t.Fatalf("small WireBytes = %d, want body len %d", smallStats.WireBytes, len(smallBody))
	}
	if smallStats.Mode != "raw" || !smallStats.CompressionSkipped || smallStats.CompressionAttempted {
		t.Fatalf("small stats = %#v, want raw skipped", smallStats)
	}
}

// TestZstdLegacyFlateStillDecodes verifies the backward-compat path: a batch
// encoded with the old batchFlagFlate (0x01) is still correctly decoded.
func TestZstdLegacyFlateStillDecodes(t *testing.T) {
	c := newTestCrypto(t)
	payload := bytes.Repeat([]byte("legacy flate payload "), 40)

	// Manually build a batchFlagFlate batch.
	f := &Frame{SessionID: sid(5), Seq: 42, Payload: payload}
	rawFrame, err := f.Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	// Build the uncompressed plaintext header.
	plain := make([]byte, 0)
	plain = append(plain, batchFlagFlate)
	plain = append(plain, make([]byte, ClientIDLen)...)
	plain = append(plain, 0, 1) // 1 frame
	plain = append(plain,
		byte(len(rawFrame)>>24), byte(len(rawFrame)>>16),
		byte(len(rawFrame)>>8), byte(len(rawFrame)))
	plain = append(plain, rawFrame...)

	// Compress plain[1:] with flate to produce the legacy wire format.
	var cbuf bytes.Buffer
	fw, _ := flate.NewWriter(&cbuf, flate.BestSpeed)
	_, _ = fw.Write(plain[1:])
	_ = fw.Close()
	legacyPlain := append(plain[:1:1], cbuf.Bytes()...)
	legacyPlain[0] = batchFlagFlate

	sealed, err := c.Seal(legacyPlain)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	encoded := make([]byte, b64Encoding.EncodedLen(len(sealed)))
	b64Encoding.Encode(encoded, sealed)

	_, out, err := DecodeBatch(c, encoded)
	if err != nil {
		t.Fatalf("legacy flate decode: %v", err)
	}
	if len(out) != 1 || out[0].Seq != 42 || !bytes.Equal(out[0].Payload, payload) {
		t.Fatal("legacy flate round-trip payload mismatch")
	}
	t.Log("legacy batchFlagFlate decoded correctly ✓")
}
