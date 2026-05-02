package frame

import (
	"bytes"
	"encoding/base64"
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

func TestCryptoOpen_WrongKey(t *testing.T) {
	a := newTestCrypto(t)
	b, _ := NewCryptoFromHexKey(strings.Repeat("ff", 32))
	env, _ := a.Seal([]byte("hello"))
	if _, err := b.Open(env); err == nil {
		t.Fatal("expected auth error on wrong key")
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

func TestDecodeBatch_EmptyBody(t *testing.T) {
	c := newTestCrypto(t)
	_, out, err := DecodeBatch(c, nil)
	if err != nil {
		t.Fatalf("decode empty: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("want 0 frames, got %d", len(out))
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

	// Manually construct a padded base64 batch (like an older version would).
	plainSize := ClientIDLen + 2 + 4 + 1 + 8 + 6 // header + u16 + u32 len + flags + sid + payload
	plain := make([]byte, 0, plainSize)
	plain = append(plain, zeroClient[:]...)
	plain = append(plain, 0, 1) // count = 1
	rawFrame, _ := in[0].Marshal()
	plain = append(plain, byte(len(rawFrame)>>24), byte(len(rawFrame)>>16), byte(len(rawFrame)>>8), byte(len(rawFrame)))
	plain = append(plain, rawFrame...)

	sealed, _ := c.Seal(plain)
	legacyBody := []byte(base64.StdEncoding.EncodeToString(sealed))

	// Should still decode correctly.
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
