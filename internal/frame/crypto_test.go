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
	body, err := EncodeBatch(c, in)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	out, err := DecodeBatch(c, body)
	if err != nil {
		t.Fatalf("decode: %v", err)
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
	out, err := DecodeBatch(c, nil)
	if err != nil {
		t.Fatalf("decode empty: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("want 0 frames, got %d", len(out))
	}
}

// Tampering any byte in the ciphertext must cause the entire batch to be
// rejected — the batch is authenticated as a single unit.
func TestDecodeBatch_TamperedBatchFails(t *testing.T) {
	c := newTestCrypto(t)
	in := []*Frame{
		{SessionID: sid(1), Seq: 0, Payload: []byte("good1")},
		{SessionID: sid(1), Seq: 1, Payload: []byte("good2")},
	}
	body, _ := EncodeBatch(c, in)
	raw, _ := base64.StdEncoding.DecodeString(string(body))
	raw[len(raw)/2] ^= 0x01 // flip a bit in the middle of the ciphertext
	tampered := []byte(base64.StdEncoding.EncodeToString(raw))
	if _, err := DecodeBatch(c, tampered); err == nil {
		t.Fatal("expected auth error on tampered batch, got nil")
	}
}
