package frame

import (
	"bytes"
	"testing"
)

func sid(b byte) [SessionIDLen]byte {
	var out [SessionIDLen]byte
	for i := range out {
		out[i] = b
	}
	return out
}

func TestFrameRoundTrip_DataOnly(t *testing.T) {
	in := &Frame{
		SessionID: sid(0xAA),
		Seq:       42,
		Payload:   []byte("hello world"),
	}
	raw, err := in.Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	out, n, err := Unmarshal(raw)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if n != len(raw) {
		t.Fatalf("n=%d want %d", n, len(raw))
	}
	if out.SessionID != in.SessionID {
		t.Fatalf("sid mismatch")
	}
	if out.Seq != in.Seq {
		t.Fatalf("seq=%d want %d", out.Seq, in.Seq)
	}
	if out.Flags != 0 {
		t.Fatalf("flags=%d want 0", out.Flags)
	}
	if out.Target != "" {
		t.Fatalf("target=%q want empty", out.Target)
	}
	if !bytes.Equal(out.Payload, in.Payload) {
		t.Fatalf("payload mismatch: %q vs %q", out.Payload, in.Payload)
	}
}

func TestFrameRoundTrip_SYN(t *testing.T) {
	in := &Frame{
		SessionID: sid(0x01),
		Seq:       0,
		Flags:     FlagSYN,
		Target:    "example.com:443",
		Payload:   []byte("GET / HTTP/1.1\r\n"),
	}
	raw, err := in.Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	out, _, err := Unmarshal(raw)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !out.HasFlag(FlagSYN) {
		t.Fatal("SYN flag lost")
	}
	if out.Target != in.Target {
		t.Fatalf("target=%q want %q", out.Target, in.Target)
	}
	if !bytes.Equal(out.Payload, in.Payload) {
		t.Fatal("payload mismatch")
	}
}

func TestFrameRoundTrip_FIN_NoPayload(t *testing.T) {
	in := &Frame{SessionID: sid(0x55), Seq: 99, Flags: FlagFIN}
	raw, err := in.Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	out, _, err := Unmarshal(raw)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !out.HasFlag(FlagFIN) {
		t.Fatal("FIN flag lost")
	}
	if len(out.Payload) != 0 {
		t.Fatalf("payload should be empty, got %d bytes", len(out.Payload))
	}
}

func TestFrameRoundTrip_ACK(t *testing.T) {
	in := &Frame{SessionID: sid(0x77), Seq: 7, Flags: FlagACK}
	raw, err := in.Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	out, _, err := Unmarshal(raw)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !out.HasFlag(FlagACK) {
		t.Fatal("ACK flag lost")
	}
}

func TestAppendMarshalMatchesMarshalAndReusesDestination(t *testing.T) {
	in := &Frame{
		SessionID: sid(0x33),
		Seq:       123,
		Flags:     FlagSYN,
		Target:    "example.org:443",
		Payload:   []byte("payload"),
	}
	prefix := []byte("prefix:")
	dst := make([]byte, len(prefix), 128)
	copy(dst, prefix)

	got, err := in.AppendMarshal(dst)
	if err != nil {
		t.Fatalf("append marshal: %v", err)
	}
	wantFrame, err := in.Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !bytes.Equal(got[:len(prefix)], prefix) {
		t.Fatalf("prefix changed: %q", got[:len(prefix)])
	}
	if !bytes.Equal(got[len(prefix):], wantFrame) {
		t.Fatalf("appended frame mismatch")
	}
	if cap(got) != cap(dst) {
		t.Fatalf("AppendMarshal allocated despite sufficient destination capacity")
	}
}

func TestUnmarshal_ShortHeader(t *testing.T) {
	if _, _, err := Unmarshal([]byte{1, 2, 3}); err == nil {
		t.Fatal("expected error on short header")
	}
}

func TestUnmarshal_TargetTooLongRejectedAtMarshal(t *testing.T) {
	in := &Frame{SessionID: sid(1), Target: string(make([]byte, 256))}
	if _, err := in.Marshal(); err == nil {
		t.Fatal("expected error on oversized target")
	}
}

func benchMarshalBatch(b *testing.B, n int) []*Frame {
	b.Helper()
	pl := bytes.Repeat([]byte{'p'}, 4*1024)
	out := make([]*Frame, n)
	for i := range out {
		out[i] = &Frame{SessionID: sid(byte(i)), Seq: uint64(i), Payload: pl}
	}
	return out
}

func BenchmarkEncodeBatch_64Frames(b *testing.B) {
	c, err := NewCryptoFromHexKey(testKeyHex)
	if err != nil {
		b.Fatalf("crypto: %v", err)
	}
	in := benchMarshalBatch(b, 64)
	var benchClient [ClientIDLen]byte
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := EncodeBatch(c, benchClient, in); err != nil {
			b.Fatalf("encode: %v", err)
		}
	}
}

func BenchmarkDecodeBatch_64Frames(b *testing.B) {
	c, err := NewCryptoFromHexKey(testKeyHex)
	if err != nil {
		b.Fatalf("crypto: %v", err)
	}
	in := benchMarshalBatch(b, 64)
	var benchClient [ClientIDLen]byte
	body, err := EncodeBatch(c, benchClient, in)
	if err != nil {
		b.Fatalf("encode: %v", err)
	}
	b.SetBytes(int64(len(body)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, err := DecodeBatch(c, body); err != nil {
			b.Fatalf("decode: %v", err)
		}
	}
}
