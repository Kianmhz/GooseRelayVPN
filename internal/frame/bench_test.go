package frame

import (
	"bytes"
	"testing"
)

var (
	benchFrameBytes  []byte
	benchFrameResult *Frame
	benchFrames      []*Frame
)

func BenchmarkFrameAppendMarshal_4KiB(b *testing.B) {
	in := &Frame{
		SessionID: sid(0x42),
		Seq:       12345,
		Flags:     FlagSYN,
		Target:    "example.com:443",
		Payload:   bytes.Repeat([]byte{'p'}, 4*1024),
	}
	dst := make([]byte, 0, in.EncodedLen())
	b.SetBytes(int64(in.EncodedLen()))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dst = dst[:0]
		out, err := in.AppendMarshal(dst)
		if err != nil {
			b.Fatalf("append marshal: %v", err)
		}
		benchFrameBytes = out
	}
}

func BenchmarkFrameUnmarshal_4KiB(b *testing.B) {
	in := &Frame{
		SessionID: sid(0x43),
		Seq:       12345,
		Flags:     FlagSYN,
		Target:    "example.com:443",
		Payload:   bytes.Repeat([]byte{'p'}, 4*1024),
	}
	raw, err := in.Marshal()
	if err != nil {
		b.Fatalf("marshal: %v", err)
	}
	b.SetBytes(int64(len(raw)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		out, _, err := Unmarshal(raw)
		if err != nil {
			b.Fatalf("unmarshal: %v", err)
		}
		benchFrameResult = out
	}
}

func BenchmarkEncodeBatchBinary_64Frames(b *testing.B) {
	c, err := NewCryptoFromHexKey(testKeyHex)
	if err != nil {
		b.Fatalf("crypto: %v", err)
	}
	in := benchMarshalBatch(b, 64)
	var benchClient [ClientIDLen]byte
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		out, err := EncodeBatchBinary(c, benchClient, in)
		if err != nil {
			b.Fatalf("encode binary: %v", err)
		}
		benchFrameBytes = out
	}
}

func BenchmarkDecodeBatchBinary_64Frames(b *testing.B) {
	c, err := NewCryptoFromHexKey(testKeyHex)
	if err != nil {
		b.Fatalf("crypto: %v", err)
	}
	in := benchMarshalBatch(b, 64)
	var benchClient [ClientIDLen]byte
	body, err := EncodeBatchBinary(c, benchClient, in)
	if err != nil {
		b.Fatalf("encode binary: %v", err)
	}
	b.SetBytes(int64(len(body)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, out, err := DecodeBatchBinary(c, body)
		if err != nil {
			b.Fatalf("decode binary: %v", err)
		}
		benchFrames = out
	}
}
