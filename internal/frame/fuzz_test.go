package frame

import "testing"

func FuzzUnmarshal(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0, 1, 2, 3})
	var id [SessionIDLen]byte
	seed := &Frame{SessionID: id, Seq: 7, Flags: FlagSYN, Target: "example.com:443", Payload: []byte("hello")}
	if b, err := seed.Marshal(); err == nil {
		f.Add(b)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _, _ = Unmarshal(data)
	})
}

func FuzzDecodeBatch(f *testing.F) {
	c := mustFuzzCrypto(f)
	f.Add([]byte{})
	f.Add([]byte("not-base64"))

	var clientID [ClientIDLen]byte
	clientID[0] = 1
	var sessionID [SessionIDLen]byte
	sessionID[0] = 2
	body, err := EncodeBatch(c, clientID, []*Frame{{
		SessionID: sessionID,
		Seq:       1,
		Flags:     FlagSYN,
		Target:    "example.com:443",
		Payload:   []byte("GET / HTTP/1.1\r\n"),
	}})
	if err != nil {
		f.Fatalf("EncodeBatch seed: %v", err)
	}
	f.Add(body)

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _, _ = DecodeBatch(c, data)
	})
}

func FuzzDecodeBatchBinary(f *testing.F) {
	c := mustFuzzCrypto(f)
	f.Add([]byte{})
	f.Add([]byte("not-a-sealed-envelope"))

	var clientID [ClientIDLen]byte
	clientID[0] = 3
	body, err := EncodeBatchBinary(c, clientID, nil)
	if err != nil {
		f.Fatalf("EncodeBatchBinary seed: %v", err)
	}
	f.Add(body)

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _, _ = DecodeBatchBinary(c, data)
	})
}

func mustFuzzCrypto(tb testing.TB) *Crypto {
	tb.Helper()
	c, err := NewCryptoFromHexKey("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	if err != nil {
		tb.Fatalf("NewCryptoFromHexKey: %v", err)
	}
	return c
}
