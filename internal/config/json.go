package config

import "bytes"

var utf8BOM = []byte{0xef, 0xbb, 0xbf}

func stripUTF8BOM(b []byte) []byte {
	return bytes.TrimPrefix(b, utf8BOM)
}
