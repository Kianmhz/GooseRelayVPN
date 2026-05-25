// sink is the bench harness's upstream target. It exposes four TCP modes,
// one per port, so scenarios can pick the behaviour that isolates what they
// measure:
//
//	:9101 echo     -> write back what was read (TTFB / round-trip)
//	:9102 sized    -> read 8-byte length N, drain N bytes, ACK 1 byte (upload throughput)
//	:9103 sizedSrc -> read 8-byte length N, write N zero bytes, close  (download throughput)
//	:9104 quick    -> accept, write 1 byte, close                      (connection-setup churn)
//
// One process owns all four ports so the harness only manages a single child.
//
// The :9102 / :9103 length-prefix protocols exist because relay-tunnel's
// VirtualConn does not implement CloseWrite, and the SOCKS lib's bidirectional
// copy doesn't propagate half-close back to the session. Without an explicit
// length, the sink would either never know the upload finished (port 9102) or
// keep streaming forever after the harness lost interest (port 9103). The
// length-prefix lets each side terminate cleanly the moment its work is done.
package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"
)

const (
	portEcho   = 9101
	portSized  = 9102
	portSource = 9103
	portQuick  = 9104

	sourceChunkSize = 64 * 1024
)

func main() {
	log.SetFlags(0)

	listeners := []struct {
		port    int
		handler func(net.Conn)
		name    string
	}{
		{portEcho, handleEcho, "echo"},
		{portSized, handleSized, "sized"},
		{portSource, handleSizedSource, "source"},
		{portQuick, handleQuick, "quick"},
	}

	var wg sync.WaitGroup
	for _, l := range listeners {
		ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", l.port))
		if err != nil {
			log.Fatalf("[sink] listen %s on :%d: %v", l.name, l.port, err)
		}
		log.Printf("[sink] %-7s ready on %s", l.name, ln.Addr())
		wg.Add(1)
		go func(ln net.Listener, h func(net.Conn), name string) {
			defer wg.Done()
			serve(ln, h, name)
		}(ln, l.handler, l.name)
	}

	// Print readiness sentinel last so the harness can wait on a single line.
	fmt.Fprintln(os.Stderr, "SINK_READY")
	wg.Wait()
}

func serve(ln net.Listener, handler func(net.Conn), name string) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			log.Printf("[sink] %s accept: %v", name, err)
			continue
		}
		go func(c net.Conn) {
			defer c.Close()
			handler(c)
		}(conn)
	}
}

func handleEcho(c net.Conn) {
	_, _ = io.Copy(c, c)
}

func handleSized(c net.Conn) {
	var hdr [8]byte
	if _, err := io.ReadFull(c, hdr[:]); err != nil {
		return
	}
	n := int64(binary.BigEndian.Uint64(hdr[:]))
	if n < 0 {
		return
	}
	if _, err := io.CopyN(io.Discard, c, n); err != nil {
		return
	}
	_, _ = c.Write([]byte{'k'})
}

func handleSizedSource(c net.Conn) {
	var hdr [8]byte
	if _, err := io.ReadFull(c, hdr[:]); err != nil {
		return
	}
	n := int64(binary.BigEndian.Uint64(hdr[:]))
	if n < 0 {
		return
	}
	buf := make([]byte, sourceChunkSize)
	remaining := n
	for remaining > 0 {
		chunk := int64(len(buf))
		if chunk > remaining {
			chunk = remaining
		}
		if _, err := c.Write(buf[:chunk]); err != nil {
			return
		}
		remaining -= chunk
	}
}

func handleQuick(c net.Conn) {
	_, _ = c.Write([]byte{'k'})
}
