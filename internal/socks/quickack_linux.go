//go:build linux

package socks

import (
	"net"
	"syscall"
)

// setQuickAck disables Linux's TCP delayed-ACK behavior on c. Without this,
// the kernel can hold back an ACK for up to 40 ms hoping to piggyback it on
// a forthcoming data segment — fine for bulk traffic but adds visible latency
// to small request/reply pairs (DNS-over-HTTPS, REST GETs, TLS handshakes).
//
// TCP_QUICKACK is a one-shot hint that the kernel resets after subsequent
// segments, so we re-apply it on each accept; the meaningful window is the
// first few RTTs of every connection, which is exactly when small interactive
// payloads dominate.
//
// No-ops cleanly on connections that aren't *net.TCPConn or where the
// SyscallConn / Setsockopt calls fail (CAP_NET_RAW restricted, kernel
// without TCP_QUICKACK, etc.).
func setQuickAck(c net.Conn) {
	tcp, ok := c.(*net.TCPConn)
	if !ok {
		return
	}
	raw, err := tcp.SyscallConn()
	if err != nil {
		return
	}
	_ = raw.Control(func(fd uintptr) {
		_ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_QUICKACK, 1)
	})
}
