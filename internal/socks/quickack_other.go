//go:build !linux

package socks

import "net"

// setQuickAck is a no-op on non-Linux platforms. TCP_QUICKACK is a Linux-only
// socket option; macOS/BSD lack the equivalent toggle, and Windows handles
// delayed-ACK via a registry-tunable global default rather than per-socket.
func setQuickAck(_ net.Conn) {}
