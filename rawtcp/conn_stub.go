// +build !linux

package rawtcp

import (
	"errors"
	"net"
)

var errNotSupported = errors.New("rawtcp: not supported on this platform (linux only)")

// Conn satisfies net.PacketConn on non-Linux platforms so this package
// still links, but Dial/Listen always fail: the technique needs raw IP
// sockets and iptables, which are Linux-specific.
type Conn struct{ net.PacketConn }

// Dial always fails on non-Linux platforms.
func Dial(network, address string) (*Conn, error) {
	return nil, errNotSupported
}

// Listen always fails on non-Linux platforms.
func Listen(network, address string) (*Conn, error) {
	return nil, errNotSupported
}

// Cleanup is a no-op on non-Linux platforms.
func Cleanup() {}
