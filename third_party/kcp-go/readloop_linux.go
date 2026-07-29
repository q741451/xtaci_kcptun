// +build linux

package kcp

import (
	"net"
	"sync/atomic"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

const (
	// ReadBatch() message size
	batchSize = 16
)

// the read loop for a client session
//
// PATCHED from the real v5.2.8 release: the batched ipv4/ipv6 path below
// unconditionally wraps s.conn in golang.org/x/net's ipv4.NewPacketConn,
// which does an unchecked `.(net.Conn)` type assertion internally and
// panics for any net.PacketConn that isn't backed by a real OS socket type
// (*net.TCPConn/*net.UDPConn/*net.IPConn) -- e.g. kcptun's rawtcp.Conn. Add
// the *net.UDPConn guard that upstream itself added in v5.4.x, falling back
// to a plain ReadFrom loop for anything else. This is the only functional
// change in this file; everything else is byte-identical to v5.2.8.
func (s *UDPSession) readLoop() {
	if _, ok := s.conn.(*net.UDPConn); !ok {
		s.readLoopGeneric()
		return
	}
	addr, _ := net.ResolveUDPAddr("udp", s.conn.LocalAddr().String())
	if addr.IP.To4() != nil {
		s.readLoopIPv4()
	} else {
		s.readLoopIPv6()
	}
}

// readLoopGeneric is the non-batched fallback for any net.PacketConn that
// isn't a real *net.UDPConn (identical to the !linux build's readLoop in
// readloop_generic.go, just under a different name so it can coexist with
// the linux-specific functions above in the same build).
func (s *UDPSession) readLoopGeneric() {
	buf := make([]byte, mtuLimit)
	var src string
	for {
		if n, addr, err := s.conn.ReadFrom(buf); err == nil {
			if src == "" {
				src = addr.String()
			} else if addr.String() != src {
				atomic.AddUint64(&DefaultSnmp.InErrs, 1)
				continue
			}
			if n >= s.headerSize+IKCP_OVERHEAD {
				s.packetInput(buf[:n])
			} else {
				atomic.AddUint64(&DefaultSnmp.InErrs, 1)
			}
		} else {
			s.chReadError <- err
			return
		}
	}
}

func (s *UDPSession) readLoopIPv6() {
	var src string
	msgs := make([]ipv6.Message, batchSize)
	for k := range msgs {
		msgs[k].Buffers = [][]byte{make([]byte, mtuLimit)}
	}

	conn := ipv6.NewPacketConn(s.conn)

	for {
		if count, err := conn.ReadBatch(msgs, 0); err == nil {
			for i := 0; i < count; i++ {
				msg := &msgs[i]
				// make sure the packet is from the same source
				if src == "" { // set source address if nil
					src = msg.Addr.String()
				} else if msg.Addr.String() != src {
					atomic.AddUint64(&DefaultSnmp.InErrs, 1)
					continue
				}

				if msg.N < s.headerSize+IKCP_OVERHEAD {
					atomic.AddUint64(&DefaultSnmp.InErrs, 1)
					continue
				}

				// source and size has validated
				s.packetInput(msg.Buffers[0][:msg.N])
			}
		} else {
			s.chReadError <- err
			return
		}
	}
}

func (s *UDPSession) readLoopIPv4() {
	var src string
	msgs := make([]ipv4.Message, batchSize)
	for k := range msgs {
		msgs[k].Buffers = [][]byte{make([]byte, mtuLimit)}
	}

	conn := ipv4.NewPacketConn(s.conn)
	for {
		if count, err := conn.ReadBatch(msgs, 0); err == nil {
			for i := 0; i < count; i++ {
				msg := &msgs[i]
				// make sure the packet is from the same source
				if src == "" { // set source address if nil
					src = msg.Addr.String()
				} else if msg.Addr.String() != src {
					atomic.AddUint64(&DefaultSnmp.InErrs, 1)
					continue
				}

				if msg.N < s.headerSize+IKCP_OVERHEAD {
					atomic.AddUint64(&DefaultSnmp.InErrs, 1)
					continue
				}

				// source and size has validated
				s.packetInput(msg.Buffers[0][:msg.N])
			}
		} else {
			s.chReadError <- err
			return
		}
	}
}

// monitor incoming data for all connections of server
//
// PATCHED: same *net.UDPConn guard as readLoop above, and for the same
// reason -- see the comment there.
func (l *Listener) monitor() {
	if _, ok := l.conn.(*net.UDPConn); !ok {
		l.monitorGeneric()
		return
	}
	addr, _ := net.ResolveUDPAddr("udp", l.conn.LocalAddr().String())
	if addr.IP.To4() != nil {
		l.monitorIPv4()
	} else {
		l.monitorIPv6()
	}
}

// monitorGeneric is the non-batched fallback, identical to the !linux
// build's monitor in readloop_generic.go.
func (l *Listener) monitorGeneric() {
	buf := make([]byte, mtuLimit)
	for {
		if n, from, err := l.conn.ReadFrom(buf); err == nil {
			if n >= l.headerSize+IKCP_OVERHEAD {
				l.packetInput(buf[:n], from)
			} else {
				atomic.AddUint64(&DefaultSnmp.InErrs, 1)
			}
		} else {
			return
		}
	}
}

func (l *Listener) monitorIPv4() {
	msgs := make([]ipv4.Message, batchSize)
	for k := range msgs {
		msgs[k].Buffers = [][]byte{make([]byte, mtuLimit)}
	}

	conn := ipv4.NewPacketConn(l.conn)
	for {
		if count, err := conn.ReadBatch(msgs, 0); err == nil {
			for i := 0; i < count; i++ {
				msg := &msgs[i]
				if msg.N >= l.headerSize+IKCP_OVERHEAD {
					l.packetInput(msg.Buffers[0][:msg.N], msg.Addr)
				} else {
					atomic.AddUint64(&DefaultSnmp.InErrs, 1)
				}
			}
		} else {
			return
		}
	}
}

func (l *Listener) monitorIPv6() {
	msgs := make([]ipv6.Message, batchSize)
	for k := range msgs {
		msgs[k].Buffers = [][]byte{make([]byte, mtuLimit)}
	}

	conn := ipv4.NewPacketConn(l.conn)
	for {
		if count, err := conn.ReadBatch(msgs, 0); err == nil {
			for i := 0; i < count; i++ {
				msg := &msgs[i]
				if msg.N >= l.headerSize+IKCP_OVERHEAD {
					l.packetInput(msg.Buffers[0][:msg.N], msg.Addr)
				} else {
					atomic.AddUint64(&DefaultSnmp.InErrs, 1)
				}
			}
		} else {
			return
		}
	}
}
