// Package rawtcp implements a packet-oriented net.PacketConn over a raw TCP
// socket: a real TCP handshake for cover, TTL=1 to silence the kernel's own
// ACKs on that socket, and hand-crafted segments (via gopacket) on a raw IP
// socket for the actual data. Linux only.
//
// This package does not touch the firewall itself. Dial/Listen tag the
// real socket with a fwmark (SO_MARK, mark param; kcptun exposes it as
// --tcpmark, default DefaultMark) so a rule can drop the kernel's spurious
// ACKs before they leave the host. Install it before calling Dial/Listen,
// remove it when done:
//
//	iptables -A OUTPUT -m mark --mark 0x6b6370 -j DROP
//	nft insert rule inet fw4 output meta mark 0x006b6370 counter drop
//
// mark == 0 skips SO_MARK.
package rawtcp

// DefaultMark is the fwmark applied to rawtcp's underlying kernel socket
// when the caller doesn't specify one. Arbitrary; pick a different value
// (--tcpmark) if this collides with an existing fwmark scheme.
const DefaultMark = 0x6b6370
