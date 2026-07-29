// Package rawtcp implements a packet-oriented net.PacketConn over a raw TCP
// socket, so that kcp-go (which expects a PacketConn) can run its protocol
// framed inside what looks like an ordinary TCP stream on the wire.
//
// This is the same technique used by github.com/xtaci/tcpraw (kcptun's
// upstream "-tcp" flag, added 2019-06/09, still unchanged in principle as of
// 2024): complete a real TCP handshake through the kernel so the connection
// looks legitimate to any middlebox, then set that socket's outgoing TTL to
// 1 so the kernel's own automatic packets (retransmits, ACKs, keepalives)
// die one hop out and never reach the peer, and hand-craft the actual data
// segments on a parallel raw IP socket with our own sequence/ack tracking
// (via google/gopacket). Because the kernel still thinks the connection is
// alive, it won't reset it; because its own packets never arrive, they can't
// desync with our hand-rolled stream.
//
// # iptables/ip6tables: this package's one external requirement
//
// The kernel doesn't know this connection is being intercepted, so on any
// inbound raw segment that our TTL=1 trick doesn't cover -- notably the
// kernel's own periodic ACKs on the "real" socket -- it may still try to
// reply, and that reply needs to be kept off the wire too. An
// iptables/ip6tables OUTPUT rule matching TTL=1 (hop-limit=1 for IPv6)
// packets does that.
//
// This package deliberately does NOT install or remove that rule itself --
// Dial and Listen assume it is already in place, and take no action to
// remove it on Close/Cleanup. Managing it is left entirely to the deployer
// (e.g. an OpenWrt procd/init script that already owns the firewall
// lifecycle), which avoids this package needing os/exec, needing to shell
// out to iptables at all, or caring whether the target is iptables-legacy,
// iptables-nft, or (once such a script is written for it) plain nftables.
//
// The rule to install before calling Dial(network, addr) -- or Listen for
// the server side -- and remove afterward:
//
//	# client: addr is the kcptun server, e.g. "vps.example.com:29900"
//	iptables  -A OUTPUT -m ttl --ttl-eq 1 -p tcp -d <server-ip> --dport <server-port> -j DROP
//	ip6tables -A OUTPUT -m hl  --hl-eq  1 -p tcp -d <server-ip> --dport <server-port> -j DROP
//
//	# server: addr is the kcptun listen address, e.g. ":29900"
//	iptables  -A OUTPUT -m ttl --ttl-eq 1 -p tcp --sport <listen-port> -j DROP
//	ip6tables -A OUTPUT -m hl  --hl-eq  1 -p tcp --sport <listen-port> -j DROP
//
// The client rule intentionally matches only on destination, not on the
// local (ephemeral, freshly chosen by the kernel on every Dial) source
// port: since nothing else on the host has any legitimate reason to send a
// TTL=1 packet to that specific server address, matching by destination
// alone is sufficient, and -- unlike the source port -- it's a value the
// deployer already knows ahead of time (it's the same address passed to
// kcptun's own -r/--remoteaddr flag), so the rule can be installed
// statically before the process ever starts, no coordination needed. The
// server rule was always static this way, since it matches its own fixed
// listen port.
//
// Linux only: it needs a raw IP socket (CAP_NET_RAW), which in practice
// means running as root. On any other GOOS, Dial and Listen return an
// error and Cleanup is a no-op, so the package still links into
// cross-compiled non-Linux binaries.
package rawtcp
