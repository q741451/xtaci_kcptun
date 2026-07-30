package main

import (
	"net"

	"github.com/xtaci/kcptun/rawtcp"
)

// dial returns the packet transport toward the server: a plain UDP socket, or
// rawtcp's TCP-disguised one. Both are net.PacketConn, so nothing above here
// has to care which.
func dial(c *config) (net.PacketConn, net.Addr, error) {
	if c.TCP {
		conn, err := rawtcp.Dial("tcp", c.RemoteAddr, c.TCPMark)
		if err != nil {
			return nil, nil, err
		}
		// rawtcp keys flows by address string; use the form it dialed with.
		raddr, err := net.ResolveTCPAddr("tcp", c.RemoteAddr)
		if err != nil {
			conn.Close()
			return nil, nil, err
		}
		return conn, raddr, nil
	}

	raddr, err := net.ResolveUDPAddr("udp", c.RemoteAddr)
	if err != nil {
		return nil, nil, err
	}
	network := "udp4"
	if raddr.IP.To4() == nil {
		network = "udp"
	}
	conn, err := net.ListenUDP(network, nil)
	if err != nil {
		return nil, nil, err
	}
	return conn, raddr, nil
}
