package main

import (
	"net"

	"github.com/pkg/errors"
	kcp "github.com/xtaci/kcp-go"
	"github.com/xtaci/kcptun/rawtcp"
)

// dial connects over plain UDP, or, if config.TCP is set, via package rawtcp.
func dial(config *Config, block kcp.BlockCrypt) (*kcp.UDPSession, error) {
	if config.TCP {
		conn, err := rawtcp.Dial("tcp", config.RemoteAddr, config.TCPMark)
		if err != nil {
			return nil, errors.Wrap(err, "rawtcp.Dial()")
		}
		return kcp.NewConn(config.RemoteAddr, block, config.DataShard, config.ParityShard, conn)
	}
	return kcp.DialWithOptions(config.RemoteAddr, block, config.DataShard, config.ParityShard)
}

// dialPacket is dial's counterpart for --udprelay, which wants the packet
// transport itself rather than a KCP session over it. rawtcp.Conn is already a
// net.PacketConn, so the two cases differ only in which one comes back.
func dialPacket(config *Config) (net.PacketConn, net.Addr, error) {
	if config.TCP {
		conn, err := rawtcp.Dial("tcp", config.RemoteAddr, config.TCPMark)
		if err != nil {
			return nil, nil, errors.Wrap(err, "rawtcp.Dial()")
		}
		// rawtcp keys flows by address string; use the form it dialed with.
		raddr, err := net.ResolveTCPAddr("tcp", config.RemoteAddr)
		if err != nil {
			conn.Close()
			return nil, nil, err
		}
		return conn, raddr, nil
	}

	raddr, err := net.ResolveUDPAddr("udp", config.RemoteAddr)
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
