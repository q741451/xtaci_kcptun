package main

import (
	"github.com/pkg/errors"
	kcp "github.com/xtaci/kcp-go"
	"github.com/xtaci/kcptun/rawtcp"
)

// dial connects to config.RemoteAddr, either as plain KCP-over-UDP or,
// when config.TCP is set, KCP framed inside an emulated TCP connection (see
// package rawtcp). Requires root/CAP_NET_RAW+CAP_NET_ADMIN and Linux.
func dial(config *Config, block kcp.BlockCrypt) (*kcp.UDPSession, error) {
	if config.TCP {
		conn, err := rawtcp.Dial("tcp", config.RemoteAddr)
		if err != nil {
			return nil, errors.Wrap(err, "rawtcp.Dial()")
		}
		return kcp.NewConn(config.RemoteAddr, block, config.DataShard, config.ParityShard, conn)
	}
	return kcp.DialWithOptions(config.RemoteAddr, block, config.DataShard, config.ParityShard)
}
