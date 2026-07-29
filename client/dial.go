package main

import (
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
