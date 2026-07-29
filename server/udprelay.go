package main

import (
	"io"
	"log"
	"net"
	"sync"
	"time"

	"github.com/xtaci/kcptun/udprelay"
	"github.com/xtaci/smux"
)

// handleMuxUDP is the UDP-relay counterpart of handleMux: every stream
// accepted on this session carries one client-side UDP flow (see
// client/udprelay.go's udpFlow), framed with udprelay.WriteRecord/
// ReadRecord instead of being copied as a raw byte stream.
func handleMuxUDP(conn io.ReadWriteCloser, config *Config) {
	smuxConfig := smux.DefaultConfig()
	smuxConfig.MaxReceiveBuffer = config.SmuxBuf
	smuxConfig.KeepAliveInterval = time.Duration(config.KeepAlive) * time.Second

	mux, err := smux.Server(conn, smuxConfig)
	if err != nil {
		log.Println(err)
		return
	}
	defer mux.Close()
	for {
		stream, err := mux.AcceptStream()
		if err != nil {
			log.Println(err)
			return
		}
		go handleClientUDP(stream, config)
	}
}

// handleClientUDP owns exactly one outbound UDP socket toward the real
// shadowsocks-libev server (config.Target) for the lifetime of one stream.
func handleClientUDP(stream *smux.Stream, config *Config) {
	if !config.Quiet {
		log.Println("udp stream opened")
		defer log.Println("udp stream closed")
	}
	defer stream.Close()

	raddr, err := net.ResolveUDPAddr("udp", config.Target)
	if err != nil {
		log.Println("udprelay ResolveUDPAddr:", err)
		return
	}
	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		log.Println("udprelay DialUDP:", err)
		return
	}
	defer conn.Close()

	die := make(chan struct{})
	var once sync.Once
	closeDie := func() { once.Do(func() { close(die) }) }

	// stream -> real shadowsocks-libev server
	go func() {
		defer closeDie()
		for {
			payload, err := udprelay.ReadRecord(stream)
			if err != nil {
				return
			}
			if _, err := conn.Write(payload); err != nil {
				return
			}
		}
	}()

	// real shadowsocks-libev server -> stream
	go func() {
		defer closeDie()
		buf := make([]byte, 65536)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				return
			}
			if err := udprelay.WriteRecord(stream, buf[:n]); err != nil {
				return
			}
		}
	}()

	<-die
}
