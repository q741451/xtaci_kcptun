// Command udptun_server is the far end of udptun_client: it forwards relayed
// datagrams to the real shadowsocks-libev server and sends its replies back.
// See ../udptun for why this carries no reliability of its own.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"sync"

	"github.com/xtaci/kcptun/rawtcp"
	"github.com/xtaci/kcptun/udptun"
)

// VERSION is injected by buildflags
var VERSION = "SELFBUILD"

type config struct {
	Listen  string `json:"listen"`
	Target  string `json:"target"`
	Key     string `json:"key"`
	Crypt   string `json:"crypt"`
	MTU     int    `json:"mtu"`
	SockBuf int    `json:"sockbuf"`
	Idle    int    `json:"idle"`
	TCP     bool   `json:"tcp"`
	TCPMark int    `json:"tcpmark"`
	Log     string `json:"log"`
	Quiet   bool   `json:"quiet"`
}

func main() {
	var c config
	var confFile string
	var showVersion bool

	flag.StringVar(&c.Listen, "l", ":29900", "udptun server listen address")
	flag.StringVar(&c.Target, "t", "127.0.0.1:12948", "the real shadowsocks-libev server's UDP address")
	flag.StringVar(&c.Key, "key", "it's a secrect", "pre-shared secret between client and server [$KCPTUN_KEY]")
	flag.StringVar(&c.Crypt, "crypt", "aes", udptun.CryptList)
	flag.IntVar(&c.MTU, "mtu", 1350, "largest packet on the wire, header included; bigger datagrams are dropped")
	flag.IntVar(&c.SockBuf, "sockbuf", 4194304, "per-socket buffer in bytes")
	flag.IntVar(&c.Idle, "idle", 60, "seconds a flow can sit idle before it is dropped")
	flag.BoolVar(&c.TCP, "tcp", false, "also accept a TCP-disguised transport alongside UDP (linux only, root; see rawtcp/doc.go)")
	flag.IntVar(&c.TCPMark, "tcpmark", rawtcp.DefaultMark, "fwmark for -tcp's firewall rule (SO_MARK); 0 disables marking")
	flag.StringVar(&c.Log, "log", "", "specify a log file to output, default goes to stderr")
	flag.BoolVar(&c.Quiet, "quiet", false, "suppress the per-flow open/close messages")
	flag.StringVar(&confFile, "c", "", "config from json file, which will override the command from shell")
	flag.BoolVar(&showVersion, "v", false, "print the version")
	flag.Parse()

	if showVersion {
		fmt.Println("udptun_server", VERSION)
		return
	}
	if env := os.Getenv("KCPTUN_KEY"); env != "" && c.Key == "it's a secrect" {
		c.Key = env
	}
	if confFile != "" {
		checkError(parseJSONConfig(&c, confFile))
	}
	if c.Log != "" {
		f, err := os.OpenFile(c.Log, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0644)
		checkError(err)
		defer f.Close()
		log.SetOutput(f)
	}

	log.Println("version:", VERSION)
	block, err := udptun.NewBlockCrypt(c.Crypt, c.Key)
	checkError(err)

	log.Println("target:", c.Target)
	log.Println("encryption:", c.Crypt)
	log.Println("mtu:", c.MTU, "payload limit:", c.MTU-udptun.HeaderSize)
	log.Println("sockbuf:", c.SockBuf)
	log.Println("idle:", c.Idle)
	log.Println("tcp:", c.TCP)
	if c.TCP {
		log.Printf("tcpmark: 0x%x", c.TCPMark)
	}

	var wg sync.WaitGroup
	serve := func(conn net.PacketConn, what string) {
		defer wg.Done()
		log.Println("serving:", what, conn.LocalAddr())
		log.Println(udptun.RunServer(udptun.ServerConfig{
			Conn:      conn,
			Target:    c.Target,
			Block:     block,
			MaxPacket: c.MTU,
			SockBuf:   c.SockBuf,
			Idle:      c.Idle,
			Quiet:     c.Quiet,
		}))
	}

	udpConn, err := net.ListenPacket("udp", c.Listen)
	checkError(err)
	wg.Add(1)
	go serve(udpConn, "udp")

	if c.TCP {
		conn, err := rawtcp.Listen("tcp", c.Listen, c.TCPMark)
		if err != nil {
			log.Println("rawtcp.Listen():", err)
		} else {
			wg.Add(1)
			go serve(conn, "tcp")
		}
	}

	wg.Wait()
}

func parseJSONConfig(c *config, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return json.NewDecoder(f).Decode(c)
}

func checkError(err error) {
	if err != nil {
		log.Printf("%+v\n", err)
		os.Exit(-1)
	}
}
