// Command udptun_client relays a shadowsocks-libev UDP relay's datagrams to a
// udptun_server. It is deliberately not part of the kcptun binaries: there is
// no KCP here, so none of their tuning applies, and keeping it separate leaves
// both command lines honest and both binaries small.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/xtaci/kcptun/rawtcp"
	"github.com/xtaci/kcptun/udptun"
)

// VERSION is injected by buildflags
var VERSION = "SELFBUILD"

type config struct {
	LocalAddr  string `json:"localaddr"`
	RemoteAddr string `json:"remoteaddr"`
	Key        string `json:"key"`
	Crypt      string `json:"crypt"`
	MTU        int    `json:"mtu"`
	SockBuf    int    `json:"sockbuf"`
	DSCP       int    `json:"dscp"`
	KeepAlive  int    `json:"keepalive"`
	Idle       int    `json:"idle"`
	TCP        bool   `json:"tcp"`
	TCPMark    int    `json:"tcpmark"`
	Log        string `json:"log"`
	Quiet      bool   `json:"quiet"`
}

func main() {
	var c config
	var confFile string
	var showVersion bool

	flag.StringVar(&c.LocalAddr, "l", ":12948", "local listen address, where ss-local's UDP relay points")
	flag.StringVar(&c.RemoteAddr, "r", "vps:29900", "udptun server address")
	flag.StringVar(&c.Key, "key", "it's a secrect", "pre-shared secret between client and server [$KCPTUN_KEY]")
	flag.StringVar(&c.Crypt, "crypt", "aes", udptun.CryptList)
	flag.IntVar(&c.MTU, "mtu", 1350, "largest packet on the wire, header included; bigger datagrams are dropped")
	flag.IntVar(&c.SockBuf, "sockbuf", 4194304, "per-socket buffer in bytes")
	flag.IntVar(&c.DSCP, "dscp", 0, "set DSCP(6bit)")
	flag.IntVar(&c.KeepAlive, "keepalive", 10, "seconds between heartbeats")
	flag.IntVar(&c.Idle, "idle", 60, "seconds a flow can sit idle before it is dropped")
	flag.BoolVar(&c.TCP, "tcp", false, "emulate a TCP connection (linux only, root; firewall rule required, see rawtcp/doc.go)")
	flag.IntVar(&c.TCPMark, "tcpmark", rawtcp.DefaultMark, "fwmark for -tcp's firewall rule (SO_MARK); 0 disables marking")
	flag.StringVar(&c.Log, "log", "", "specify a log file to output, default goes to stderr")
	flag.BoolVar(&c.Quiet, "quiet", false, "suppress the per-flow open/close messages")
	flag.StringVar(&confFile, "c", "", "config from json file, which will override the command from shell")
	flag.BoolVar(&showVersion, "v", false, "print the version")
	flag.Parse()

	if showVersion {
		fmt.Println("udptun_client", VERSION)
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

	conn, remote, err := dial(&c)
	checkError(err)

	log.Println("remote address:", remote)
	log.Println("encryption:", c.Crypt)
	log.Println("mtu:", c.MTU, "payload limit:", c.MTU-udptun.HeaderSize)
	log.Println("sockbuf:", c.SockBuf)
	log.Println("dscp:", c.DSCP)
	log.Println("keepalive:", c.KeepAlive)
	log.Println("idle:", c.Idle)
	log.Println("tcp:", c.TCP)
	if c.TCP {
		log.Printf("tcpmark: 0x%x", c.TCPMark)
	}

	checkError(udptun.RunClient(udptun.ClientConfig{
		LocalAddr: c.LocalAddr,
		Conn:      conn,
		Remote:    remote,
		Block:     block,
		MaxPacket: c.MTU,
		SockBuf:   c.SockBuf,
		DSCP:      c.DSCP,
		Idle:      c.Idle,
		KeepAlive: c.KeepAlive,
		Quiet:     c.Quiet,
	}))
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
