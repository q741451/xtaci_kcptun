package main

import (
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtaci/kcptun/udprelay"
	"github.com/xtaci/smux"
)

// udpFlow carries one local UDP source's traffic over a dedicated smux
// stream. The "local source" here is one of ss-local's own per-target
// outbound sockets -- ss-local opens a fresh one per local application
// flow and always talks to whatever address its config points at, which
// for --udprelay is this process's local listener. Everything above the
// framing is opaque shadowsocks ciphertext to us.
type udpFlow struct {
	stream     *smux.Stream
	conn       *net.UDPConn // shared local listener, used to write replies back
	remote     *net.UDPAddr // the ss-local socket this flow serves
	sendCh     chan []byte
	lastActive int64 // unix nano, atomic
	die        chan struct{}
	dieOnce    sync.Once
}

func newUDPFlow(stream *smux.Stream, conn *net.UDPConn, remote *net.UDPAddr, config *Config) *udpFlow {
	f := &udpFlow{
		stream: stream,
		conn:   conn,
		remote: remote,
		sendCh: make(chan []byte, config.UDPSendQ),
		die:    make(chan struct{}),
	}
	f.touch()
	go f.writeLoop()
	go f.readLoop()
	return f
}

func (f *udpFlow) touch() {
	atomic.StoreInt64(&f.lastActive, time.Now().UnixNano())
}

func (f *udpFlow) idleFor() time.Duration {
	return time.Since(time.Unix(0, atomic.LoadInt64(&f.lastActive)))
}

func (f *udpFlow) dead() bool {
	select {
	case <-f.die:
		return true
	default:
		return false
	}
}

// enqueue tail-drops the incoming datagram if this flow's send queue is
// already full: a full queue means the tunnel is behind, and dropping a
// fresh packet is cheaper than queueing it behind others and adding
// latency for everything that follows.
func (f *udpFlow) enqueue(pkt []byte) {
	select {
	case f.sendCh <- pkt:
	default:
	}
}

func (f *udpFlow) writeLoop() {
	for {
		select {
		case pkt := <-f.sendCh:
			if err := udprelay.WriteRecord(f.stream, pkt); err != nil {
				f.close()
				return
			}
		case <-f.die:
			return
		}
	}
}

func (f *udpFlow) readLoop() {
	for {
		payload, err := udprelay.ReadRecord(f.stream)
		if err != nil {
			f.close()
			return
		}
		f.touch()
		if _, err := f.conn.WriteToUDP(payload, f.remote); err != nil {
			f.close()
			return
		}
	}
}

func (f *udpFlow) close() {
	f.dieOnce.Do(func() {
		close(f.die)
		f.stream.Close()
	})
}

// runUDPRelayClient listens for a shadowsocks-libev UDP relay's traffic on
// config.LocalAddr and forwards each distinct source address over its own
// dedicated smux stream, obtained from getSession -- the same round-robin
// session pool main() otherwise uses for TCP forwarding. It blocks until
// the local listener errors out.
func runUDPRelayClient(config *Config, getSession func() *smux.Session) error {
	laddr, err := net.ResolveUDPAddr("udp", config.LocalAddr)
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		return err
	}
	log.Println("udprelay listening on:", conn.LocalAddr())

	var mu sync.Mutex
	flows := make(map[string]*udpFlow)

	go func() {
		idleTTL := time.Duration(config.UDPIdle) * time.Second
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for range ticker.C {
			mu.Lock()
			for k, f := range flows {
				if f.dead() || f.idleFor() > idleTTL {
					f.close()
					delete(flows, k)
					if !config.Quiet {
						log.Println("udp flow closed:", k)
					}
				}
			}
			mu.Unlock()
		}
	}()

	buf := make([]byte, 65536)
	for {
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			return err
		}

		key := addr.String()
		mu.Lock()
		f, ok := flows[key]
		if ok && f.dead() {
			ok = false
		}
		if !ok {
			sess := getSession()
			stream, err := sess.OpenStream()
			if err != nil {
				mu.Unlock()
				log.Println("udprelay OpenStream:", err)
				continue
			}
			f = newUDPFlow(stream, conn, addr, config)
			flows[key] = f
			if !config.Quiet {
				log.Println("udp flow opened:", key)
			}
		}
		mu.Unlock()

		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		f.touch()
		f.enqueue(pkt)
	}
}
