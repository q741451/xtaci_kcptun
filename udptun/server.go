package udptun

import (
	"log"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtaci/kcp-go/crypt"
)

// ServerConfig configures RunServer.
type ServerConfig struct {
	Conn      net.PacketConn // transport facing clients
	Target    string         // the real shadowsocks-libev server
	Block     crypt.BlockCrypt
	MaxPacket int  // largest packet on the wire, header included (--mtu)
	SockBuf   int  // --sockbuf
	Idle      int  // seconds before an unused flow is closed
	Quiet     bool // suppress per-flow logging
}

// serverFlow owns one socket toward Target per client flow -- the target
// answers whichever source port asked, so this is what attributes replies.
type serverFlow struct {
	conn       *net.UDPConn
	client     net.Addr
	id         uint32
	key        string
	lastActive int64 // unix nano, atomic
}

func (f *serverFlow) touch() { atomic.StoreInt64(&f.lastActive, time.Now().UnixNano()) }

func (f *serverFlow) idle() time.Duration {
	return time.Since(time.Unix(0, atomic.LoadInt64(&f.lastActive)))
}

type server struct {
	cfg    ServerConfig
	codec  *Codec
	target *net.UDPAddr

	mu    sync.Mutex
	flows map[string]*serverFlow

	die     chan struct{}
	dieOnce sync.Once
}

// RunServer relays datagrams between cfg.Conn and cfg.Target. It blocks until
// the transport fails.
func RunServer(cfg ServerConfig) error {
	target, err := net.ResolveUDPAddr("udp", cfg.Target)
	if err != nil {
		return err
	}
	codec, err := NewCodec(cfg.Block)
	if err != nil {
		return err
	}
	applySockBuf(cfg.Conn, cfg.SockBuf)

	s := &server{
		cfg:    cfg,
		codec:  codec,
		target: target,
		flows:  make(map[string]*serverFlow),
		die:    make(chan struct{}),
	}
	go s.reap()
	defer s.dieOnce.Do(func() { close(s.die) })

	buf := make([]byte, 65536)
	out := make([]byte, HeaderSize)
	for {
		n, from, err := cfg.Conn.ReadFrom(buf)
		if err != nil {
			return err
		}
		flowID, payload, err := s.codec.Open(buf[:n])
		if err != nil {
			continue // not ours, or corrupt
		}

		if flowID == KeepAliveFlow {
			// Pong: the client's NAT mapping, and its rawtcp flow state,
			// only refresh on inbound packets.
			if pkt, serr := s.codec.Seal(out, KeepAliveFlow, nil); serr == nil {
				cfg.Conn.WriteTo(pkt, from)
			}
			continue
		}

		f, err := s.flowFor(from, flowID)
		if err != nil {
			continue
		}
		f.touch()
		if _, err := f.conn.Write(payload); err != nil {
			s.closeFlow(f)
		}
	}
}

// flowKey scopes an id to its client; ids are unique per client only.
func flowKey(client net.Addr, id uint32) string {
	return client.String() + "|" + strconv.FormatUint(uint64(id), 10)
}

func (s *server) flowFor(client net.Addr, id uint32) (*serverFlow, error) {
	key := flowKey(client, id)

	s.mu.Lock()
	if f, ok := s.flows[key]; ok {
		s.mu.Unlock()
		return f, nil
	}
	s.mu.Unlock()

	conn, err := net.DialUDP("udp", nil, s.target)
	if err != nil {
		log.Println("udptun DialUDP:", err)
		return nil, err
	}

	f := &serverFlow{conn: conn, client: client, id: id, key: key}
	f.touch()

	s.mu.Lock()
	if existing, ok := s.flows[key]; ok { // raced; keep the winner
		s.mu.Unlock()
		conn.Close()
		return existing, nil
	}
	s.flows[key] = f
	s.mu.Unlock()

	if !s.cfg.Quiet {
		log.Printf("udp flow opened: %s", key)
	}
	go s.pump(f)
	return f, nil
}

// pump carries the target's replies back to this flow's client.
func (s *server) pump(f *serverFlow) {
	buf := make([]byte, 65536)
	out := make([]byte, s.cfg.MaxPacket)
	for {
		n, err := f.conn.Read(buf)
		if err != nil {
			s.closeFlow(f)
			return
		}
		if HeaderSize+n > s.cfg.MaxPacket {
			continue // see client.localLoop
		}
		f.touch()
		pkt, err := s.codec.Seal(out, f.id, buf[:n])
		if err != nil {
			continue
		}
		if _, err := s.cfg.Conn.WriteTo(pkt, f.client); err != nil {
			s.closeFlow(f)
			return
		}
	}
}

func (s *server) closeFlow(f *serverFlow) {
	s.mu.Lock()
	if s.flows[f.key] == f {
		delete(s.flows, f.key)
		s.mu.Unlock()
		f.conn.Close()
		if !s.cfg.Quiet {
			log.Printf("udp flow closed: %s", f.key)
		}
		return
	}
	s.mu.Unlock()
}

func (s *server) reap() {
	idleTTL := time.Duration(s.cfg.Idle) * time.Second
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-s.die:
			return
		case <-ticker.C:
			var stale []*serverFlow
			s.mu.Lock()
			for _, f := range s.flows {
				if f.idle() > idleTTL {
					stale = append(stale, f)
				}
			}
			s.mu.Unlock()
			for _, f := range stale {
				s.closeFlow(f)
			}
		}
	}
}
