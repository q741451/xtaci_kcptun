package udprelay

import (
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	kcp "github.com/xtaci/kcp-go"
)

// ClientConfig configures RunClient.
type ClientConfig struct {
	LocalAddr string         // where ss-local's UDP relay points
	Conn      net.PacketConn // transport toward the server
	Remote    net.Addr       // server address on Conn
	Block     kcp.BlockCrypt
	MaxPacket int  // largest packet on the wire, header included (--mtu)
	SockBuf   int  // --sockbuf
	Idle      int  // seconds before an unused flow is forgotten
	KeepAlive int  // seconds between keepalives
	Quiet     bool // suppress per-flow logging
}

// clientFlow maps one of ss-local's sockets to a flow id. ss-local opens a
// fresh one per application flow; the server echoes the id back so replies
// find the right socket.
type clientFlow struct {
	id         uint32
	addr       *net.UDPAddr
	lastActive int64 // unix nano, atomic
}

func (f *clientFlow) touch() { atomic.StoreInt64(&f.lastActive, time.Now().UnixNano()) }

func (f *clientFlow) idle() time.Duration {
	return time.Since(time.Unix(0, atomic.LoadInt64(&f.lastActive)))
}

type client struct {
	cfg   ClientConfig
	codec *Codec
	local *net.UDPConn

	mu     sync.Mutex
	byAddr map[string]*clientFlow
	byID   map[uint32]*clientFlow
	nextID uint32

	oversize uint64 // atomic
	die      chan struct{}
	dieOnce  sync.Once
}

// RunClient relays datagrams between cfg.LocalAddr and the server on cfg.Conn.
// It blocks until either side fails.
func RunClient(cfg ClientConfig) error {
	laddr, err := net.ResolveUDPAddr("udp", cfg.LocalAddr)
	if err != nil {
		return err
	}
	local, err := net.ListenUDP("udp", laddr)
	if err != nil {
		return err
	}
	defer local.Close()

	codec, err := NewCodec(cfg.Block)
	if err != nil {
		return err
	}
	applySockBuf(cfg.Conn, cfg.SockBuf)

	c := &client{
		cfg:    cfg,
		codec:  codec,
		local:  local,
		byAddr: make(map[string]*clientFlow),
		byID:   make(map[uint32]*clientFlow),
		die:    make(chan struct{}),
	}
	log.Println("udprelay listening on:", local.LocalAddr())

	errCh := make(chan error, 2)
	go func() { errCh <- c.transportLoop() }()
	go c.maintain()
	go func() { errCh <- c.localLoop() }()

	err = <-errCh
	c.dieOnce.Do(func() { close(c.die) })
	return err
}

// flowFor returns addr's flow, registering one if new.
func (c *client) flowFor(addr *net.UDPAddr) *clientFlow {
	key := addr.String()
	c.mu.Lock()
	defer c.mu.Unlock()
	if f, ok := c.byAddr[key]; ok {
		return f
	}
	// skip KeepAliveFlow, and any id still live after a wrap
	for {
		c.nextID++
		if c.nextID != KeepAliveFlow && c.byID[c.nextID] == nil {
			break
		}
	}
	f := &clientFlow{id: c.nextID, addr: addr}
	f.touch()
	c.byAddr[key] = f
	c.byID[f.id] = f
	if !c.cfg.Quiet {
		log.Printf("udp flow opened: %s (id %d)", key, f.id)
	}
	return f
}

func (c *client) lookup(id uint32) *clientFlow {
	c.mu.Lock()
	f := c.byID[id]
	c.mu.Unlock()
	return f
}

// localLoop forwards ss-local's datagrams onward.
func (c *client) localLoop() error {
	buf := make([]byte, 65536)
	out := make([]byte, c.cfg.MaxPacket)
	for {
		n, addr, err := c.local.ReadFromUDP(buf)
		if err != nil {
			return err
		}
		// Nothing below fragments, and IP doing it would give --tcp away.
		// Drop, and let the sender find its path MTU.
		if HeaderSize+n > c.cfg.MaxPacket {
			if total := atomic.AddUint64(&c.oversize, 1); total == 1 {
				log.Printf("udprelay: dropping %d-byte datagram, over the %d-byte limit set by -mtu; lower the sender's packet size", n, c.cfg.MaxPacket-HeaderSize)
			}
			continue
		}

		f := c.flowFor(addr)
		f.touch()
		pkt, err := c.codec.Seal(out, f.id, buf[:n])
		if err != nil {
			continue
		}
		if _, err := c.cfg.Conn.WriteTo(pkt, c.cfg.Remote); err != nil {
			return err
		}
	}
}

// transportLoop hands replies back to the socket that asked.
func (c *client) transportLoop() error {
	buf := make([]byte, 65536)
	for {
		n, _, err := c.cfg.Conn.ReadFrom(buf)
		if err != nil {
			return err
		}
		flowID, payload, err := c.codec.Open(buf[:n])
		if err != nil {
			continue // not ours, or corrupt
		}
		if flowID == KeepAliveFlow {
			continue // arriving was the point
		}
		f := c.lookup(flowID)
		if f == nil {
			continue // already reaped
		}
		f.touch()
		if _, err := c.local.WriteToUDP(payload, f.addr); err != nil {
			return err
		}
	}
}

// maintain reaps idle flows and keeps the path warm.
func (c *client) maintain() {
	idleTTL := time.Duration(c.cfg.Idle) * time.Second
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	out := make([]byte, HeaderSize)
	var lastPing time.Time
	keepAlive := time.Duration(c.cfg.KeepAlive) * time.Second

	for {
		select {
		case <-c.die:
			return
		case now := <-ticker.C:
			c.mu.Lock()
			for key, f := range c.byAddr {
				if f.idle() > idleTTL {
					delete(c.byAddr, key)
					delete(c.byID, f.id)
					if !c.cfg.Quiet {
						log.Printf("udp flow closed: %s (id %d)", key, f.id)
					}
				}
			}
			c.mu.Unlock()

			if keepAlive > 0 && now.Sub(lastPing) >= keepAlive {
				lastPing = now
				if pkt, err := c.codec.Seal(out, KeepAliveFlow, nil); err == nil {
					c.cfg.Conn.WriteTo(pkt, c.cfg.Remote)
				}
			}
		}
	}
}
