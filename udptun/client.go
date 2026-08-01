package udptun

import (
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtaci/kcp-go/crypt"
)

// ClientConfig configures RunClient.
type ClientConfig struct {
	LocalAddr string // where ss-local's UDP relay points
	// Dial opens the transport toward the server. It is called again whenever
	// the transport goes dead, so the local listener -- and the flow table --
	// survive a server restart.
	Dial      func() (net.PacketConn, net.Addr, error)
	Block     crypt.BlockCrypt
	MaxPacket int  // largest packet on the wire, header included (--mtu)
	SockBuf   int  // --sockbuf
	DSCP      int  // --dscp
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

	// current transport; replaced on reconnect
	connMu   sync.RWMutex
	conn     net.PacketConn
	remote   net.Addr
	lastRecv int64 // unix nano, atomic

	mu     sync.Mutex
	byAddr map[string]*clientFlow
	byID   map[uint32]*clientFlow
	nextID uint32

	oversize uint64 // atomic
	sendErr  int64  // unix nano of last warning, atomic
	replyErr int64
	die      chan struct{}
	dieOnce  sync.Once
}

// RunClient relays datagrams between cfg.LocalAddr and the server reached by
// cfg.Dial. It blocks until the local listener fails; a failing transport is
// reconnected instead.
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
	c := &client{
		cfg:    cfg,
		codec:  codec,
		local:  local,
		byAddr: make(map[string]*clientFlow),
		byID:   make(map[uint32]*clientFlow),
		die:    make(chan struct{}),
	}
	log.Println("listening on:", local.LocalAddr())

	errCh := make(chan error, 1)
	go c.maintain()
	go func() { errCh <- c.localLoop() }()
	go c.supervise()

	err = <-errCh
	c.dieOnce.Do(func() { close(c.die) })
	return err
}

// supervise keeps a transport up. A dead one is replaced rather than fatal:
// the far end restarting should cost a reconnect, not the whole relay.
func (c *client) supervise() {
	for {
		conn, remote, err := c.cfg.Dial()
		if err != nil {
			log.Println("udptun dial:", err)
			select {
			case <-c.die:
				return
			case <-time.After(time.Second):
			}
			continue
		}
		applySockBuf(conn, c.cfg.SockBuf)
		applyDSCP(conn, c.cfg.DSCP)

		c.connMu.Lock()
		c.conn, c.remote = conn, remote
		c.connMu.Unlock()
		c.touchRecv()
		log.Println("connection:", conn.LocalAddr(), "->", remote)

		go c.watchdog(conn)
		err = c.transportLoop(conn)
		conn.Close()

		// Stop handing this one out before redialing: Dial can keep failing
		// for as long as the far end is down, and every datagram meanwhile
		// would otherwise be written to a closed connection.
		c.connMu.Lock()
		c.conn, c.remote = nil, nil
		c.connMu.Unlock()

		select {
		case <-c.die:
			return
		default:
		}
		log.Println("udptun: transport lost, reconnecting:", err)
	}
}

// watchdog replaces a transport that has gone quiet. It is deliberately the
// only liveness signal: a UDP socket never errors, and under -tcp the cover
// connection is decorative once the handshake is done -- the data path runs on
// raw sockets and survives the RST injection that rawtcp exists to hide from.
// Treating a dead cover connection as a dead transport would hand any
// middlebox a way to tear down a working tunnel, so only silence counts.
func (c *client) watchdog(conn net.PacketConn) {
	if c.cfg.KeepAlive <= 0 {
		return
	}
	dead := time.Duration(3*c.cfg.KeepAlive) * time.Second
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-c.die:
			return
		case <-ticker.C:
			c.connMu.RLock()
			current := c.conn
			c.connMu.RUnlock()
			if current != conn {
				return // already replaced
			}
			if time.Since(time.Unix(0, atomic.LoadInt64(&c.lastRecv))) > dead {
				log.Printf("udptun: nothing received for %v, dropping the transport", dead)
				conn.Close() // unblocks transportLoop
				return
			}
		}
	}
}

func (c *client) touchRecv() { atomic.StoreInt64(&c.lastRecv, time.Now().UnixNano()) }

// transport returns the connection to write on, nil before the first dial.
func (c *client) transport() (net.PacketConn, net.Addr) {
	c.connMu.RLock()
	defer c.connMu.RUnlock()
	return c.conn, c.remote
}

// warn rate-limits a recurring message to one line a second. Loss is normal
// here so these must not flood, but they must not be silent either.
func (c *client) warn(last *int64, format string, args ...interface{}) {
	now := time.Now().UnixNano()
	prev := atomic.LoadInt64(last)
	if now-prev < int64(time.Second) || !atomic.CompareAndSwapInt64(last, prev, now) {
		return
	}
	log.Printf(format, args...)
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
				log.Printf("udptun: dropping %d-byte datagram, over the %d-byte limit set by -mtu; lower the sender's packet size", n, c.cfg.MaxPacket-HeaderSize)
			}
			continue
		}

		f := c.flowFor(addr)
		f.touch()
		pkt, err := c.codec.Seal(out, f.id, buf[:n])
		if err != nil {
			continue
		}
		conn, remote := c.transport()
		if conn == nil {
			continue // no transport yet; the datagram is not worth queueing
		}
		if _, err := conn.WriteTo(pkt, remote); err != nil {
			// Expected while the supervisor swaps a dead transport out, and
			// never worth killing the relay for: only the local listener
			// failing is fatal. Dropping one datagram is what UDP is for.
			c.warn(&c.sendErr, "udptun: transport write failed: %v", err)
		}
	}
}

// transportLoop hands replies back to the socket that asked.
func (c *client) transportLoop(conn net.PacketConn) error {
	buf := make([]byte, 65536)
	for {
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			return err
		}
		c.touchRecv()
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
			c.warn(&c.replyErr, "udptun: reply to %s failed: %v", f.addr, err)
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
					if conn, remote := c.transport(); conn != nil {
						conn.WriteTo(pkt, remote)
					}
				}
			}
		}
	}
}
