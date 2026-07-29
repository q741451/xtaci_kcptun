// +build linux

package rawtcp

import (
	"container/list"
	"encoding/binary"
	"errors"
	"io"
	"io/ioutil"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var (
	errTimeout   = errors.New("rawtcp: i/o timeout")
	flowExpire   = time.Minute
	orphanExpire = 5 * time.Second
)

// fingerprint mimics a real Linux TCP stack's window/options/TTL.
var fingerprint = struct {
	window uint16
	ttl    uint16
}{window: 65535, ttl: 64}

var (
	connList   list.List
	connListMu sync.Mutex
)

type message struct {
	bts  []byte
	addr net.Addr
}

// flow tracks per-peer TCP sequencing state for one raw connection.
type flow struct {
	conn   *net.TCPConn
	handle *net.IPConn
	seq    uint32
	ack    uint32
	tsEcr  uint32
	ts     time.Time
	buf    gopacket.SerializeBuffer
	header layers.TCP
}

// Conn is a packet-oriented connection emulated over raw TCP; it implements
// net.PacketConn, as needed by kcp-go's NewConn/ServeConn.
type Conn struct {
	elem    *list.Element
	die     chan struct{}
	dieOnce sync.Once

	tcpconn  *net.TCPConn     // set on the dialing (client) side
	listener *net.TCPListener // set on the listening (server) side
	handles  []*net.IPConn    // raw IP sockets used to read/write segments

	chMessage chan message

	flows     map[string]*flow
	flowsLock sync.Mutex

	readDeadline  atomic.Value
	writeDeadline atomic.Value

	opts gopacket.SerializeOptions
}

func (c *Conn) lockflow(addr net.Addr, f func(*flow)) {
	key := addr.String()
	c.flowsLock.Lock()
	e := c.flows[key]
	if e == nil {
		e = new(flow)
		e.ts = time.Now()
		e.buf = gopacket.NewSerializeBuffer()
	}
	f(e)
	c.flows[key] = e
	c.flowsLock.Unlock()
}

// cleaner evicts idle flows.
func (c *Conn) cleaner() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-c.die:
			return
		case <-ticker.C:
			c.flowsLock.Lock()
			now := time.Now()
			for k, v := range c.flows {
				ttl := flowExpire
				if v.conn == nil {
					ttl = orphanExpire
				}
				if now.Sub(v.ts) > ttl {
					if v.conn != nil {
						setTTL(v.conn, int(fingerprint.ttl))
						v.conn.Close()
					}
					delete(c.flows, k)
				}
			}
			c.flowsLock.Unlock()
		}
	}
}

// captureFlow reads inbound segments on handle and delivers payloads to ReadFrom.
func (c *Conn) captureFlow(handle *net.IPConn, port int) {
	buf := make([]byte, 2048)
	opt := gopacket.DecodeOptions{NoCopy: true, Lazy: true}
	for {
		n, addr, err := handle.ReadFromIP(buf)
		if err != nil {
			return
		}

		packet := gopacket.NewPacket(buf[:n], layers.LayerTypeTCP, opt)
		tcp, ok := packet.TransportLayer().(*layers.TCP)
		if !ok {
			continue
		}
		if int(tcp.DstPort) != port {
			continue
		}

		src := &net.TCPAddr{IP: addr.IP, Port: int(tcp.SrcPort)}

		var orphan bool
		c.lockflow(src, func(e *flow) {
			if e.conn == nil {
				orphan = true
			}
			e.ts = time.Now()
			if tcp.ACK {
				e.seq = tcp.Ack
			}
			for _, o := range tcp.Options {
				if o.OptionType == layers.TCPOptionKindTimestamps && len(o.OptionData) == 8 {
					e.tsEcr = binary.BigEndian.Uint32(o.OptionData[:4])
					break
				}
			}
			next := tcp.Seq + uint32(len(tcp.Payload))
			if tcp.SYN {
				next++
			}
			if tcp.FIN {
				next++
			}
			if next != tcp.Seq && (e.ack == 0 || e.ack == tcp.Seq) {
				e.ack = next
			}
			e.handle = handle
		})

		if !orphan && tcp.PSH && len(tcp.Payload) > 0 {
			payload := make([]byte, len(tcp.Payload))
			copy(payload, tcp.Payload)
			select {
			case c.chMessage <- message{payload, src}:
			case <-c.die:
				return
			}
		}
	}
}

// ReadFrom implements net.PacketConn.
func (c *Conn) ReadFrom(p []byte) (int, net.Addr, error) {
	var deadline <-chan time.Time
	if d, ok := c.readDeadline.Load().(time.Time); ok && !d.IsZero() {
		t := time.NewTimer(time.Until(d))
		defer t.Stop()
		deadline = t.C
	}
	select {
	case <-deadline:
		return 0, nil, errTimeout
	case <-c.die:
		return 0, nil, io.EOF
	case m := <-c.chMessage:
		return copy(p, m.bts), m.addr, nil
	}
}

// WriteTo implements net.PacketConn.
func (c *Conn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	var deadline <-chan time.Time
	if d, ok := c.writeDeadline.Load().(time.Time); ok && !d.IsZero() {
		t := time.NewTimer(time.Until(d))
		defer t.Stop()
		deadline = t.C
	}
	select {
	case <-deadline:
		return 0, errTimeout
	case <-c.die:
		return 0, io.EOF
	default:
	}

	raddr, err := net.ResolveTCPAddr("tcp", addr.String())
	if err != nil {
		return 0, err
	}

	var lport int
	if c.tcpconn != nil {
		lport = c.tcpconn.LocalAddr().(*net.TCPAddr).Port
	} else {
		lport = c.listener.Addr().(*net.TCPAddr).Port
	}

	c.lockflow(addr, func(e *flow) {
		if e.handle == nil {
			// peer never sent us anything on this flow yet; nowhere to send to.
			n = len(p)
			return
		}

		e.header = layers.TCP{
			SrcPort: layers.TCPPort(lport),
			DstPort: layers.TCPPort(raddr.Port),
			Window:  fingerprint.window,
			Ack:     e.ack,
			Seq:     e.seq,
			PSH:     true,
			ACK:     true,
			Options: []layers.TCPOption{
				{OptionType: layers.TCPOptionKindNop},
				{OptionType: layers.TCPOptionKindNop},
				{OptionType: layers.TCPOptionKindTimestamps, OptionLength: 10, OptionData: make([]byte, 8)},
			},
		}
		binary.BigEndian.PutUint32(e.header.Options[2].OptionData[:4], uint32(time.Now().UnixNano()/int64(time.Millisecond)))
		binary.BigEndian.PutUint32(e.header.Options[2].OptionData[4:], e.tsEcr)

		if raddr.IP.To4() != nil {
			ip := &layers.IPv4{
				Protocol: layers.IPProtocolTCP,
				SrcIP:    e.handle.LocalAddr().(*net.IPAddr).IP.To4(),
				DstIP:    raddr.IP.To4(),
			}
			e.header.SetNetworkLayerForChecksum(ip)
		} else {
			ip := &layers.IPv6{
				NextHeader: layers.IPProtocolTCP,
				SrcIP:      e.handle.LocalAddr().(*net.IPAddr).IP.To16(),
				DstIP:      raddr.IP.To16(),
			}
			e.header.SetNetworkLayerForChecksum(ip)
		}

		e.buf.Clear()
		if serr := gopacket.SerializeLayers(e.buf, c.opts, &e.header, gopacket.Payload(p)); serr != nil {
			err = serr
			return
		}
		if c.tcpconn != nil {
			_, err = e.handle.Write(e.buf.Bytes())
		} else {
			_, err = e.handle.WriteToIP(e.buf.Bytes(), &net.IPAddr{IP: raddr.IP})
		}
		e.seq += uint32(len(p))
		n = len(p)
	})
	return n, err
}

// Close tears down the connection. Safe to call more than once.
func (c *Conn) Close() error {
	var err error
	c.dieOnce.Do(func() {
		close(c.die)

		if c.tcpconn != nil {
			setTTL(c.tcpconn, int(fingerprint.ttl))
			err = c.tcpconn.Close()
		} else if c.listener != nil {
			err = c.listener.Close()
			c.flowsLock.Lock()
			for k, v := range c.flows {
				if v.conn != nil {
					setTTL(v.conn, int(fingerprint.ttl))
					v.conn.Close()
				}
				delete(c.flows, k)
			}
			c.flowsLock.Unlock()
		}

		for _, h := range c.handles {
			h.Close()
		}

		connListMu.Lock()
		connList.Remove(c.elem)
		connListMu.Unlock()
	})
	return err
}

// LocalAddr implements net.PacketConn.
func (c *Conn) LocalAddr() net.Addr {
	if c.tcpconn != nil {
		return c.tcpconn.LocalAddr()
	}
	if c.listener != nil {
		return c.listener.Addr()
	}
	return nil
}

// SetDeadline implements net.PacketConn.
func (c *Conn) SetDeadline(t time.Time) error {
	if err := c.SetReadDeadline(t); err != nil {
		return err
	}
	return c.SetWriteDeadline(t)
}

// SetReadDeadline implements net.PacketConn.
func (c *Conn) SetReadDeadline(t time.Time) error {
	c.readDeadline.Store(t)
	return nil
}

// SetWriteDeadline implements net.PacketConn.
func (c *Conn) SetWriteDeadline(t time.Time) error {
	c.writeDeadline.Store(t)
	return nil
}

// SetDSCP sets the 6-bit DSCP field (IPv4) / traffic class (IPv6).
func (c *Conn) SetDSCP(dscp int) error {
	for _, h := range c.handles {
		if err := setDSCP(h, dscp); err != nil {
			return err
		}
	}
	return nil
}

// SetReadBuffer sets the OS receive buffer size on the raw IP socket(s).
func (c *Conn) SetReadBuffer(bytes int) error {
	for _, h := range c.handles {
		if err := h.SetReadBuffer(bytes); err != nil {
			return err
		}
	}
	return nil
}

// SetWriteBuffer sets the OS send buffer size on the raw IP socket(s).
func (c *Conn) SetWriteBuffer(bytes int) error {
	for _, h := range c.handles {
		if err := h.SetWriteBuffer(bytes); err != nil {
			return err
		}
	}
	return nil
}

// Dial completes a real TCP handshake to address and returns a
// packet-oriented connection that emulates it over raw sockets. mark == 0
// skips SO_MARK; see doc.go for the firewall rule this requires.
func Dial(network, address string, mark int) (*Conn, error) {
	raddr, err := net.ResolveTCPAddr(network, address)
	if err != nil {
		return nil, err
	}

	handle, err := net.DialIP("ip:tcp", nil, &net.IPAddr{IP: raddr.IP})
	if err != nil {
		return nil, err
	}

	tcpconn, err := net.DialTCP(network, nil, raddr)
	if err != nil {
		handle.Close()
		return nil, err
	}

	c := &Conn{
		die:       make(chan struct{}),
		flows:     make(map[string]*flow),
		tcpconn:   tcpconn,
		chMessage: make(chan message),
		handles:   []*net.IPConn{handle},
		opts:      gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
	}
	c.lockflow(tcpconn.RemoteAddr(), func(e *flow) { e.conn = tcpconn })

	go c.captureFlow(handle, tcpconn.LocalAddr().(*net.TCPAddr).Port)
	go c.cleaner()

	if err := setTTL(tcpconn, 1); err != nil {
		c.Close()
		return nil, err
	}
	if mark != 0 {
		setMark(tcpconn, mark) // best-effort, see doc.go
	}

	go io.Copy(ioutil.Discard, tcpconn)

	connListMu.Lock()
	c.elem = connList.PushBack(c)
	connListMu.Unlock()

	return wrap(c), nil
}

// Listen accepts TCP connections on address and returns a single
// packet-oriented connection multiplexing every accepted peer. mark == 0
// skips SO_MARK; see doc.go for the firewall rule this requires.
func Listen(network, address string, mark int) (*Conn, error) {
	laddr, err := net.ResolveTCPAddr(network, address)
	if err != nil {
		return nil, err
	}

	c := &Conn{
		flows:     make(map[string]*flow),
		die:       make(chan struct{}),
		chMessage: make(chan message),
		opts:      gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	if laddr.IP == nil || laddr.IP.IsUnspecified() {
		var lastErr error
		for _, iface := range ifaces {
			addrs, aerr := iface.Addrs()
			if aerr != nil {
				continue
			}
			for _, a := range addrs {
				ipnet, ok := a.(*net.IPNet)
				if !ok {
					continue
				}
				handle, herr := net.ListenIP("ip:tcp", &net.IPAddr{IP: ipnet.IP})
				if herr != nil {
					lastErr = herr
					continue
				}
				c.handles = append(c.handles, handle)
				go c.captureFlow(handle, laddr.Port)
			}
		}
		if len(c.handles) == 0 {
			if lastErr == nil {
				lastErr = errors.New("rawtcp: no usable network interface")
			}
			return nil, lastErr
		}
	} else {
		handle, herr := net.ListenIP("ip:tcp", &net.IPAddr{IP: laddr.IP})
		if herr != nil {
			return nil, herr
		}
		c.handles = append(c.handles, handle)
		go c.captureFlow(handle, laddr.Port)
	}

	l, err := net.ListenTCP(network, laddr)
	if err != nil {
		for _, h := range c.handles {
			h.Close()
		}
		return nil, err
	}
	c.listener = l

	go c.cleaner()

	go func() {
		for {
			conn, aerr := l.AcceptTCP()
			if aerr != nil {
				return
			}
			if terr := setTTL(conn, 1); terr != nil {
				conn.Close()
				continue
			}
			if mark != 0 {
				setMark(conn, mark) // best-effort, see doc.go
			}
			c.lockflow(conn.RemoteAddr(), func(e *flow) { e.conn = conn })
			go io.Copy(ioutil.Discard, conn)
		}
	}()

	connListMu.Lock()
	c.elem = connList.PushBack(c)
	connListMu.Unlock()

	return wrap(c), nil
}

// Cleanup gracefully closes every live Conn; call it from a signal handler.
func Cleanup() {
	connListMu.Lock()
	var wg sync.WaitGroup
	for e := connList.Front(); e != nil; e = e.Next() {
		wg.Add(1)
		go func(c *Conn) {
			defer wg.Done()
			c.Close()
		}(e.Value.(*Conn))
	}
	connListMu.Unlock()
	wg.Wait()
}

func setTTL(c *net.TCPConn, ttl int) error {
	raw, err := c.SyscallConn()
	if err != nil {
		return err
	}
	addr := c.LocalAddr().(*net.TCPAddr)
	var serr error
	if addr.IP.To4() == nil {
		raw.Control(func(fd uintptr) {
			serr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_UNICAST_HOPS, ttl)
		})
	} else {
		raw.Control(func(fd uintptr) {
			serr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TTL, ttl)
		})
	}
	return serr
}

// setMark sets SO_MARK on c; best-effort, see doc.go.
func setMark(c *net.TCPConn, mark int) error {
	raw, err := c.SyscallConn()
	if err != nil {
		return err
	}
	var serr error
	raw.Control(func(fd uintptr) {
		serr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, mark)
	})
	return serr
}

func setDSCP(c *net.IPConn, dscp int) error {
	raw, err := c.SyscallConn()
	if err != nil {
		return err
	}
	addr := c.LocalAddr().(*net.IPAddr)
	var serr error
	if addr.IP.To4() == nil {
		raw.Control(func(fd uintptr) {
			serr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_TCLASS, dscp)
		})
	} else {
		raw.Control(func(fd uintptr) {
			serr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TOS, dscp<<2)
		})
	}
	return serr
}

// wrap attaches a finalizer so a dropped Conn still gets closed on GC.
func wrap(c *Conn) *Conn {
	runtime.SetFinalizer(c, func(c *Conn) { c.Close() })
	return c
}

var _ net.PacketConn = (*Conn)(nil)
