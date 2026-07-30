// Package udprelay carries a shadowsocks-libev UDP relay's datagrams over a
// net.PacketConn: a plain UDP socket, or package rawtcp's disguised one.
//
// Loss is passed through, not repaired. QUIC and DNS recover on their own, and
// repeating that underneath only adds latency.
//
// Wire format is kcp-go's, plus a flow id so replies find their way back:
//
//	nonce[16] | crc32[4] | flowID[4] | payload
//
// Datagram boundaries survive the transport, so records carry no length. The
// encryption is obfuscation, not security -- CRC32 is not a MAC and nothing
// stops a replay; shadowsocks' own AEAD protects the payload.
package udprelay

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"io"
	"log"
	"net"
	"sync"

	kcp "github.com/xtaci/kcp-go"
)

const (
	nonceSize  = 16
	crcSize    = 4
	flowIDSize = 4

	// HeaderSize is the per-datagram overhead on the wire.
	HeaderSize = nonceSize + crcSize + flowIDSize

	// KeepAliveFlow is reserved for keepalives; real flows start at 1. Nothing
	// else holds open a NAT mapping, or rawtcp's per-flow state, so the client
	// pings and the server pongs.
	KeepAliveFlow = 0
)

var (
	errShortPacket = errors.New("udprelay: packet shorter than header")
	errChecksum    = errors.New("udprelay: checksum mismatch")
	errBufTooSmall = errors.New("udprelay: destination buffer too small")
)

// applySockBuf sizes the transport's kernel buffers. net.PacketConn lacks
// these, but both concrete types have them.
func applySockBuf(conn net.PacketConn, size int) {
	if size <= 0 {
		return
	}
	if c, ok := conn.(interface{ SetReadBuffer(int) error }); ok {
		if err := c.SetReadBuffer(size); err != nil {
			log.Println("udprelay SetReadBuffer:", err)
		}
	}
	if c, ok := conn.(interface{ SetWriteBuffer(int) error }); ok {
		if err := c.SetWriteBuffer(size); err != nil {
			log.Println("udprelay SetWriteBuffer:", err)
		}
	}
}

// nonceGen re-implements kcp-go's unexported nonceAES128: a block cipher over
// its own output, far cheaper per packet than crypto/rand.
type nonceGen struct {
	seed  [aes.BlockSize]byte
	block cipher.Block
}

func newNonceGen() (*nonceGen, error) {
	var key [16]byte
	if _, err := io.ReadFull(rand.Reader, key[:]); err != nil {
		return nil, err
	}
	n := new(nonceGen)
	if _, err := io.ReadFull(rand.Reader, n.seed[:]); err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	n.block = block
	return n, nil
}

func (n *nonceGen) fill(dst []byte) {
	n.block.Encrypt(n.seed[:], n.seed[:])
	copy(dst, n.seed[:])
}

// Codec seals and opens datagrams, safely from many goroutines. BlockCrypt
// implementations keep scratch buffers in the struct -- kcp-go only ever calls
// them under a session lock -- hence the mutexes. Encrypt and Decrypt share no
// state, so each direction gets its own.
type Codec struct {
	block kcp.BlockCrypt

	sealMu sync.Mutex
	nonce  *nonceGen

	openMu sync.Mutex
}

// NewCodec returns a Codec using block, derived as for a KCP session.
func NewCodec(block kcp.BlockCrypt) (*Codec, error) {
	nonce, err := newNonceGen()
	if err != nil {
		return nil, err
	}
	return &Codec{block: block, nonce: nonce}, nil
}

// Seal frames payload for flowID into dst, which needs room for
// HeaderSize+len(payload).
func (c *Codec) Seal(dst []byte, flowID uint32, payload []byte) ([]byte, error) {
	total := HeaderSize + len(payload)
	if cap(dst) < total {
		return nil, errBufTooSmall
	}
	buf := dst[:total]

	binary.LittleEndian.PutUint32(buf[nonceSize+crcSize:], flowID)
	copy(buf[HeaderSize:], payload)
	binary.LittleEndian.PutUint32(buf[nonceSize:], crc32.ChecksumIEEE(buf[nonceSize+crcSize:]))

	c.sealMu.Lock()
	c.nonce.fill(buf[:nonceSize])
	c.block.Encrypt(buf, buf)
	c.sealMu.Unlock()
	return buf, nil
}

// Open decrypts and validates a datagram in place. payload aliases buf.
func (c *Codec) Open(buf []byte) (flowID uint32, payload []byte, err error) {
	if len(buf) < HeaderSize {
		return 0, nil, errShortPacket
	}

	c.openMu.Lock()
	c.block.Decrypt(buf, buf)
	c.openMu.Unlock()

	body := buf[nonceSize:] // crc | flowID | payload
	if crc32.ChecksumIEEE(body[crcSize:]) != binary.LittleEndian.Uint32(body) {
		return 0, nil, errChecksum
	}
	body = body[crcSize:] // flowID | payload
	return binary.LittleEndian.Uint32(body), body[flowIDSize:], nil
}
