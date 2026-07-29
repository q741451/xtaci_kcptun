// Package udprelay implements the tiny length-prefixed framing kcptun uses
// to carry discrete UDP datagrams -- their boundaries -- as discrete
// records inside a single reliable smux stream. This is what lets a
// shadowsocks-libev UDP relay ride an ordinary kcptun tunnel instance
// dedicated to --udprelay, alongside kcptun's normal TCP forwarding,
// without either side needing to know anything about shadowsocks' own
// wire format -- see client/udprelay.go and server/udprelay.go for the
// business logic that uses this framing.
package udprelay

import (
	"encoding/binary"
	"errors"
	"io"
)

// MaxPayload bounds a single record's payload to the uint16 length field.
// Real shadowsocks UDP packets are at most a few KB, far below this.
const MaxPayload = 65535

var errRecordTooLarge = errors.New("udprelay: payload too large")

// WriteRecord frames payload with its length and writes it to w in a
// single call.
func WriteRecord(w io.Writer, payload []byte) error {
	if len(payload) > MaxPayload {
		return errRecordTooLarge
	}
	buf := make([]byte, 2+len(payload))
	binary.BigEndian.PutUint16(buf[:2], uint16(len(payload)))
	copy(buf[2:], payload)
	_, err := w.Write(buf)
	return err
}

// ReadRecord reads exactly one record previously written by WriteRecord.
// It uses io.ReadFull throughout, so it reassembles a record correctly
// regardless of how the underlying stream happens to fragment reads
// (smux frame boundaries, partial TCP-ish reads, etc.).
func ReadRecord(r io.Reader) ([]byte, error) {
	var lenBuf [2]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, err
	}
	body := make([]byte, binary.BigEndian.Uint16(lenBuf[:]))
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}
	return body, nil
}
