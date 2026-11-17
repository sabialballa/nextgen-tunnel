package transport

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
)

const MaxDatagram = 1150

type Request struct {
	Service  string `json:"service"`
	Protocol string `json:"protocol"`
}

func WriteFrame(w io.Writer, b []byte, max int) error {
	if len(b) > max || len(b) > 65535 {
		return errors.New("frame too large")
	}
	buf := make([]byte, 2+len(b))
	binary.BigEndian.PutUint16(buf, uint16(len(b)))
	copy(buf[2:], b)
	for len(buf) > 0 {
		n, e := w.Write(buf)
		if e != nil {
			return e
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		buf = buf[n:]
	}
	return nil
}
func ReadFrame(r io.Reader, max int) ([]byte, error) {
	var h [2]byte
	if _, e := io.ReadFull(r, h[:]); e != nil {
		return nil, e
	}
	n := int(binary.BigEndian.Uint16(h[:]))
	if n > max {
		return nil, errors.New("frame too large")
	}
	b := make([]byte, n)
	_, e := io.ReadFull(r, b)
	return b, e
}
func WriteRequest(w io.Writer, q Request) error {
	b, e := json.Marshal(q)
	if e != nil {
		return e
	}
	return WriteFrame(w, b, 1024)
}
func ReadRequest(r io.Reader) (Request, error) {
	var q Request
	b, e := ReadFrame(r, 1024)
	if e != nil {
		return q, e
	}
	e = json.Unmarshal(b, &q)
	return q, e
}
