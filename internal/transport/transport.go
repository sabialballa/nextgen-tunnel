// Package transport uses standard TLS / QUIC cryptography. The small application
// framing is intentionally identifiable and makes no browser-impersonation claim.
package transport

import (
	"context"
	"crypto/tls"
	"errors"
	"github.com/quic-go/quic-go"
	"io"
	"net"
	"nextgen-tunnel/internal/config"
	"sync"
	"time"
)

type Stream interface {
	io.Reader
	io.Writer
	io.Closer
	SetDeadline(time.Time) error
}
type Session struct {
	Stream   Stream
	Conn     *quic.Conn
	protocol string
	once     sync.Once
}

func (s *Session) Close() error {
	var e error
	s.once.Do(func() {
		e = s.Stream.Close()
		if s.Conn != nil {
			_ = s.Conn.CloseWithError(0, "")
		}
	})
	return e
}
func (s *Session) Send(b []byte) error {
	if len(b) > MaxDatagram {
		return errors.New("datagram exceeds 1150 bytes")
	}
	if s.Conn != nil {
		return s.Conn.SendDatagram(b)
	}
	return WriteFrame(s.Stream, b, MaxDatagram)
}
func (s *Session) Receive(ctx context.Context) ([]byte, error) {
	if s.Conn != nil {
		b, err := s.Conn.ReceiveDatagram(ctx)
		if err == nil && len(b) > MaxDatagram {
			return nil, errors.New("received datagram exceeds 1150 bytes")
		}
		return b, err
	}
	stop := context.AfterFunc(ctx, func() { s.Close() })
	defer stop()
	return ReadFrame(s.Stream, MaxDatagram)
}
func QUICConfig() *quic.Config {
	return &quic.Config{EnableDatagrams: true, HandshakeIdleTimeout: 5 * time.Second, MaxIdleTimeout: 30 * time.Second, KeepAlivePeriod: 10 * time.Second, MaxIncomingStreams: 1, MaxIncomingUniStreams: -1, Allow0RTT: false}
}
func Dial(ctx context.Context, e config.Endpoint, t *tls.Config, q Request) (*Session, error) {
	var s *Session
	if e.Protocol == "quic" {
		c, err := quic.DialAddr(ctx, e.Address, t.Clone(), QUICConfig())
		if err != nil {
			return nil, err
		}
		st, err := c.OpenStreamSync(ctx)
		if err != nil {
			_ = c.CloseWithError(0, "")
			return nil, err
		}
		s = &Session{Stream: st, Conn: c, protocol: "quic"}
	} else {
		d := tls.Dialer{NetDialer: &net.Dialer{Timeout: 5 * time.Second}, Config: t.Clone()}
		c, err := d.DialContext(ctx, "tcp", e.Address)
		if err != nil {
			return nil, err
		}
		s = &Session{Stream: c, protocol: "tls"}
	}
	stop := context.AfterFunc(ctx, func() { s.Close() })
	defer stop()
	_ = s.Stream.SetDeadline(time.Now().Add(5 * time.Second))
	if err := WriteRequest(s.Stream, q); err != nil {
		s.Close()
		return nil, err
	}
	var ack [1]byte
	if _, err := io.ReadFull(s.Stream, ack[:]); err != nil {
		s.Close()
		return nil, err
	}
	if ack[0] != 0 {
		s.Close()
		return nil, errors.New("service rejected")
	}
	_ = s.Stream.SetDeadline(time.Time{})
	return s, nil
}

// Pipe propagates half-close so request/response services that await EOF work.
// Read deadlines are refreshed on every successful read, bounding idle sessions.
func Pipe(ctx context.Context, a, b Stream, idle time.Duration) {
	abort := func(s Stream) {
		_ = s.SetDeadline(time.Now())
		if q, ok := s.(*quic.Stream); ok {
			q.CancelRead(0)
			q.CancelWrite(0)
		} else {
			_ = s.Close()
		}
	}
	stop := context.AfterFunc(ctx, func() { abort(a); abort(b) })
	defer stop()
	copyOne := func(dst, src Stream) {
		buf := make([]byte, 32*1024)
		for {
			_ = src.SetDeadline(time.Now().Add(idle))
			n, err := src.Read(buf)
			if n > 0 {
				_ = dst.SetDeadline(time.Now().Add(idle))
				if _, e := io.CopyN(dst, &sliceReader{b: buf[:n]}, int64(n)); e != nil {
					abort(a)
					abort(b)
					return
				}
			}
			if err != nil {
				if err != io.EOF {
					abort(a)
					abort(b)
				}
				break
			}
		}
		if v, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = v.CloseWrite()
		} else {
			_ = dst.Close()
		}
	}
	done := make(chan struct{})
	go func() { copyOne(a, b); close(done) }()
	copyOne(b, a)
	<-done
}

type sliceReader struct{ b []byte }

func (r *sliceReader) Read(p []byte) (int, error) {
	if len(r.b) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.b)
	r.b = r.b[n:]
	return n, nil
}
