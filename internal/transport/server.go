package transport

import (
	"context"
	"crypto/tls"
	"github.com/quic-go/quic-go"
	"io"
	"log/slog"
	"net"
	"nextgen-tunnel/internal/config"
	"sync"
	"time"
)

type Server struct {
	cfg    config.Config
	tls    *tls.Config
	tcp    net.Listener
	quic   *quic.Listener
	slots  chan struct{}
	wg     sync.WaitGroup
	mu     sync.Mutex
	tokens float64
	last   time.Time
}

func Listen(c config.Config, t *tls.Config) (*Server, error) {
	tcp, e := net.Listen("tcp", c.Listen)
	if e != nil {
		return nil, e
	}
	q, e := quic.ListenAddr(tcp.Addr().String(), t.Clone(), QUICConfig())
	if e != nil {
		tcp.Close()
		return nil, e
	}
	return &Server{cfg: c, tls: t, tcp: tcp, quic: q, slots: make(chan struct{}, c.MaxSessions), tokens: 50, last: time.Now()}, nil
}
func (s *Server) Address() string { return s.tcp.Addr().String() }
func (s *Server) admit() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	s.tokens += now.Sub(s.last).Seconds() * 50
	s.last = now
	if s.tokens > 50 {
		s.tokens = 50
	}
	if s.tokens < 1 {
		return false
	}
	select {
	case s.slots <- struct{}{}:
		s.tokens--
		return true
	default:
		return false
	}
}
func (s *Server) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { s.tcp.Close(); s.quic.Close() })
	defer stop()
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			c, e := s.quic.Accept(ctx)
			if e != nil {
				return
			}
			if !s.admit() {
				_ = c.CloseWithError(1, "busy")
				continue
			}
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				defer func() { <-s.slots }()
				defer c.CloseWithError(0, "")
				sc, cancel := context.WithTimeout(ctx, 5*time.Second)
				st, e := c.AcceptStream(sc)
				cancel()
				if e != nil {
					return
				}
				defer st.Close()
				s.handle(ctx, &Session{Stream: st, Conn: c})
				// Stream.Close sends FIN asynchronously. Closing the connection
				// immediately can discard queued probe/rejection/final response bytes.
				_ = st.Close()
				timer := time.NewTimer(5 * time.Second)
				defer timer.Stop()
				select {
				case <-c.Context().Done():
				case <-ctx.Done():
				case <-timer.C:
				}
			}()
		}
	}()
	for {
		c, e := s.tcp.Accept()
		if e != nil {
			wasCanceled := ctx.Err() != nil
			cancel()
			s.quic.Close()
			s.wg.Wait()
			if wasCanceled {
				return nil
			}
			return e
		}
		if !s.admit() {
			c.Close()
			continue
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer func() { <-s.slots }()
			tc := tls.Server(c, s.tls.Clone())
			defer tc.Close()
			_ = tc.SetDeadline(time.Now().Add(5 * time.Second))
			hctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			if tc.HandshakeContext(hctx) != nil {
				slog.Warn("TLS handshake rejected")
				return
			}
			s.handle(ctx, &Session{Stream: tc})
		}()
	}
}
func (s *Server) handle(ctx context.Context, session *Session) {
	st := session.Stream
	stop := context.AfterFunc(ctx, func() { session.Close() })
	defer stop()
	_ = st.SetDeadline(time.Now().Add(5 * time.Second))
	req, e := ReadRequest(st)
	if e != nil {
		slog.Warn("invalid or timed-out session request")
		return
	}
	if req.Protocol == "probe" && req.Service == "" {
		if _, e = st.Write([]byte{0}); e != nil {
			return
		}
		var nonce [32]byte
		if _, e = io.ReadFull(st, nonce[:]); e == nil {
			_, _ = st.Write(nonce[:])
		}
		return
	}
	target, ok := s.cfg.Services[req.Service]
	if !ok || target.Protocol != req.Protocol {
		slog.Warn("session rejected by service policy")
		_, _ = st.Write([]byte{1})
		return
	}
	dial := net.Dialer{Timeout: 5 * time.Second}
	backend, e := dial.DialContext(ctx, target.Protocol, target.Target)
	if e != nil {
		slog.Warn("backend connection failed", "service", req.Service)
		_, _ = st.Write([]byte{2})
		return
	}
	defer backend.Close()
	if _, e = st.Write([]byte{0}); e != nil {
		return
	}
	_ = st.SetDeadline(time.Time{})
	idle := time.Duration(s.cfg.IdleSeconds) * time.Second
	if target.Protocol == "tcp" {
		Pipe(ctx, st, backend, idle)
		return
	}
	dctx, cancel := context.WithCancel(ctx)
	defer cancel()
	// Either direction's inactivity closes the association; backend errors cannot
	// retain a goroutine indefinitely. A UDP flow is bounded by MaxSessions.
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer session.Close()
		buf := make([]byte, 65535)
		for {
			_ = backend.SetReadDeadline(time.Now().Add(idle))
			n, e := backend.Read(buf)
			if e != nil {
				return
			}
			if n > MaxDatagram {
				continue
			}
			_ = st.SetDeadline(time.Now().Add(idle))
			if e = session.Send(buf[:n]); e != nil {
				return
			}
		}
	}()
	for {
		_ = st.SetDeadline(time.Now().Add(idle))
		rctx, rcancel := context.WithTimeout(dctx, idle)
		b, e := session.Receive(rctx)
		rcancel()
		if e != nil {
			break
		}
		_ = backend.SetWriteDeadline(time.Now().Add(idle))
		if _, e = backend.Write(b); e != nil {
			break
		}
	}
	cancel()
	backend.Close()
	session.Close()
	<-done
}
