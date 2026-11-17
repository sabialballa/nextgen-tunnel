package manager

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"nextgen-tunnel/internal/config"
	"nextgen-tunnel/internal/transport"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

type Client struct {
	Config      config.Config
	Manager     *Manager
	tcp         []net.Listener
	udp         []*net.UDPConn
	forwardsTCP []config.Forward
	forwardsUDP []config.Forward
	slots       chan struct{}
	wg          sync.WaitGroup
	accepted    atomic.Uint64
	rejected    atomic.Uint64
	oversized   atomic.Uint64
	failures    atomic.Uint64
	queueDrops  atomic.Uint64
	running     atomic.Bool
}

func ListenClient(c config.Config, m *Manager) (*Client, error) {
	cl := &Client{Config: c, Manager: m, slots: make(chan struct{}, c.MaxSessions)}
	for _, f := range c.Forwards {
		if f.Protocol == "tcp" {
			l, e := net.Listen("tcp", f.Listen)
			if e != nil {
				cl.Close()
				return nil, e
			}
			cl.tcp = append(cl.tcp, l)
			cl.forwardsTCP = append(cl.forwardsTCP, f)
		} else {
			a, e := net.ResolveUDPAddr("udp", f.Listen)
			if e != nil {
				cl.Close()
				return nil, e
			}
			l, e := net.ListenUDP("udp", a)
			if e != nil {
				cl.Close()
				return nil, e
			}
			cl.udp = append(cl.udp, l)
			cl.forwardsUDP = append(cl.forwardsUDP, f)
		}
	}
	return cl, nil
}
func (c *Client) Close() {
	for _, l := range c.tcp {
		l.Close()
	}
	for _, l := range c.udp {
		l.Close()
	}
}
func (c *Client) acquire() bool {
	select {
	case c.slots <- struct{}{}:
		c.accepted.Add(1)
		return true
	default:
		c.rejected.Add(1)
		return false
	}
}

type Status struct {
	Version    int       `json:"schema_version"`
	Time       time.Time `json:"time"`
	Selected   string    `json:"selected"`
	Transports []State   `json:"transports"`
	Active     int       `json:"active_sessions"`
	Accepted   uint64    `json:"accepted_sessions"`
	Rejected   uint64    `json:"rejected_sessions"`
	Oversized  uint64    `json:"oversized_datagrams"`
	Failures   uint64    `json:"failed_sessions"`
	QueueDrops uint64    `json:"queue_dropped_datagrams"`
	Running    bool      `json:"running"`
}

func (c *Client) Status() Status {
	name, states := c.Manager.Snapshot()
	return Status{1, time.Now().UTC(), name, states, len(c.slots), c.accepted.Load(), c.rejected.Load(), c.oversized.Load(), c.failures.Load(), c.queueDrops.Load(), c.running.Load()}
}
func (c *Client) saveStatus() error {
	path := c.Config.StatusFile
	if path == "" {
		return nil
	}
	b, e := json.MarshalIndent(c.Status(), "", "  ")
	if e != nil {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(path), ".nextgen-status-")
	if e != nil {
		return e
	}
	name := f.Name()
	defer os.Remove(name)
	if e = f.Chmod(0600); e != nil {
		f.Close()
		return e
	}
	if _, e = f.Write(b); e != nil {
		f.Close()
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	err := os.Rename(name, path)
	// Windows readers can temporarily deny file replacement. Retain atomic
	// replacement and retry only these bounded sharing/access failures.
	if runtime.GOOS == "windows" {
		for _, delay := range []time.Duration{10, 20, 40, 80, 160} {
			if !errors.Is(err, syscall.Errno(5)) && !errors.Is(err, syscall.Errno(32)) {
				break
			}
			time.Sleep(delay * time.Millisecond)
			err = os.Rename(name, path)
		}
	}
	return err
}
func (c *Client) Run(ctx context.Context) error {
	c.running.Store(true)
	if e := c.saveStatus(); e != nil {
		c.running.Store(false)
		c.Close()
		return fmt.Errorf("cannot initialize status file: %w", e)
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(ctx, c.Close)
	defer stop()
	errs := make(chan error, len(c.tcp)+len(c.udp)+1)
	c.wg.Add(1)
	go func() { defer c.wg.Done(); c.Manager.Run(ctx, time.Duration(c.Config.ProbeSeconds)*time.Second) }()
	for i, l := range c.tcp {
		f := c.forwardsTCP[i]
		c.wg.Add(1)
		go func() {
			defer c.wg.Done()
			for {
				conn, e := l.Accept()
				if e != nil {
					if ctx.Err() == nil {
						errs <- e
					}
					return
				}
				if !c.acquire() {
					conn.Close()
					continue
				}
				c.wg.Add(1)
				go func() {
					defer c.wg.Done()
					defer func() { <-c.slots }()
					defer conn.Close()
					dc, stop := context.WithTimeout(ctx, 5*time.Second)
					s, e := c.Manager.Dial(dc, transport.Request{Service: f.Service, Protocol: "tcp"})
					stop()
					if e != nil {
						c.failures.Add(1)
						return
					}
					defer s.Close()
					transport.Pipe(ctx, conn, s.Stream, time.Duration(c.Config.IdleSeconds)*time.Second)
				}()
			}
		}()
	}
	for i, l := range c.udp {
		f := c.forwardsUDP[i]
		c.wg.Add(1)
		go func() {
			defer c.wg.Done()
			if e := c.serveUDP(ctx, l, f); e != nil && ctx.Err() == nil {
				errs <- e
			}
		}()
	}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	var result error
loop:
	for {
		select {
		case <-ctx.Done():
			break loop
		case e := <-errs:
			result = e
			break loop
		case <-ticker.C:
			if e := c.saveStatus(); e != nil {
				result = fmt.Errorf("cannot write status file: %w", e)
				break loop
			}
		}
	}
	cancel()
	c.Close()
	c.wg.Wait()
	c.running.Store(false)
	_ = c.saveStatus()
	return result
}

type association struct {
	queue chan []byte
	addr  *net.UDPAddr
}

func (c *Client) serveUDP(ctx context.Context, l *net.UDPConn, f config.Forward) error {
	var mu sync.Mutex
	flows := map[string]*association{}
	buf := make([]byte, 65535)
	for {
		n, addr, e := l.ReadFromUDP(buf)
		if e != nil {
			return e
		}
		if n > transport.MaxDatagram {
			c.oversized.Add(1)
			continue
		}
		key := addr.String()
		mu.Lock()
		flow := flows[key]
		if flow == nil {
			if !c.acquire() {
				mu.Unlock()
				continue
			}
			flow = &association{queue: make(chan []byte, 32), addr: addr}
			flows[key] = flow
			c.wg.Add(1)
			go func(flow *association, key string) {
				defer c.wg.Done()
				defer func() { <-c.slots; mu.Lock(); delete(flows, key); mu.Unlock() }()
				c.udpFlow(ctx, l, f, flow)
			}(flow, key)
		}
		select {
		case flow.queue <- append([]byte(nil), buf[:n]...):
		default:
			c.queueDrops.Add(1)
		}
		mu.Unlock()
	}
}
func (c *Client) udpFlow(ctx context.Context, l *net.UDPConn, f config.Forward, flow *association) {
	dc, cancel := context.WithTimeout(ctx, 5*time.Second)
	s, e := c.Manager.Dial(dc, transport.Request{Service: f.Service, Protocol: "udp"})
	cancel()
	if e != nil {
		c.failures.Add(1)
		return
	}
	defer s.Close()
	fctx, fcancel := context.WithCancel(ctx)
	defer fcancel()
	stop := context.AfterFunc(fctx, func() { s.Close() })
	defer stop()
	done := make(chan struct{})
	idle := time.Duration(c.Config.IdleSeconds) * time.Second
	go func() {
		defer close(done)
		defer fcancel()
		for {
			_ = s.Stream.SetDeadline(time.Now().Add(idle))
			rc, stop := context.WithTimeout(fctx, idle)
			b, e := s.Receive(rc)
			stop()
			if e != nil {
				return
			}
			if _, e = l.WriteToUDP(b, flow.addr); e != nil {
				return
			}
		}
	}()
	timer := time.NewTimer(idle)
	defer timer.Stop()
loop:
	for {
		select {
		case <-fctx.Done():
			break loop
		case <-timer.C:
			break loop
		case b := <-flow.queue:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timer.Reset(idle)
			_ = s.Stream.SetDeadline(time.Now().Add(idle))
			if e = s.Send(b); e != nil {
				c.failures.Add(1)
				break loop
			}
		}
	}
	fcancel()
	s.Close()
	<-done
}
