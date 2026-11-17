package engine

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// RedundancyConfig duplicates encrypted WireGuard datagrams over independent
// loopback carriers. WireGuard authenticates and rejects duplicate packets.
// It does not duplicate plaintext application traffic or implement encryption.
type RedundancyConfig struct {
	Enabled  bool     `json:"enabled"`
	Mode     string   `json:"mode,omitempty"`
	Listen   string   `json:"listen,omitempty"`
	Target   string   `json:"target,omitempty"`
	Backends []string `json:"backends,omitempty"`
}

func LoadRedundancy(path string) (RedundancyConfig, error) {
	var c RedundancyConfig
	if !filepath.IsAbs(path) {
		return c, errors.New("absolute redundancy configuration path required")
	}
	f, e := os.Open(path)
	if e != nil {
		return c, e
	}
	defer f.Close()
	if info, err := f.Stat(); err != nil {
		return c, err
	} else if info.Size() > 16384 {
		return c, errors.New("redundancy configuration exceeds 16 KiB")
	}
	d := json.NewDecoder(io.LimitReader(f, 16385))
	d.DisallowUnknownFields()
	if e = d.Decode(&c); e != nil {
		return c, e
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return c, errors.New("trailing redundancy configuration data")
	}
	return c, c.Validate()
}

func (c RedundancyConfig) Validate() error {
	if !c.Enabled {
		if c.Mode != "" || c.Listen != "" || c.Target != "" || len(c.Backends) != 0 {
			return errors.New("disabled redundancy must have no endpoints")
		}
		return nil
	}
	if c.Mode != "" && c.Mode != "listener" {
		return errors.New("unknown redundancy mode")
	}
	if c.Mode == "listener" && len(c.Backends) != 0 {
		return errors.New("listener learns bounded loopback peers; no backends allowed")
	}
	if c.Mode != "listener" && (len(c.Backends) < 2 || len(c.Backends) > 4) {
		return errors.New("two to four independent carriers required")
	}
	seen := map[netip.AddrPort]bool{}
	for _, s := range append([]string{c.Listen, c.Target}, c.Backends...) {
		a, e := netip.ParseAddrPort(s)
		if e != nil || !a.Addr().Is4() || !a.Addr().IsLoopback() || a.Port() < 1024 || seen[a] {
			return errors.New("distinct unprivileged IPv4 loopback endpoints required")
		}
		seen[a] = true
	}
	return nil
}

type UDPRedundancy struct {
	front *net.UDPConn
	back  []*net.UDPConn
	done  chan struct{}
	once  sync.Once
	wg    sync.WaitGroup
}

func StartRedundancy(c RedundancyConfig) (*UDPRedundancy, error) {
	if e := c.Validate(); e != nil {
		return nil, e
	}
	if !c.Enabled {
		return nil, nil
	}
	if c.Mode == "listener" {
		return startListenerRedundancy(c)
	}
	r := &UDPRedundancy{done: make(chan struct{})}
	listen := netip.MustParseAddrPort(c.Listen)
	target := netip.MustParseAddrPort(c.Target)
	var e error
	r.front, e = net.ListenUDP("udp4", net.UDPAddrFromAddrPort(listen))
	if e != nil {
		return nil, e
	}
	reserved := map[uint16]bool{listen.Port(): true, target.Port(): true}
	for _, b := range c.Backends {
		reserved[netip.MustParseAddrPort(b).Port()] = true
	}
	for _, b := range c.Backends {
		var conn *net.UDPConn
		for attempt := 0; attempt < 16; attempt++ {
			candidate, err := net.DialUDP("udp4", nil, net.UDPAddrFromAddrPort(netip.MustParseAddrPort(b)))
			if err != nil {
				r.Close()
				return nil, err
			}
			if reserved[candidate.LocalAddr().(*net.UDPAddr).AddrPort().Port()] {
				candidate.Close()
				continue
			}
			conn = candidate
			break
		}
		if conn == nil {
			r.Close()
			return nil, errors.New("cannot allocate a non-conflicting carrier source port")
		}
		r.back = append(r.back, conn)
	}
	queues := make([]chan []byte, len(r.back))
	for i, conn := range r.back {
		q := make(chan []byte, 64)
		queues[i] = q
		r.wg.Add(2)
		go func() {
			defer r.wg.Done()
			for {
				select {
				case <-r.done:
					return
				case packet := <-q:
					conn.SetWriteDeadline(time.Now().Add(100 * time.Millisecond))
					conn.Write(packet)
				}
			}
		}()
		go func() {
			defer r.wg.Done()
			buf := make([]byte, 2049)
			for {
				n, err := conn.Read(buf)
				if err != nil {
					select {
					case <-r.done:
						return
					default:
						time.Sleep(10 * time.Millisecond)
						continue
					}
				}
				if n > 2048 {
					continue
				}
				r.front.SetWriteDeadline(time.Now().Add(100 * time.Millisecond))
				r.front.WriteToUDPAddrPort(buf[:n], target)
			}
		}()
	}
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		buf := make([]byte, 2049)
		for {
			n, from, err := r.front.ReadFromUDPAddrPort(buf)
			if err != nil {
				select {
				case <-r.done:
					return
				default:
					time.Sleep(10 * time.Millisecond)
					continue
				}
			}
			if from != target || n > 2048 {
				continue
			}
			for _, q := range queues {
				packet := append([]byte(nil), buf[:n]...)
				select {
				case q <- packet:
				default:
				}
			}
		}
	}()
	return r, nil
}

func (r *UDPRedundancy) Close() {
	if r == nil {
		return
	}
	r.once.Do(func() {
		close(r.done)
		if r.front != nil {
			r.front.Close()
		}
		for _, c := range r.back {
			c.Close()
		}
		r.wg.Wait()
	})
}
