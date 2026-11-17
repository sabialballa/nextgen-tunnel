package engine

import (
	"encoding/binary"
	"net"
	"net/netip"
	"sync"
	"time"
)

// Only WireGuard-shaped opaque packets enter the bounded local peer cache.
// Authentication and replay checking remain WireGuard's responsibility.
func wireGuardDatagram(p []byte) bool {
	if len(p) < 4 || len(p) > 2048 {
		return false
	}
	switch binary.LittleEndian.Uint32(p[:4]) {
	case 1:
		return len(p) == 148
	case 2:
		return len(p) == 92
	case 3:
		return len(p) == 64
	case 4:
		return len(p) >= 32 && len(p)%16 == 0
	}
	return false
}

// The listener pins WireGuard to ONE local UDP socket and replicates its replies
// to every recently active carrier. Without this, endpoint roaming selects only
// the last carrier for downlink and silently loses reverse-path redundancy.
func startListenerRedundancy(c RedundancyConfig) (*UDPRedundancy, error) {
	r := &UDPRedundancy{done: make(chan struct{})}
	listen := netip.MustParseAddrPort(c.Listen)
	target := netip.MustParseAddrPort(c.Target)
	var err error
	r.front, err = net.ListenUDP("udp4", net.UDPAddrFromAddrPort(listen))
	if err != nil {
		return nil, err
	}
	back, err := net.DialUDP("udp4", nil, net.UDPAddrFromAddrPort(target))
	if err != nil {
		r.Close()
		return nil, err
	}
	r.back = append(r.back, back)
	type peer struct {
		address netip.AddrPort
		seen    time.Time
	}
	type packet struct {
		address netip.AddrPort
		body    []byte
	}
	var lock sync.Mutex
	peers := [4]peer{}
	queues := [4]chan packet{}
	for i := range queues {
		q := make(chan packet, 64)
		queues[i] = q
		r.wg.Add(1)
		go func() {
			defer r.wg.Done()
			for {
				select {
				case <-r.done:
					return
				case p := <-q:
					r.front.SetWriteDeadline(time.Now().Add(100 * time.Millisecond))
					r.front.WriteToUDPAddrPort(p.body, p.address)
				}
			}
		}()
	}
	r.wg.Add(2)
	go func() {
		defer r.wg.Done()
		buf := make([]byte, 2049)
		for {
			n, from, e := r.front.ReadFromUDPAddrPort(buf)
			if e != nil {
				select {
				case <-r.done:
					return
				default:
					time.Sleep(10 * time.Millisecond)
					continue
				}
			}
			if !from.Addr().IsLoopback() || from == target || from == back.LocalAddr().(*net.UDPAddr).AddrPort() || !wireGuardDatagram(buf[:n]) {
				continue
			}
			now := time.Now()
			lock.Lock()
			slot := 0
			for i, p := range peers {
				if p.address == from {
					slot = i
					break
				}
				if p.seen.Before(peers[slot].seen) {
					slot = i
				}
			}
			peers[slot] = peer{from, now}
			lock.Unlock()
			back.SetWriteDeadline(now.Add(100 * time.Millisecond))
			back.Write(buf[:n])
		}
	}()
	go func() {
		defer r.wg.Done()
		buf := make([]byte, 2049)
		for {
			n, e := back.Read(buf)
			if e != nil {
				select {
				case <-r.done:
					return
				default:
					time.Sleep(10 * time.Millisecond)
					continue
				}
			}
			if !wireGuardDatagram(buf[:n]) {
				continue
			}
			lock.Lock()
			snapshot := peers
			lock.Unlock()
			now := time.Now()
			for i, p := range snapshot {
				if !p.address.IsValid() || now.Sub(p.seen) > 30*time.Second {
					continue
				}
				v := packet{p.address, append([]byte(nil), buf[:n]...)}
				select {
				case queues[i] <- v:
				default:
				}
			}
		}
	}()
	return r, nil
}
