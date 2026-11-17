package engine

import (
	"bytes"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func localUDP(t *testing.T) *net.UDPConn {
	t.Helper()
	c, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func TestRedundancySurvivesEitherSilentCarrier(t *testing.T) {
	target := localUDP(t)
	a := localUDP(t)
	b := localUDP(t)
	reservation := localUDP(t)
	listen := reservation.LocalAddr().String()
	reservation.Close()
	var silentA, silentB atomic.Bool
	silentA.Store(true)
	var countA, countB atomic.Int64
	for _, item := range []struct {
		c      *net.UDPConn
		silent *atomic.Bool
		count  *atomic.Int64
	}{{a, &silentA, &countA}, {b, &silentB, &countB}} {
		go func() {
			buf := make([]byte, 2048)
			for {
				n, addr, e := item.c.ReadFromUDP(buf)
				if e != nil {
					return
				}
				item.count.Add(1)
				if !item.silent.Load() {
					item.c.WriteToUDP(buf[:n], addr)
				}
			}
		}()
	}
	relay, e := StartRedundancy(RedundancyConfig{Enabled: true, Listen: listen, Target: target.LocalAddr().String(), Backends: []string{a.LocalAddr().String(), b.LocalAddr().String()}})
	if e != nil {
		t.Fatal(e)
	}
	defer relay.Close()
	front, e := net.ResolveUDPAddr("udp4", listen)
	if e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 2; i++ {
		payload := bytes.Repeat([]byte{byte(i + 1)}, 1024)
		target.SetReadDeadline(time.Now().Add(time.Second))
		if _, e = target.WriteToUDP(payload, front); e != nil {
			t.Fatal(e)
		}
		buf := make([]byte, 2048)
		n, _, e := target.ReadFromUDP(buf)
		if e != nil || !bytes.Equal(buf[:n], payload) {
			t.Fatalf("silent carrier %d interrupted datagram: %v", i, e)
		}
		silentB.Store(true)
		silentA.Store(false)
	}
	if countA.Load() == 0 || countB.Load() == 0 {
		t.Fatal("traffic was not duplicated across independent carriers")
	}
}

func TestRedundancyRejectsUnknownLocalSender(t *testing.T) {
	target := localUDP(t)
	a := localUDP(t)
	b := localUDP(t)
	stranger := localUDP(t)
	reservation := localUDP(t)
	listen := reservation.LocalAddr().String()
	reservation.Close()
	relay, e := StartRedundancy(RedundancyConfig{Enabled: true, Listen: listen, Target: target.LocalAddr().String(), Backends: []string{a.LocalAddr().String(), b.LocalAddr().String()}})
	if e != nil {
		t.Fatal(e)
	}
	defer relay.Close()
	front, _ := net.ResolveUDPAddr("udp4", listen)
	stranger.WriteToUDP([]byte("not the WireGuard socket"), front)
	a.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	if _, _, e = a.ReadFromUDP(make([]byte, 64)); e == nil {
		t.Fatal("unknown sender reached a carrier")
	}
}

func TestRedundancyRestrictsDestinations(t *testing.T) {
	for _, c := range []RedundancyConfig{{Enabled: true, Listen: "0.0.0.0:51811", Target: "127.0.0.1:51860", Backends: []string{"127.0.0.1:51812", "127.0.0.1:51813"}}, {Enabled: true, Listen: "127.0.0.1:51811", Target: "127.0.0.1:51860", Backends: []string{"127.0.0.1:51812", "127.0.0.1:51812"}}, {Enabled: false, Listen: "127.0.0.1:51811"}} {
		if c.Validate() == nil {
			t.Fatal("unsafe relay configuration accepted")
		}
	}
}

func TestRedundancyContinuesAfterOversizedPacket(t *testing.T) {
	target := localUDP(t)
	a := localUDP(t)
	b := localUDP(t)
	reservation := localUDP(t)
	listen := reservation.LocalAddr().String()
	reservation.Close()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, e := a.ReadFromUDP(buf)
			if e != nil {
				return
			}
			a.WriteToUDP(buf[:n], addr)
		}
	}()
	relay, e := StartRedundancy(RedundancyConfig{Enabled: true, Listen: listen, Target: target.LocalAddr().String(), Backends: []string{a.LocalAddr().String(), b.LocalAddr().String()}})
	if e != nil {
		t.Fatal(e)
	}
	defer relay.Close()
	front, _ := net.ResolveUDPAddr("udp4", listen)
	target.WriteToUDP(make([]byte, 9000), front)
	payload := []byte("valid encrypted datagram placeholder")
	target.WriteToUDP(payload, front)
	target.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 2048)
	n, _, e := target.ReadFromUDP(buf)
	if e != nil || !bytes.Equal(buf[:n], payload) {
		t.Fatalf("oversized datagram stopped forwarding: %v", e)
	}
}
