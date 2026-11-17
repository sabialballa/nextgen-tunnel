package engine

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

func TestListenerDuplicatesRepliesAndPinsWireGuardEndpoint(t *testing.T) {
	wg := localUDP(t)
	a := localUDP(t)
	b := localUDP(t)
	reserved := localUDP(t)
	address := reserved.LocalAddr().String()
	reserved.Close()
	r, e := StartRedundancy(RedundancyConfig{Enabled: true, Mode: "listener", Listen: address, Target: wg.LocalAddr().String()})
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	front, _ := net.ResolveUDPAddr("udp4", address)
	packet := bytes.Repeat([]byte{7}, 64)
	binary.LittleEndian.PutUint32(packet, 4)
	buf := make([]byte, 2048)
	var pinned string
	for _, c := range []*net.UDPConn{a, b} {
		c.WriteToUDP(packet, front)
		wg.SetReadDeadline(time.Now().Add(time.Second))
		n, from, e := wg.ReadFromUDP(buf)
		if e != nil || !bytes.Equal(buf[:n], packet) {
			t.Fatalf("forward: %v", e)
		}
		if pinned != "" && pinned != from.String() {
			t.Fatal("WireGuard endpoint roamed between carriers")
		}
		pinned = from.String()
	}
	to, _ := net.ResolveUDPAddr("udp4", pinned)
	wg.WriteToUDP(packet, to)
	for _, c := range []*net.UDPConn{a, b} {
		c.SetReadDeadline(time.Now().Add(time.Second))
		n, _, e := c.ReadFromUDP(buf)
		if e != nil || !bytes.Equal(buf[:n], packet) {
			t.Fatalf("reverse carrier did not receive: %v", e)
		}
	}
	// A quiet first carrier must not stop the other carrier's next reply.
	b.WriteToUDP(packet, front)
	wg.SetReadDeadline(time.Now().Add(time.Second))
	_, from, e := wg.ReadFromUDP(buf)
	if e != nil {
		t.Fatal(e)
	}
	wg.WriteToUDP(packet, from)
	b.SetReadDeadline(time.Now().Add(time.Second))
	if _, _, e = b.ReadFromUDP(buf); e != nil {
		t.Fatal(e)
	}
}

func TestListenerRejectsMalformedAndOversizedPackets(t *testing.T) {
	wg := localUDP(t)
	a := localUDP(t)
	reserved := localUDP(t)
	address := reserved.LocalAddr().String()
	reserved.Close()
	r, e := StartRedundancy(RedundancyConfig{Enabled: true, Mode: "listener", Listen: address, Target: wg.LocalAddr().String()})
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	front, _ := net.ResolveUDPAddr("udp4", address)
	for _, p := range [][]byte{[]byte("invalid"), make([]byte, 2049), {1, 0, 0, 0}} {
		a.WriteToUDP(p, front)
	}
	wg.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	if _, _, e = wg.ReadFromUDP(make([]byte, 4096)); e == nil {
		t.Fatal("malformed packet forwarded")
	}
}
