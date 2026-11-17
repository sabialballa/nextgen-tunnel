package integration

import (
	"context"
	"nextgen-tunnel/internal/transport"
	"testing"
	"time"
)

func TestPeerCannotBypassServerDatagramBound(t *testing.T) {
	f := setup(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	s, e := transport.Dial(ctx, f.endpoint("quic"), f.clientTLS, transport.Request{Service: "udp-echo", Protocol: "udp"})
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	if e = s.Conn.SendDatagram(make([]byte, transport.MaxDatagram+1)); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Receive(ctx); e == nil {
		t.Fatal("oversized native datagram was accepted")
	}
	if got := f.udpPackets.Load(); got != 0 {
		t.Fatalf("forwarded %d oversized packets to backend", got)
	}
}
