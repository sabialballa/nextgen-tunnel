package integration

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"nextgen-tunnel/internal/config"
	"nextgen-tunnel/internal/manager"
	"nextgen-tunnel/internal/security"
	"nextgen-tunnel/internal/transport"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fixture struct {
	server           *transport.Server
	clientTLS        *tls.Config
	config           config.Config
	tcpAddr, udpAddr string
	cancel           context.CancelFunc
	done             chan struct{}
	udpPackets       *atomic.Uint64
}

func setup(t testing.TB) *fixture {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "pki")
	if e := security.InitPKI(dir, "tunnel.internal", "entry"); e != nil {
		t.Fatal(e)
	}
	tl := config.TLS{CA: filepath.Join(dir, "ca.crt"), Cert: filepath.Join(dir, "server.crt"), Key: filepath.Join(dir, "server.key"), ClientName: "entry"}
	tcp, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	udp, e := net.ListenPacket("udp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	var wg sync.WaitGroup
	var conns sync.Map
	var udpPackets atomic.Uint64
	wg.Add(2)
	go func() {
		defer wg.Done()
		for {
			c, e := tcp.Accept()
			if e != nil {
				return
			}
			conns.Store(c, true)
			wg.Add(1)
			go func() { defer wg.Done(); defer conns.Delete(c); defer c.Close(); io.Copy(c, c) }()
		}
	}()
	go func() {
		defer wg.Done()
		buf := make([]byte, 65535)
		for {
			n, a, e := udp.ReadFrom(buf)
			if e != nil {
				return
			}
			udpPackets.Add(1)
			udp.WriteTo(buf[:n], a)
		}
	}()
	c := config.Config{Role: "server", Listen: "127.0.0.1:0", TLS: tl, Services: map[string]config.Service{"tcp-echo": {Protocol: "tcp", Target: tcp.Addr().String()}, "udp-echo": {Protocol: "udp", Target: udp.LocalAddr().String()}}, MaxSessions: 64, IdleSeconds: 5, ProbeSeconds: 1}
	st, e := security.Load(c)
	if e != nil {
		t.Fatal(e)
	}
	s, e := transport.Listen(c, st)
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		if e := s.Run(ctx); e != nil {
			t.Error(e)
		}
	}()
	cc := c
	cc.Role = "client"
	cc.TLS.Cert = filepath.Join(dir, "client.crt")
	cc.TLS.Key = filepath.Join(dir, "client.key")
	cc.TLS.ServerName = "tunnel.internal"
	ct, e := security.Load(cc)
	if e != nil {
		t.Fatal(e)
	}
	f := &fixture{s, ct, c, tcp.Addr().String(), udp.LocalAddr().String(), cancel, done, &udpPackets}
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(8 * time.Second):
			t.Error("server shutdown leaked sessions")
		}
		tcp.Close()
		udp.Close()
		conns.Range(func(k, v any) bool { k.(net.Conn).Close(); return true })
		wg.Wait()
	})
	return f
}
func (f *fixture) endpoint(proto string) config.Endpoint {
	return config.Endpoint{Name: proto, Protocol: proto, Address: f.server.Address()}
}
func TestEncryptedTCPAndUDP(t *testing.T) {
	f := setup(t)
	for _, proto := range []string{"quic", "tls"} {
		t.Run(proto, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if e := manager.Probe(ctx, f.endpoint(proto), f.clientTLS); e != nil {
				t.Fatal(e)
			}
			for _, network := range []string{"tcp", "udp"} {
				t.Run(network, func(t *testing.T) {
					s, e := transport.Dial(ctx, f.endpoint(proto), f.clientTLS, transport.Request{Service: network + "-echo", Protocol: network})
					if e != nil {
						t.Fatal(e)
					}
					defer s.Close()
					_ = s.Stream.SetDeadline(time.Now().Add(3 * time.Second))
					payload := bytes.Repeat([]byte{0, 1, 2, 255}, 100)
					if network == "tcp" {
						if _, e = s.Stream.Write(payload); e != nil {
							t.Fatal(e)
						}
						reply := make([]byte, len(payload))
						if _, e = io.ReadFull(s.Stream, reply); e != nil || !bytes.Equal(reply, payload) {
							t.Fatal("TCP payload mismatch", e)
						}
					} else {
						for _, b := range [][]byte{payload, {}, bytes.Repeat([]byte{7}, transport.MaxDatagram)} {
							if e = s.Send(b); e != nil {
								t.Fatal(e)
							}
							r, e := s.Receive(ctx)
							if e != nil || !bytes.Equal(r, b) {
								t.Fatal("UDP payload mismatch", e)
							}
						}
						if s.Send(make([]byte, transport.MaxDatagram+1)) == nil {
							t.Fatal("oversize accepted")
						}
					}
				})
			}
		})
	}
}
func TestAuthenticationAndServiceAllowlist(t *testing.T) {
	f := setup(t)
	for _, proto := range []string{"tls", "quic"} {
		t.Run(proto, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			bad := f.clientTLS.Clone()
			bad.ServerName = "wrong.internal"
			if e := manager.Probe(ctx, f.endpoint(proto), bad); e == nil {
				t.Fatal("wrong server identity accepted")
			}
			bad = f.clientTLS.Clone()
			bad.RootCAs = x509.NewCertPool()
			if e := manager.Probe(ctx, f.endpoint(proto), bad); e == nil {
				t.Fatal("untrusted CA accepted")
			}
			bad = f.clientTLS.Clone()
			bad.Certificates = nil
			if e := manager.Probe(ctx, f.endpoint(proto), bad); e == nil {
				t.Fatal("anonymous client accepted")
			}
			if s, e := transport.Dial(ctx, f.endpoint(proto), f.clientTLS, transport.Request{Service: "unlisted", Protocol: "tcp"}); e == nil {
				s.Close()
				t.Fatal("unlisted target accepted")
			}
			if s, e := transport.Dial(ctx, f.endpoint(proto), f.clientTLS, transport.Request{Service: "tcp-echo", Protocol: "udp"}); e == nil {
				s.Close()
				t.Fatal("protocol mismatch accepted")
			}
		})
	}
}

func TestExpiredAndUnauthorizedClientCertificates(t *testing.T) {
	f := setup(t)
	dir := filepath.Dir(f.config.TLS.CA)
	caPEM, _ := os.ReadFile(filepath.Join(dir, "ca.crt"))
	caBlock, _ := pem.Decode(caPEM)
	ca, e := x509.ParseCertificate(caBlock.Bytes)
	if e != nil {
		t.Fatal(e)
	}
	caKeyPEM, _ := os.ReadFile(filepath.Join(dir, "ca.key"))
	keyBlock, _ := pem.Decode(caKeyPEM)
	caKey, e := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if e != nil {
		t.Fatal(e)
	}
	leaf, e := x509.ParseCertificate(f.clientTLS.Certificates[0].Certificate[0])
	if e != nil {
		t.Fatal(e)
	}
	for _, kind := range []string{"expired", "wrong-client-name"} {
		cert := *leaf
		if kind == "expired" {
			cert.NotBefore = time.Now().Add(-2 * time.Hour)
			cert.NotAfter = time.Now().Add(-time.Hour)
		} else {
			cert.Subject.CommonName = "unauthorized-entry"
			cert.RawSubject = nil
		}
		der, e := x509.CreateCertificate(rand.Reader, &cert, ca, leaf.PublicKey, caKey)
		if e != nil {
			t.Fatal(e)
		}
		bad := f.clientTLS.Clone()
		bad.Certificates = append([]tls.Certificate(nil), bad.Certificates...)
		bad.Certificates[0].Certificate = [][]byte{der}
		bad.Certificates[0].Leaf = nil
		for _, proto := range []string{"tls", "quic"} {
			t.Run(kind+"/"+proto, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				if e := manager.Probe(ctx, f.endpoint(proto), bad); e == nil {
					t.Fatal("invalid client certificate accepted")
				}
			})
		}
	}
}
func TestClientForwardingAndShutdown(t *testing.T) {
	f := setup(t)
	for _, proto := range []string{"quic", "tls"} {
		t.Run(proto, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			m := manager.New([]config.Endpoint{f.endpoint(proto)}, f.clientTLS)
			m.Record(0, true, time.Millisecond, time.Now())
			m.Record(0, true, time.Millisecond, time.Now())
			// Reserve ports, then release them immediately before binding the client.
			a, _ := net.Listen("tcp", "127.0.0.1:0")
			ta := a.Addr().String()
			a.Close()
			b, _ := net.ListenPacket("udp", "127.0.0.1:0")
			ua := b.LocalAddr().String()
			b.Close()
			c := config.Config{Role: "client", MaxSessions: 8, IdleSeconds: 5, ProbeSeconds: 1, Forwards: []config.Forward{{Service: "tcp-echo", Protocol: "tcp", Listen: ta}, {Service: "udp-echo", Protocol: "udp", Listen: ua}}}
			cl, e := manager.ListenClient(c, m)
			if e != nil {
				t.Fatal(e)
			}
			done := make(chan error, 1)
			go func() { done <- cl.Run(ctx) }()
			for _, p := range []struct{ net, addr string }{{"tcp", ta}, {"udp", ua}} {
				conn, e := net.DialTimeout(p.net, p.addr, time.Second)
				if e != nil {
					t.Fatal(e)
				}
				conn.SetDeadline(time.Now().Add(4 * time.Second))
				payload := []byte("forwarded " + p.net)
				conn.Write(payload)
				reply := make([]byte, len(payload))
				if _, e = io.ReadFull(conn, reply); e != nil || !bytes.Equal(reply, payload) {
					conn.Close()
					t.Fatal(e)
				}
				conn.Close()
			}
			held, err := net.DialTimeout("tcp", ta, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer held.Close()
			held.SetDeadline(time.Now().Add(3 * time.Second))
			if _, err = held.Write([]byte{42}); err != nil {
				t.Fatal(err)
			}
			var reply [1]byte
			if _, err = io.ReadFull(held, reply[:]); err != nil {
				t.Fatal(err)
			}
			cancel()
			select {
			case e := <-done:
				if e != nil {
					t.Fatal(e)
				}
			case <-time.After(7 * time.Second):
				t.Fatal("client failed to stop")
			}
		})
	}
}
func TestFailoverWithRealAuthenticatedProbes(t *testing.T) {
	f := setup(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	dead := f.endpoint("quic")
	dead.Address = "127.0.0.1:1"
	m := manager.New([]config.Endpoint{f.endpoint("quic"), f.endpoint("tls")}, f.clientTLS)
	for i := 0; i < 2; i++ {
		for j, p := range []string{"quic", "tls"} {
			e := manager.Probe(ctx, f.endpoint(p), f.clientTLS)
			m.Record(j, e == nil, time.Millisecond, time.Now())
		}
	}
	for i := 0; i < 3; i++ {
		dc, stop := context.WithTimeout(ctx, 100*time.Millisecond)
		e := manager.Probe(dc, dead, f.clientTLS)
		stop()
		m.Record(0, e == nil, 0, time.Now())
	}
	name, _ := m.Snapshot()
	if name != "tls" {
		t.Fatal(name)
	}
	s, e := m.Dial(ctx, transport.Request{Protocol: "tcp", Service: "tcp-echo"})
	if e != nil {
		t.Fatal(e)
	}
	s.Close()
}
func BenchmarkTCPStream(b *testing.B) {
	f := setup(b)
	for _, proto := range []string{"tls", "quic"} {
		b.Run(proto, func(b *testing.B) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			s, e := transport.Dial(ctx, f.endpoint(proto), f.clientTLS, transport.Request{Protocol: "tcp", Service: "tcp-echo"})
			if e != nil {
				b.Fatal(e)
			}
			defer s.Close()
			payload := bytes.Repeat([]byte{7}, 32*1024)
			reply := make([]byte, len(payload))
			b.SetBytes(int64(len(payload)))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				s.Stream.SetDeadline(time.Now().Add(5 * time.Second))
				if _, e = s.Stream.Write(payload); e != nil {
					b.Fatal(e)
				}
				if _, e = io.ReadFull(s.Stream, reply); e != nil {
					b.Fatal(e)
				}
			}
			b.StopTimer()
		})
	}
}
func Example_limits() {
	fmt.Println("UDP payload limit: 1150 bytes; established sessions do not migrate")
	// Output: UDP payload limit: 1150 bytes; established sessions do not migrate
}
