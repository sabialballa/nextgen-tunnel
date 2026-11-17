package transport

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestTLSFramedReceiveHonorsCancellation(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	s := &Session{Stream: a}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, e := s.Receive(ctx); done <- e }()
	cancel()
	select {
	case e := <-done:
		if e == nil {
			t.Fatal("canceled read succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("canceled session read did not exit")
	}
}
