package manager

import (
	"nextgen-tunnel/internal/config"
	"testing"
	"time"
)

func TestFailoverHysteresisAndStickySelection(t *testing.T) {
	m := New([]config.Endpoint{{Name: "primary"}, {Name: "backup"}}, nil)
	now := time.Now()
	m.Record(0, true, time.Millisecond, now)
	n, _ := m.Snapshot()
	if n != "" {
		t.Fatal("selected before two successes")
	}
	m.Record(0, true, time.Millisecond, now)
	m.Record(1, true, time.Millisecond, now)
	m.Record(1, true, time.Millisecond, now)
	for i := 0; i < 2; i++ {
		m.Record(0, false, 0, now)
		n, _ = m.Snapshot()
		if n != "primary" {
			t.Fatal("premature failover")
		}
	}
	m.Record(0, false, 0, now)
	n, _ = m.Snapshot()
	if n != "backup" {
		t.Fatal("no failover")
	}
	m.Record(0, true, time.Millisecond, now)
	m.Record(0, true, time.Millisecond, now)
	n, _ = m.Snapshot()
	if n != "backup" {
		t.Fatal("unwanted failback")
	}
	for i := 0; i < 3; i++ {
		m.Record(1, false, 0, now)
	}
	n, _ = m.Snapshot()
	if n != "primary" {
		t.Fatal("did not recover")
	}
	for i := 0; i < 3; i++ {
		m.Record(0, false, 0, now)
	}
	n, _ = m.Snapshot()
	if n != "" {
		t.Fatal("failed path retained")
	}
}
func TestBackoffBounded(t *testing.T) {
	m := New([]config.Endpoint{{Name: "a"}}, nil)
	now := time.Now()
	for i := 0; i < 100; i++ {
		m.Record(0, false, 0, now)
	}
	_, s := m.Snapshot()
	if s[0].RetryAt.Sub(now) != 32*time.Second {
		t.Fatal(s)
	}
}
