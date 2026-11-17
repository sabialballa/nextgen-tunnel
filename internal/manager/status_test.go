package manager

import (
	"nextgen-tunnel/internal/config"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestStatusReplaceWithConcurrentReader(t *testing.T) {
	c := &Client{Config: config.Config{StatusFile: filepath.Join(t.TempDir(), "status.json")}, Manager: New(nil, nil), slots: make(chan struct{}, 1)}
	if e := c.saveStatus(); e != nil {
		t.Fatal(e)
	}
	f, e := os.Open(c.Config.StatusFile)
	if e != nil {
		t.Fatal(e)
	}
	done := make(chan struct{})
	go func() { defer close(done); time.Sleep(40 * time.Millisecond); f.Close() }()
	e = c.saveStatus()
	<-done
	if e != nil {
		t.Fatal(e)
	}
}
