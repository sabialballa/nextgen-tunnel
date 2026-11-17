package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRejectUnsafeAddresses(t *testing.T) {
	for _, s := range []string{"example.com:443", "127.0.0.1:0", "127.0.0.1:65536", "1.2.3.4:22", "0.0.0.0:443", "127.0.0.1;id:443"} {
		if Address(s, true) == nil {
			t.Errorf("accepted %q", s)
		}
	}
	if e := Address("[::1]:8443", true); e != nil {
		t.Fatal(e)
	}
}
func TestRejectUnknownAndTrailing(t *testing.T) {
	for _, b := range []string{`{"typo":1}`, `{} {}`, `[]`} {
		p := filepath.Join(t.TempDir(), "c.json")
		os.WriteFile(p, []byte(b), 0600)
		if _, e := Load(p); e == nil {
			t.Fatal("accepted", b)
		}
	}
}
