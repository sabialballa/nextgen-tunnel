package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPrivatePlanDoesNotPutServerPrivateKeyInClient(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "private")
	if e := Init(dir, "127.0.0.1", "tunnel.internal"); e != nil {
		t.Fatal(e)
	}
	var p Profile
	b, _ := os.ReadFile(filepath.Join(dir, "profile.json"))
	if e := json.Unmarshal(b, &p); e != nil {
		t.Fatal(e)
	}
	out := filepath.Join(t.TempDir(), "configs")
	if e := Plan(filepath.Join(dir, "profile.json"), out); e != nil {
		t.Fatal(e)
	}
	client, e := os.ReadFile(filepath.Join(out, "client.json"))
	if e != nil {
		t.Fatal(e)
	}
	if strings.Contains(string(client), p.PrivateKey) || strings.Contains(string(client), p.Key) || strings.Contains(string(client), `"insecure": true`) {
		t.Fatal("private server material or insecure TLS in client")
	}
	if Plan(filepath.Join(dir, "profile.json"), out) == nil {
		t.Fatal("existing configuration overwritten")
	}
}
func TestEngineIntegrityBeforeExecution(t *testing.T) {
	path := filepath.Join(t.TempDir(), "engine")
	if e := os.WriteFile(path, []byte("not an engine"), 0700); e != nil {
		t.Fatal(e)
	}
	if Verify(path, strings.Repeat("0", 64)) == nil {
		t.Fatal("bad digest accepted")
	}
	sum := sha256.Sum256([]byte("not an engine"))
	if e := Verify(path, hex.EncodeToString(sum[:])); e != nil && os.PathSeparator == '/' {
		t.Fatal(e)
	}
}
