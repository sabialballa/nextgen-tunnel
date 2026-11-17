package security

import (
	"crypto/tls"
	"nextgen-tunnel/internal/config"
	"os"
	"path/filepath"
	"testing"
)

func TestDedicatedPKIAndStrictTLS(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "pki")
	if e := InitPKI(dir, "tunnel.internal", "entry"); e != nil {
		t.Fatal(e)
	}
	if InitPKI(dir, "other", "entry") == nil {
		t.Fatal("existing private directory overwritten")
	}
	c := config.Config{Role: "server", TLS: config.TLS{CA: filepath.Join(dir, "ca.crt"), Cert: filepath.Join(dir, "server.crt"), Key: filepath.Join(dir, "server.key"), ClientName: "entry"}}
	tc, e := Load(c)
	if e != nil {
		t.Fatal(e)
	}
	if tc.MinVersion != tls.VersionTLS13 || tc.ClientAuth != tls.RequireAndVerifyClientCert || tc.InsecureSkipVerify {
		t.Fatal("TLS policy weakened")
	}
	if tc.VerifyConnection(tls.ConnectionState{NegotiatedProtocol: "other"}) == nil {
		t.Fatal("incorrect ALPN accepted")
	}
	os.WriteFile(c.TLS.CA, []byte("invalid CA"), 0600)
	if _, e = Load(c); e == nil {
		t.Fatal("invalid trust anchor accepted")
	}
}
