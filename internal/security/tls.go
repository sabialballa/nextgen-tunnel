package security

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"nextgen-tunnel/internal/config"
	"os"
	"path/filepath"
	"time"
)

const ALPN = "nextgen-tunnel/1"

func Load(c config.Config) (*tls.Config, error) {
	cert, e := tls.LoadX509KeyPair(c.TLS.Cert, c.TLS.Key)
	if e != nil {
		return nil, e
	}
	b, e := os.ReadFile(c.TLS.CA)
	if e != nil {
		return nil, e
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(b) {
		return nil, errors.New("no CA certificate")
	}
	t := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}, RootCAs: roots, NextProtos: []string{ALPN}, ServerName: c.TLS.ServerName}
	t.VerifyConnection = func(s tls.ConnectionState) error {
		if s.NegotiatedProtocol != ALPN {
			return errors.New("unexpected ALPN")
		}
		if c.Role == "server" && (len(s.PeerCertificates) == 0 || s.PeerCertificates[0].Subject.CommonName != c.TLS.ClientName) {
			return errors.New("unauthorized client identity")
		}
		return nil
	}
	if c.Role == "server" {
		t.ClientAuth = tls.RequireAndVerifyClientCert
		t.ClientCAs = roots
	}
	return t, nil
}

// InitPKI writes a dedicated offline CA and two short-lived endpoint certificates.
// Never copy ca.key to a server. Existing directories are refused.
func InitPKI(dir, serverName, clientName string) error {
	if serverName == "" || clientName == "" {
		return errors.New("identities required")
	}
	if e := os.Mkdir(dir, 0700); e != nil {
		return e
	}
	serial := func() *big.Int {
		n, e := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
		if e != nil {
			panic(e)
		}
		return n
	}
	caKey, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return e
	}
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: "nextgen dedicated CA"}, NotBefore: now.Add(-5 * time.Minute), NotAfter: now.AddDate(1, 0, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, e := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if e != nil {
		return e
	}
	save := func(name string, der []byte, key *ecdsa.PrivateKey) error {
		if e := os.WriteFile(filepath.Join(dir, name+".crt"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); e != nil {
			return e
		}
		kb, e := x509.MarshalPKCS8PrivateKey(key)
		if e != nil {
			return e
		}
		return os.WriteFile(filepath.Join(dir, name+".key"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kb}), 0600)
	}
	if e = save("ca", der, caKey); e != nil {
		return e
	}
	for _, role := range []string{"server", "client"} {
		key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if e != nil {
			return e
		}
		name := clientName
		usage := x509.ExtKeyUsageClientAuth
		if role == "server" {
			name = serverName
			usage = x509.ExtKeyUsageServerAuth
		}
		cert := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: name}, NotBefore: now.Add(-5 * time.Minute), NotAfter: now.AddDate(0, 0, 90), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}}
		if role == "server" {
			cert.DNSNames = []string{serverName}
		}
		b, e := x509.CreateCertificate(rand.Reader, cert, ca, &key.PublicKey, caKey)
		if e != nil {
			return e
		}
		if e = save(role, b, key); e != nil {
			return e
		}
	}
	return nil
}
