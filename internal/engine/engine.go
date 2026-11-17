// Package engine generates versioned configurations for a separately supplied
// sing-box engine. It does not implement or impersonate its transport protocols.
package engine

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"nextgen-tunnel/internal/security"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

type M = map[string]any
type Profile struct {
	ServerIP        string   `json:"server_ip"`
	ServerName      string   `json:"server_name"`
	QUICPort        int      `json:"quic_port"`
	TCPPort         int      `json:"tcp_port"`
	Password        string   `json:"password"`
	UUID            string   `json:"uuid"`
	PrivateKey      string   `json:"reality_private_key"`
	PublicKey       string   `json:"reality_public_key"`
	ShortID         string   `json:"short_id"`
	CA              string   `json:"ca"`
	Cert            string   `json:"cert"`
	Key             string   `json:"key"`
	Namespace       string   `json:"namespace"`
	DNS             string   `json:"dns_server"`
	HealthURL       string   `json:"health_url"`
	AllowCIDRs      []string `json:"allow_cidrs"`
	RouteCIDRs      []string `json:"route_cidrs"`
	HandshakeServer string   `json:"handshake_server"`
	HandshakePort   int      `json:"handshake_port"`
}

func Init(dir, ip, name string) error {
	if net.ParseIP(ip) == nil {
		return errors.New("literal server IP required")
	}
	if e := os.Mkdir(dir, 0700); e != nil {
		return e
	}
	dir, e := filepath.Abs(dir)
	if e != nil {
		return e
	}
	if e = security.InitPKI(filepath.Join(dir, "pki"), name, "entry"); e != nil {
		return e
	}
	key, e := ecdh.X25519().GenerateKey(rand.Reader)
	if e != nil {
		return e
	}
	secret := make([]byte, 32)
	if _, e = rand.Read(secret); e != nil {
		return e
	}
	id := make([]byte, 16)
	if _, e = rand.Read(id); e != nil {
		return e
	}
	id[6] = (id[6] & 15) | 64
	id[8] = (id[8] & 63) | 128
	uuid := fmt.Sprintf("%x-%x-%x-%x-%x", id[:4], id[4:6], id[6:8], id[8:10], id[10:])
	p := Profile{ServerIP: ip, ServerName: name, QUICPort: 18444, TCPPort: 18445, Password: hex.EncodeToString(secret), UUID: uuid, PrivateKey: base64.RawURLEncoding.EncodeToString(key.Bytes()), PublicKey: base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes()), ShortID: hex.EncodeToString(secret[:8]), CA: filepath.Join(dir, "pki/ca.crt"), Cert: filepath.Join(dir, "pki/server.crt"), Key: filepath.Join(dir, "pki/server.key"), Namespace: "ngt-apps", DNS: "1.1.1.1", HealthURL: "https://www.gstatic.com/generate_204", AllowCIDRs: []string{"0.0.0.0/0", "::/0"}, RouteCIDRs: []string{"0.0.0.0/0", "::/0"}, HandshakeServer: "127.0.0.1", HandshakePort: 19443}
	return write(filepath.Join(dir, "profile.json"), p)
}
func write(path string, value any) error {
	b, e := json.MarshalIndent(value, "", "  ")
	if e != nil {
		return e
	}
	return os.WriteFile(path, append(b, '\n'), 0600)
}
func Plan(path, out string) error {
	f, e := os.Open(path)
	if e != nil {
		return e
	}
	defer f.Close()
	info, e := f.Stat()
	if e != nil {
		return e
	}
	if info.Size() > 1<<20 {
		return errors.New("engine profile exceeds 1 MiB")
	}
	var p Profile
	d := json.NewDecoder(io.LimitReader(f, 1<<20))
	d.DisallowUnknownFields()
	if e = d.Decode(&p); e != nil {
		return e
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return errors.New("trailing engine profile data")
	}
	if net.ParseIP(p.ServerIP) == nil || net.ParseIP(p.DNS) == nil || net.ParseIP(p.HandshakeServer) == nil || len(p.Password) < 32 || !regexp.MustCompile(`^ngt-[a-z0-9_-]{1,24}$`).MatchString(p.Namespace) {
		return errors.New("invalid engine profile")
	}
	for _, v := range []int{p.QUICPort, p.TCPPort, p.HandshakePort} {
		if v < 1 || v > 65535 {
			return errors.New("invalid engine port")
		}
	}
	for _, v := range append(append([]string{}, p.AllowCIDRs...), p.RouteCIDRs...) {
		if _, _, e = net.ParseCIDR(v); e != nil {
			return e
		}
	}
	if len(p.AllowCIDRs) == 0 || len(p.RouteCIDRs) == 0 {
		return errors.New("explicit destination and route policy required")
	}
	for _, v := range []string{p.CA, p.Cert, p.Key} {
		if !filepath.IsAbs(v) {
			return errors.New("absolute credential paths required")
		}
	}
	if e = os.Mkdir(out, 0700); e != nil {
		return e
	}
	stls := M{"enabled": true, "min_version": "1.3", "certificate_path": p.Cert, "key_path": p.Key}
	hy := M{"type": "hysteria2", "tag": "hy2", "listen": "0.0.0.0", "listen_port": p.QUICPort, "users": []M{{"name": "entry", "password": p.Password}}, "tls": stls}
	reality := M{"enabled": true, "handshake": M{"server": p.HandshakeServer, "server_port": p.HandshakePort}, "private_key": p.PrivateKey, "short_id": []string{p.ShortID}}
	vl := M{"type": "vless", "tag": "reality", "listen": "0.0.0.0", "listen_port": p.TCPPort, "users": []M{{"uuid": p.UUID, "flow": "xtls-rprx-vision"}}, "tls": M{"enabled": true, "server_name": p.ServerName, "reality": reality}}
	server := M{"log": M{"level": "warn"}, "inbounds": []M{hy, vl}, "outbounds": []M{{"type": "direct", "tag": "egress"}}, "route": M{"rules": []M{{"ip_cidr": p.AllowCIDRs, "action": "route", "outbound": "egress"}, {"action": "reject"}}}}
	hyout := M{"type": "hysteria2", "tag": "hy2", "server": p.ServerIP, "server_port": p.QUICPort, "password": p.Password, "tls": M{"enabled": true, "min_version": "1.3", "server_name": p.ServerName, "certificate_path": p.CA}}
	vlout := M{"type": "vless", "tag": "reality", "server": p.ServerIP, "server_port": p.TCPPort, "uuid": p.UUID, "flow": "xtls-rprx-vision", "packet_encoding": "xudp", "tls": M{"enabled": true, "server_name": p.ServerName, "utls": M{"enabled": true, "fingerprint": "chrome"}, "reality": M{"enabled": true, "public_key": p.PublicKey, "short_id": p.ShortID}}}
	tun := M{"type": "tun", "tag": "tun", "netns": p.Namespace, "interface_name": "ngt0", "address": []string{"172.29.250.1/30", "fd29:250::1/126"}, "mtu": 1400, "auto_route": true, "strict_route": true, "dns_mode": "disabled", "route_address": p.RouteCIDRs, "stack": "system"}
	client := M{"log": M{"level": "warn"}, "inbounds": []M{tun}, "outbounds": []M{{"type": "urltest", "tag": "auto", "outbounds": []string{"hy2", "reality"}, "url": p.HealthURL, "interval": "5s", "tolerance": 100, "interrupt_exist_connections": false}, hyout, vlout}, "dns": M{"servers": []M{{"type": "udp", "tag": "remote", "server": p.DNS, "detour": "auto"}}}, "route": M{"auto_detect_interface": true, "rules": []M{{"port": 53, "action": "hijack-dns"}}, "final": "auto"}}
	if e = write(filepath.Join(out, "server.json"), server); e != nil {
		return e
	}
	return write(filepath.Join(out, "client.json"), client)
}
func Verify(binary, digest string) error {
	if !filepath.IsAbs(binary) {
		return errors.New("absolute engine binary path required")
	}
	s, e := os.Lstat(binary)
	if e != nil {
		return e
	}
	if !s.Mode().IsRegular() || s.Mode().Perm()&0022 != 0 {
		return errors.New("engine must be a regular file not writable by group/others")
	}
	if s.Size() > 256<<20 {
		return errors.New("engine exceeds 256 MiB")
	}
	f, e := os.Open(binary)
	if e != nil {
		return e
	}
	defer f.Close()
	sum := sha256.New()
	if _, e = io.Copy(sum, f); e != nil {
		return e
	}
	if len(digest) != 64 || hex.EncodeToString(sum.Sum(nil)) != strings.ToLower(digest) {
		return errors.New("engine SHA256 mismatch")
	}
	return nil
}
func Execute(ctx context.Context, binary, digest, config string, check bool) error {
	if e := Verify(binary, digest); e != nil {
		return e
	}
	if !filepath.IsAbs(config) {
		return errors.New("absolute engine config path required")
	}
	action := "run"
	if check {
		action = "check"
	}
	cmd := exec.CommandContext(ctx, binary, action, "-c", config)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if ctx.Err() != nil {
		return nil
	}
	return err
}
