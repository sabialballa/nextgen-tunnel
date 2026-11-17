package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
)

type TLS struct {
	CA         string `json:"ca"`
	Cert       string `json:"cert"`
	Key        string `json:"key"`
	ServerName string `json:"server_name"`
	ClientName string `json:"client_name"`
}
type Service struct {
	Protocol string `json:"protocol"`
	Target   string `json:"target"`
}
type Forward struct {
	Service  string `json:"service"`
	Protocol string `json:"protocol"`
	Listen   string `json:"listen"`
}
type Endpoint struct {
	Name     string `json:"name"`
	Protocol string `json:"protocol"`
	Address  string `json:"address"`
}
type Config struct {
	Role         string             `json:"role"`
	Listen       string             `json:"listen,omitempty"`
	TLS          TLS                `json:"tls"`
	Services     map[string]Service `json:"services,omitempty"`
	Forwards     []Forward          `json:"forwards,omitempty"`
	Endpoints    []Endpoint         `json:"endpoints,omitempty"`
	MaxSessions  int                `json:"max_sessions"`
	IdleSeconds  int                `json:"idle_seconds"`
	ProbeSeconds int                `json:"probe_seconds"`
	StatusFile   string             `json:"status_file,omitempty"`
}

var identifier = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$`)

func Address(s string, loopback bool) error {
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return errors.New("address must be literal IP:port")
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return errors.New("DNS endpoints are not accepted; use a literal IP and TLS server_name")
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return errors.New("invalid port")
	}
	if loopback && !ip.IsLoopback() {
		return errors.New("local forwards must bind to loopback")
	}
	return nil
}
func Load(path string) (Config, error) {
	var c Config
	f, e := os.Open(path)
	if e != nil {
		return c, e
	}
	defer f.Close()
	info, e := f.Stat()
	if e != nil {
		return c, e
	}
	if info.Size() > 1<<20 {
		return c, errors.New("configuration exceeds 1 MiB")
	}
	d := json.NewDecoder(io.LimitReader(f, 1<<20))
	d.DisallowUnknownFields()
	if e = d.Decode(&c); e != nil {
		return c, e
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return c, errors.New("trailing JSON data")
	}
	return c, c.Validate()
}
func (c Config) Validate() error {
	if c.Role != "server" && c.Role != "client" {
		return errors.New("role must be server or client")
	}
	if c.MaxSessions < 1 || c.MaxSessions > 4096 || c.IdleSeconds < 5 || c.IdleSeconds > 3600 || c.ProbeSeconds < 1 || c.ProbeSeconds > 300 {
		return errors.New("invalid session, idle or probe limits")
	}
	for _, p := range []string{c.TLS.CA, c.TLS.Cert, c.TLS.Key} {
		if !filepath.IsAbs(p) {
			return errors.New("TLS paths must be absolute")
		}
	}
	if c.Role == "server" {
		if e := Address(c.Listen, false); e != nil {
			return e
		}
		if !identifier.MatchString(c.TLS.ClientName) {
			return errors.New("server requires expected client_name")
		}
		if len(c.Services) == 0 || len(c.Services) > 128 {
			return errors.New("server requires 1..128 services")
		}
		for name, s := range c.Services {
			if !identifier.MatchString(name) || (s.Protocol != "tcp" && s.Protocol != "udp") {
				return errors.New("invalid service")
			}
			if e := Address(s.Target, false); e != nil {
				return e
			}
		}
	} else {
		if c.TLS.ServerName == "" {
			return errors.New("TLS server_name required")
		}
		if len(c.Endpoints) == 0 || len(c.Endpoints) > 8 || len(c.Forwards) == 0 || len(c.Forwards) > 128 {
			return errors.New("client requires 1..8 endpoints and 1..128 forwards")
		}
		names := map[string]bool{}
		for _, s := range c.Endpoints {
			if names[s.Name] || !identifier.MatchString(s.Name) || (s.Protocol != "tls" && s.Protocol != "quic") {
				return errors.New("invalid or duplicate endpoint")
			}
			names[s.Name] = true
			if e := Address(s.Address, false); e != nil {
				return e
			}
		}
		binds := map[string]bool{}
		for _, s := range c.Forwards {
			if !identifier.MatchString(s.Service) || (s.Protocol != "tcp" && s.Protocol != "udp") {
				return errors.New("invalid forward")
			}
			if e := Address(s.Listen, true); e != nil {
				return e
			}
			k := s.Protocol + s.Listen
			if binds[k] {
				return fmt.Errorf("duplicate listener")
			}
			binds[k] = true
		}
	}
	return nil
}
