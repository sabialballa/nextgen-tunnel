package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"nextgen-tunnel/internal/config"
	"nextgen-tunnel/internal/engine"
	"nextgen-tunnel/internal/manager"
	"nextgen-tunnel/internal/security"
	"nextgen-tunnel/internal/transport"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

var version = "0.3.0-rc3"

func main() {
	if err := run(os.Args[1:]); err != nil {
		slog.Error("command failed", "error", err)
		os.Exit(1)
	}
}
func run(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: nextgen-tunnel run|check|probe|status|menu -config FILE; pki -dir DIR; version")
	}
	if args[0] == "version" {
		fmt.Println(version)
		return nil
	}
	if strings.HasPrefix(args[0], "engine-") {
		f := flag.NewFlagSet(args[0], flag.ContinueOnError)
		dir := f.String("dir", "", "new private directory")
		ip := f.String("server-ip", "", "literal peer IP")
		name := f.String("server-name", "tunnel.internal", "TLS server identity")
		profile := f.String("profile", "", "private profile JSON")
		out := f.String("output", "", "new output directory")
		binary := f.String("binary", "", "absolute external engine path")
		digest := f.String("sha256", "", "trusted engine digest")
		cfg := f.String("config", "", "absolute engine config path")
		redundancy := f.String("redundancy-config", "", "optional loopback WireGuard redundancy configuration")
		if e := f.Parse(args[1:]); e != nil {
			return e
		}
		switch args[0] {
		case "engine-init":
			return engine.Init(*dir, *ip, *name)
		case "engine-plan":
			return engine.Plan(*profile, *out)
		case "engine-check", "engine-run":
			if *redundancy != "" {
				c, e := engine.LoadRedundancy(*redundancy)
				if e != nil {
					return e
				}
				if args[0] == "engine-run" {
					relay, e := engine.StartRedundancy(c)
					if e != nil {
						return e
					}
					defer relay.Close()
				}
			}
			ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer cancel()
			return engine.Execute(ctx, *binary, *digest, *cfg, args[0] == "engine-check")
		default:
			return errors.New("unknown engine command")
		}
	}
	if args[0] == "pki" {
		f := flag.NewFlagSet("pki", flag.ContinueOnError)
		dir := f.String("dir", "", "new private directory")
		server := f.String("server-name", "tunnel.internal", "server DNS identity")
		client := f.String("client-name", "entry", "authorized client identity")
		if e := f.Parse(args[1:]); e != nil {
			return e
		}
		return security.InitPKI(*dir, *server, *client)
	}
	f := flag.NewFlagSet(args[0], flag.ContinueOnError)
	path := f.String("config", "", "absolute or relative config file")
	if e := f.Parse(args[1:]); e != nil {
		return e
	}
	c, e := config.Load(*path)
	if e != nil {
		return e
	}
	if args[0] == "menu" {
		return menu(*path, c)
	}
	if args[0] == "status" {
		return status(c)
	}
	t, e := security.Load(c)
	if e != nil {
		return e
	}
	switch args[0] {
	case "check":
		fmt.Println("configuration and TLS material loaded; network connectivity not tested")
		return nil
	case "probe":
		if c.Role != "client" {
			return errors.New("probe requires client config")
		}
		failed := false
		for _, ep := range c.Endpoints {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			start := time.Now()
			e := manager.Probe(ctx, ep, t)
			cancel()
			fmt.Printf("%s %s healthy=%t elapsed_ms=%.3f\n", ep.Name, ep.Protocol, e == nil, float64(time.Since(start).Microseconds())/1000)
			if e != nil {
				failed = true
			}
		}
		if failed {
			return errors.New("one or more encrypted probes failed")
		}
		return nil
	case "run":
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()
		if c.Role == "server" {
			s, e := transport.Listen(c, t)
			if e != nil {
				return e
			}
			slog.Info("server listening", "address", c.Listen)
			return s.Run(ctx)
		}
		cl, e := manager.ListenClient(c, manager.New(c.Endpoints, t))
		if e != nil {
			return e
		}
		defer cl.Close()
		slog.Info("client listening", "forward_count", len(c.Forwards))
		return cl.Run(ctx)
	default:
		return errors.New("unknown command")
	}
}
func status(c config.Config) error {
	if c.StatusFile == "" {
		return errors.New("status_file not configured")
	}
	b, e := os.ReadFile(c.StatusFile)
	if e != nil {
		return e
	}
	var s manager.Status
	if e = json.Unmarshal(b, &s); e != nil {
		return e
	}
	fmt.Println(string(b))
	if time.Since(s.Time) > 10*time.Second {
		return errors.New("status is stale")
	}
	if !s.Running {
		return errors.New("client is stopped")
	}
	if s.Selected == "" {
		return errors.New("no healthy transport")
	}
	return nil
}
func menu(path string, c config.Config) error {
	r := bufio.NewScanner(os.Stdin)
	for {
		fmt.Println("NEXTGEN TUNNEL\n1. Validate configuration\n2. Probe encrypted paths\n3. Read status\n0. Exit")
		if !r.Scan() {
			return r.Err()
		}
		var e error
		switch strings.TrimSpace(r.Text()) {
		case "0":
			return nil
		case "1":
			e = run([]string{"check", "-config", path})
		case "2":
			e = run([]string{"probe", "-config", path})
		case "3":
			e = status(c)
		default:
			fmt.Println("Invalid option")
			continue
		}
		if e != nil {
			fmt.Println("ERROR:", e)
		}
	}
}
