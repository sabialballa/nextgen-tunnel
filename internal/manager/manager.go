package manager

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"errors"
	"io"
	"nextgen-tunnel/internal/config"
	"nextgen-tunnel/internal/transport"
	"sync"
	"time"
)

type State struct {
	Name      string    `json:"name"`
	Protocol  string    `json:"protocol"`
	Healthy   bool      `json:"healthy"`
	Failures  int       `json:"consecutive_failures"`
	Successes int       `json:"consecutive_successes"`
	RTTMS     float64   `json:"probe_rtt_ms"`
	RetryAt   time.Time `json:"retry_at"`
}
type Manager struct {
	mu         sync.Mutex
	endpoints  []config.Endpoint
	states     []State
	selected   int
	started    bool
	lastSwitch time.Time
	tls        *tls.Config
}

func New(ep []config.Endpoint, t *tls.Config) *Manager {
	m := &Manager{endpoints: ep, tls: t, selected: -1}
	for _, e := range ep {
		m.states = append(m.states, State{Name: e.Name, Protocol: e.Protocol})
	}
	return m
}
func Probe(ctx context.Context, e config.Endpoint, t *tls.Config) error {
	s, err := transport.Dial(ctx, e, t, transport.Request{Protocol: "probe"})
	if err != nil {
		return err
	}
	defer s.Close()
	_ = s.Stream.SetDeadline(time.Now().Add(3 * time.Second))
	stop := context.AfterFunc(ctx, func() { s.Close() })
	defer stop()
	var nonce, reply [32]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return err
	}
	if _, err = s.Stream.Write(nonce[:]); err != nil {
		return err
	}
	if _, err = io.ReadFull(s.Stream, reply[:]); err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(nonce[:], reply[:]) != 1 {
		return errors.New("invalid probe response")
	}
	return nil
}

// Record retains a working selected path, requires three consecutive failures
// to mark it down and two successes to recover. No opportunistic failback.
func (m *Manager) Record(i int, ok bool, rtt time.Duration, now time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := &m.states[i]
	if ok {
		s.Successes++
		s.Failures = 0
		s.RTTMS = float64(rtt.Microseconds()) / 1000
		s.RetryAt = time.Time{}
		if s.Successes >= 2 {
			s.Healthy = true
		}
	} else {
		s.Failures++
		s.Successes = 0
		if s.Failures >= 3 {
			s.Healthy = false
		}
		power := s.Failures
		if power > 5 {
			power = 5
		}
		s.RetryAt = now.Add(time.Second * time.Duration(1<<power))
	}
	if m.selected >= 0 && m.states[m.selected].Healthy {
		return
	}
	// Failed paths are never retained merely to satisfy a cooldown.
	for j := range m.states {
		if m.states[j].Healthy {
			m.selected = j
			m.started = true
			m.lastSwitch = now
			return
		}
		if !m.started && m.states[j].Failures == 0 {
			return
		}
	}
	m.selected = -1
}
func (m *Manager) Snapshot() (string, []State) {
	m.mu.Lock()
	defer m.mu.Unlock()
	name := ""
	if m.selected >= 0 {
		name = m.states[m.selected].Name
	}
	return name, append([]State(nil), m.states...)
}
func (m *Manager) Dial(ctx context.Context, req transport.Request) (*transport.Session, error) {
	m.mu.Lock()
	idx := m.selected
	m.mu.Unlock()
	if idx < 0 {
		return nil, errors.New("no healthy transport")
	}
	// Never replay application bytes or silently migrate established sessions.
	return transport.Dial(ctx, m.endpoints[idx], m.tls, req)
}
func (m *Manager) Run(ctx context.Context, interval time.Duration) {
	var wg sync.WaitGroup
	defer wg.Wait()
	for i, e := range m.endpoints {
		wg.Add(1)
		go func(i int, e config.Endpoint) {
			defer wg.Done()
			timer := time.NewTimer(0)
			defer timer.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-timer.C:
				}
				pc, cancel := context.WithTimeout(ctx, 5*time.Second)
				start := time.Now()
				err := Probe(pc, e, m.tls)
				cancel()
				now := time.Now()
				m.Record(i, err == nil, now.Sub(start), now)
				wait := interval
				m.mu.Lock()
				retry := m.states[i].RetryAt
				m.mu.Unlock()
				if d := time.Until(retry); d > wait {
					wait = d
				}
				var jitter [1]byte
				_, _ = rand.Read(jitter[:])
				wait += time.Duration(jitter[0]) * time.Millisecond
				timer.Reset(wait)
			}
		}(i, e)
	}
	<-ctx.Done()
}
