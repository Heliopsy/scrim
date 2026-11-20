// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"

	"github.com/heliopsy/scrim/internal/config"
)

// DefaultRoutes are the LLM proxy's path prefixes per provider family.
var DefaultRoutes = map[string]string{"anthropic": "/anthropic", "openai": "/openai"}

// RunEndpoints is what a daemon offers an agent started by `scrim run`.
// None of it is secret.
type RunEndpoints struct {
	// APISocket is the agent API socket.
	APISocket string
	// LLMBaseURL is the base URL listener, for example http://127.0.0.1:9790.
	LLMBaseURL string
	// Routes maps a provider family to its path prefix on LLMBaseURL.
	Routes map[string]string
	// ForwardProxy is the forward proxy as an http:// URL, or empty.
	ForwardProxy string
	// CACertPEM is the tool-proxy CA clients must trust (two certificates
	// during a rotation's overlap).
	CACertPEM []byte
	// Bypass lists loopback upstreams the agent must reach directly.
	Bypass []string
}

// Lease is one `scrim run`'s use of a daemon: a shared one found running,
// or one started in this process for the run.
type Lease struct {
	cfg  *config.Config
	info Info
	own  *Daemon
	ca   []byte
}

// Acquire reuses the daemon behind o's admin.url or starts one in this
// process, and returns once it is ready.
func Acquire(ctx context.Context, o Options) (*Lease, error) {
	cfg, err := config.Build(o.Config)
	if err != nil {
		return nil, err
	}
	info, d, err := Ensure(ctx, o)
	if err != nil {
		return nil, err
	}
	l := &Lease{cfg: cfg, info: info, own: d}
	if !info.Ready {
		_ = l.Release(context.WithoutCancel(ctx))
		return nil, fmt.Errorf("daemon %d is not ready: %v", info.PID, info.Problems)
	}
	if d != nil {
		l.ca = []byte(d.TrustBundlePEM())
	} else if pem, err := TrustBundle(ctx, cfg); err == nil {
		l.ca = pem
	}
	if info.Addrs.ForwardProxy != "" && len(l.ca) == 0 {
		_ = l.Release(context.WithoutCancel(ctx))
		return nil, errors.New("the daemon runs a forward proxy but reports no CA certificate to trust")
	}
	return l, nil
}

// Endpoints says where the agent reaches the daemon.
func (l *Lease) Endpoints() RunEndpoints {
	a := l.info.Addrs
	if l.own != nil {
		a = l.own.Addrs()
	}
	ep := RunEndpoints{APISocket: a.AgentAPI, LLMBaseURL: a.BaseURL, Routes: maps.Clone(DefaultRoutes),
		CACertPEM: slices.Clone(l.ca), Bypass: slices.Clone(l.info.Bypass)}
	if a.ForwardProxy != "" {
		ep.ForwardProxy = "http://" + a.ForwardProxy
	}
	return ep
}

// Ready returns nil while the daemon serves traffic with a snapshot applied.
func (l *Lease) Ready(ctx context.Context) error {
	if l.own != nil {
		if !l.own.Ready(ctx) {
			return fmt.Errorf("scrim is not ready: %v", l.own.Info().Problems)
		}
		return nil
	}
	in, err := Connect(ctx, l.cfg)
	if err != nil {
		return err
	}
	if !in.Ready {
		return fmt.Errorf("scrim is not ready: %v", in.Problems)
	}
	return nil
}

// Release ends the run's use: a daemon started for the run stops, a shared
// one keeps running.
func (l *Lease) Release(ctx context.Context) error {
	if l.own == nil {
		return nil
	}
	d := l.own
	l.own = nil
	return d.Shutdown(ctx)
}

// Shared reports whether the lease reuses a daemon that runs on its own.
func (l *Lease) Shared() bool { return l.own == nil }
