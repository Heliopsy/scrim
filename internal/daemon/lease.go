// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net"
	"os"
	"slices"
	"syscall"

	"github.com/heliopsy/scrim/internal/agentapi"
	"github.com/heliopsy/scrim/internal/approval"
	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/localapi"
	"github.com/heliopsy/scrim/internal/secret"
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
	// sys is the system service's agent API, set when the lease found the
	// daemon `scrim install --system` runs rather than this user's.
	sys *localapi.Client
}

// Acquire reuses the daemon behind o's admin.url or starts one in this
// process, and returns once it is ready. With nothing configured it looks
// for this user's daemon first (admin socket under $XDG_RUNTIME_DIR), then
// for the system service's agent API in /run/scrim, and only then starts
// one here.
func Acquire(ctx context.Context, o Options) (*Lease, error) {
	cfg, err := config.Build(o.Config)
	if err != nil {
		return nil, err
	}
	if useSystemService(cfg) {
		return acquireSystem(ctx, cfg)
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

// useSystemService reports whether the lease should use the system service:
// neither admin.url nor api.socket is configured, this user's admin socket
// does not exist, and the system service's agent API socket does.
func useSystemService(cfg *config.Config) bool {
	if approval.AdminURL.Get(cfg) != "" || agentapi.Socket.Get(cfg) != "" {
		return false
	}
	if _, err := os.Stat(approval.DefaultAdminSocket()); err == nil {
		return false
	}
	_, err := os.Stat(localapi.SystemSocketPath())
	return err == nil
}

// acquireSystem leases the system service through its agent API. The admin
// API is not used: it accepts only the service's own user and root, and the
// agent may be neither. A system service that does not answer is an error,
// not a reason to start a private daemon behind the operator's back.
func acquireSystem(ctx context.Context, cfg *config.Config) (*Lease, error) {
	sock := localapi.SystemSocketPath()
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", sock)
	if err != nil {
		if errors.Is(err, os.ErrPermission) || errors.Is(err, syscall.EACCES) {
			return nil, fmt.Errorf("the scrim system service at %s refuses this user: add it to the %s group (and log in again): %w",
				sock, localapi.SystemAgentGroup, err)
		}
		return nil, fmt.Errorf("the scrim system service at %s does not answer: %w", sock, err)
	}
	_ = conn.Close()
	c := localapi.NewClient(sock, secret.Value{})
	ep, err := c.Endpoints(ctx)
	if err != nil {
		c.Close()
		return nil, fmt.Errorf("the scrim system service at %s does not answer: %w", sock, err)
	}
	if !ep.Ready {
		c.Close()
		return nil, fmt.Errorf("the scrim system service is not ready: %v", ep.Problems)
	}
	l := &Lease{cfg: cfg, sys: c, ca: []byte(ep.CAPEM),
		info: Info{Ready: true, Bypass: ep.Bypass, Addrs: Addrs{AgentAPI: sock, BaseURL: ep.BaseURL, ForwardProxy: ep.ForwardProxy}}}
	if ep.ForwardProxy != "" && len(l.ca) == 0 {
		c.Close()
		return nil, errors.New("the scrim system service runs a forward proxy but reports no CA certificate to trust")
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
	if l.sys != nil {
		ep, err := l.sys.Endpoints(ctx)
		if err != nil {
			return err
		}
		if !ep.Ready {
			return fmt.Errorf("scrim is not ready: %v", ep.Problems)
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
	if l.sys != nil {
		l.sys.Close()
	}
	if l.own == nil {
		return nil
	}
	d := l.own
	l.own = nil
	return d.Shutdown(ctx)
}

// Shared reports whether the lease reuses a daemon that runs on its own.
func (l *Lease) Shared() bool { return l.own == nil }
