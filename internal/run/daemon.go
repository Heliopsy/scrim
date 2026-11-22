// SPDX-License-Identifier: AGPL-3.0-only

package run

import (
	"context"
	"errors"
)

// Provider families the LLM proxy serves on its base URL.
const (
	ProviderAnthropic = "anthropic"
	ProviderOpenAI    = "openai"
	ProviderGemini    = "gemini"
)

// DefaultRoutes are the LLM proxy's default path prefixes per provider.
var DefaultRoutes = map[string]string{ProviderAnthropic: "/anthropic", ProviderOpenAI: "/openai", ProviderGemini: "/gemini"}

// Endpoints is what a running scrim offers an agent. None of it is secret.
type Endpoints struct {
	// APISocket is the local agent API's Unix socket.
	APISocket string
	// LLMBaseURL is the LLM proxy's base URL listener, for example
	// http://127.0.0.1:9790. Required: an agent is never started without it.
	LLMBaseURL string
	// Routes maps a provider family to its path prefix on LLMBaseURL. Nil
	// takes DefaultRoutes.
	Routes map[string]string
	// ForwardProxy is the forward proxy (tool proxy and provider hosts) as
	// an http:// URL, or empty when it is not running. With it, tool
	// traffic goes through scrim for injection and response redaction.
	ForwardProxy string
	// CACertPEM is the forward proxy's public CA certificate (or
	// certificates during a rotation). Required with ForwardProxy.
	CACertPEM []byte
	// Bypass lists chained local upstreams (host or host:port, for example
	// caveman on 127.0.0.1:8787) that the agent must reach directly, never
	// through the forward proxy, so traffic does not loop.
	Bypass []string
}

// route returns the prefix for provider.
func (e Endpoints) route(provider string) string {
	if e.Routes != nil {
		if p, ok := e.Routes[provider]; ok {
			return p
		}
	}
	return DefaultRoutes[provider]
}

// Daemon starts or finds the scrim that serves an agent. The real one lives
// in internal/daemon; tests use a fake.
type Daemon interface {
	// Ensure returns a running scrim, reusing one that already runs for
	// this user or starting one. It returns only once the data plane is
	// ready to redact, and fails otherwise.
	Ensure(ctx context.Context) (Instance, error)
}

// Instance is one scrim serving this run.
type Instance interface {
	// Endpoints says where the agent reaches scrim.
	Endpoints() Endpoints
	// Ready returns nil while the data plane serves traffic with a snapshot
	// applied.
	Ready(ctx context.Context) error
	// Release ends this run's use of the instance. An instance the run
	// started itself stops; a shared one keeps running.
	Release(ctx context.Context) error
}

// ErrNoDaemon is returned by Unavailable.
var ErrNoDaemon = errors.New("no scrim daemon is available to this command")

// Unavailable is a Daemon that never starts: scrim run then refuses to
// start the agent.
type Unavailable struct {
	// Reason says why, shown to the user.
	Reason string
}

// Ensure implements Daemon.
func (u Unavailable) Ensure(context.Context) (Instance, error) {
	if u.Reason == "" {
		return nil, ErrNoDaemon
	}
	return nil, errors.New(u.Reason)
}

// Static is an Instance with fixed endpoints and a readiness check, for a
// scrim managed elsewhere and for tests.
type Static struct {
	EP      Endpoints
	ReadyFn func(context.Context) error
	// OnRelease runs on Release. Optional.
	OnRelease func(context.Context) error
}

// Endpoints implements Instance.
func (s *Static) Endpoints() Endpoints { return s.EP }

// Ready implements Instance.
func (s *Static) Ready(ctx context.Context) error {
	if s.ReadyFn == nil {
		return nil
	}
	return s.ReadyFn(ctx)
}

// Release implements Instance.
func (s *Static) Release(ctx context.Context) error {
	if s.OnRelease == nil {
		return nil
	}
	return s.OnRelease(ctx)
}

// Fixed is a Daemon that always returns the same instance.
type Fixed struct{ Instance Instance }

// Ensure implements Daemon.
func (f Fixed) Ensure(ctx context.Context) (Instance, error) {
	if err := f.Instance.Ready(ctx); err != nil {
		return nil, err
	}
	return f.Instance, nil
}
