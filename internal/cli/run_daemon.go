// SPDX-License-Identifier: AGPL-3.0-only

package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/heliopsy/scrim/internal/daemon"
	agentrun "github.com/heliopsy/scrim/internal/run"
)

// runDaemonFor adapts internal/daemon to scrim run's Daemon contract.
func runDaemonFor(e *Env) agentrun.Daemon { return runDaemonAdapter{e: e} }

type runDaemonAdapter struct{ e *Env }

// Ensure reuses the daemon behind admin.url or starts one in this process.
// A daemon started here logs to $XDG_STATE_HOME/scrim/run-daemon.log, so
// its lines do not mix with the agent's terminal; operator notices (entry
// page links) still go to standard error.
func (a runDaemonAdapter) Ensure(ctx context.Context) (agentrun.Instance, error) {
	cfg, err := a.e.Config()
	if err != nil {
		return nil, err
	}
	logw := io.Discard
	closeLog := func() {}
	if dir, err := cfg.StateDir(); err == nil {
		if err := os.MkdirAll(dir, 0o700); err == nil {
			f, err := os.OpenFile(filepath.Join(dir, "run-daemon.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600) //nolint:gosec // fixed name in the state directory
			if err == nil {
				logw, closeLog = f, func() { _ = f.Close() }
			}
		}
	}
	l, err := daemon.Acquire(ctx, daemon.Options{Config: a.e.ConfigOptions(), LogOutput: logw, Notices: a.e.Stderr})
	if err != nil {
		closeLog()
		return nil, fmt.Errorf("scrim daemon: %w", err)
	}
	if l.Shared() {
		closeLog()
		closeLog = func() {}
	}
	return &runInstance{l: l, closeLog: closeLog}, nil
}

type runInstance struct {
	l        *daemon.Lease
	closeLog func()
}

func (r *runInstance) Endpoints() agentrun.Endpoints {
	ep := r.l.Endpoints()
	return agentrun.Endpoints{APISocket: ep.APISocket, LLMBaseURL: ep.LLMBaseURL, Routes: ep.Routes,
		ForwardProxy: ep.ForwardProxy, CACertPEM: ep.CACertPEM, Bypass: ep.Bypass}
}

func (r *runInstance) Ready(ctx context.Context) error { return r.l.Ready(ctx) }

func (r *runInstance) Release(ctx context.Context) error {
	err := r.l.Release(ctx)
	r.closeLog()
	return err
}
