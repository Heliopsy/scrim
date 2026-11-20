// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"context"
	"fmt"
	"time"

	"github.com/heliopsy/scrim/internal/state"
	"github.com/heliopsy/scrim/internal/status"
)

// Runtime is what the running daemon protects, for `scrim status` and
// `scrim doctor` (specs/interception "Doctor and status report
// protections"). It is built from the listeners actually bound and the
// sessions actually open, never from configuration alone.
type Runtime struct {
	Profile      string              `json:"profile"`
	Interception []string            `json:"interception_modes"`
	Providers    []status.Provider   `json:"providers"`
	Protections  []status.Protection `json:"protections"`
	// Sessions counts open `scrim run` sessions.
	Sessions int `json:"sessions"`
}

// runtimeInfo derives the runtime report.
func (d *Daemon) runtimeInfo(ctx context.Context, ready bool) Runtime {
	cfg := d.app.Config.Current()
	a := d.Addrs()
	rt := Runtime{Profile: cfg.Profile()}
	sessions := d.openSessions(ctx)
	rt.Sessions = sessions
	dpUp := ready && d.dpReady.Load()
	if dpUp {
		if a.BaseURL != "" {
			rt.Interception = append(rt.Interception, "base-url "+a.BaseURL)
		}
		if a.BaseURLSocket != "" {
			rt.Interception = append(rt.Interception, "base-url unix:"+a.BaseURLSocket)
		}
		if a.ForwardProxy != "" {
			rt.Interception = append(rt.Interception, "forward-proxy http://"+a.ForwardProxy)
		}
		if a.ToolProxy != "" {
			rt.Interception = append(rt.Interception, "tool-proxy "+a.ToolProxy)
		}
		if sessions > 0 {
			rt.Interception = append(rt.Interception, fmt.Sprintf("wrapper (%d scrim run session(s))", sessions))
		}
	}
	for _, r := range routes(cfg) {
		up := r.GetUpstream()
		if c := r.GetChain(); c != nil {
			up = c.GetUrl() + " -> " + up
		}
		rt.Providers = append(rt.Providers, status.Provider{Name: r.GetName(), Upstream: up})
	}
	// A store target with 0 values protects nothing: redaction is not
	// reported active while one exists.
	empty := emptyTargets(d.storeStatus())
	bg := d.app.PolicyParts.BreakGlass.Active()
	rt.Protections = []status.Protection{
		{Name: "redaction", Active: dpUp && len(empty) == 0, Detail: redactionDetail(dpUp, empty)},
		{Name: "credential injection", Active: dpUp && (a.ForwardProxy != "" || a.ToolProxy != "") && !bg,
			Detail: detail(a.ForwardProxy != "" || a.ToolProxy != "", "through the tool proxy toward bound hosts", "no forward or tool proxy listener: tools never receive injected credentials")},
		{Name: "direct egress blocked", Active: false, Detail: "no enforcing interception mode (transparent, eBPF, network policy) is active; an agent can still reach providers directly"},
		{Name: "break-glass", Active: bg, Detail: detail(bg, "deny-all engaged: injection, grants and approvals are refused", "off")},
		{Name: "capture mode", Active: d.capture != "", Detail: detail(d.capture != "", "provider requests are written to "+d.capture, "off")},
	}
	return rt
}

func detail(ok bool, yes, no string) string {
	if ok {
		return yes
	}
	return no
}

func (d *Daemon) openSessions(ctx context.Context) int {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	n := 0
	now := time.Now()
	_ = d.app.State.View(ctx, func(tx state.Tx) error {
		ss, err := tx.ListSessions(ctx, state.SessionFilter{Open: true})
		if err != nil {
			return err
		}
		for _, s := range ss {
			if s.EndedAt.IsZero() && now.Before(s.ExpiresAt) {
				n++
			}
		}
		return nil
	})
	return n
}

// StatusRuntime is the daemon's runtime as a status.RuntimeSource.
func (in Info) StatusRuntime() status.RuntimeSource { return runtimeSource{in.Runtime} }

type runtimeSource struct{ r Runtime }

func (s runtimeSource) Profile() string                  { return s.r.Profile }
func (s runtimeSource) InterceptionModes() []string      { return s.r.Interception }
func (s runtimeSource) Providers() []status.Provider     { return s.r.Providers }
func (s runtimeSource) Protections() []status.Protection { return s.r.Protections }

// StatusDataPlane is the data plane as the daemon reports it.
func (in Info) StatusDataPlane() status.DataPlane {
	dp := status.DataPlane{Running: in.DataPlane != nil, Healthy: in.Ready}
	if in.DataPlane != nil {
		dp.Version = in.DataPlane.Version
		dp.Detail = fmt.Sprintf("snapshot %d, %d values, policy %s, served by scrim daemon %d", in.DataPlane.Snapshot,
			in.DataPlane.Values, in.DataPlane.PolicyEngine, in.PID)
	}
	if !in.Ready {
		dp.Detail = fmt.Sprintf("daemon %d not ready: %v", in.PID, in.Problems)
	}
	return dp
}
