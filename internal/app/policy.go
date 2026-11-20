// SPDX-License-Identifier: AGPL-3.0-only

package app

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/heliopsy/scrim/internal/approval"
	"github.com/heliopsy/scrim/internal/breakglass"
	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/gate"
	"github.com/heliopsy/scrim/internal/grant"
	"github.com/heliopsy/scrim/internal/notify"
	"github.com/heliopsy/scrim/internal/notify/ntfy"
	"github.com/heliopsy/scrim/internal/notify/terminal"
	"github.com/heliopsy/scrim/internal/notify/webhook"
	"github.com/heliopsy/scrim/internal/obs"
	"github.com/heliopsy/scrim/internal/policy"
	"github.com/heliopsy/scrim/internal/secret"
)

// Policy holds the policy, approval and grant components.
type Policy struct {
	Rules      *policy.Live
	BreakGlass *breakglass.Switch
	Grants     *grant.Service
	Approvals  *approval.Service
	Gate       *gate.Gate
	Notifiers  []notify.Notifier
}

// initPolicy builds the rule set, break-glass switch, grants, notifiers,
// approvals and the gate from cfg. It starts nothing; [App.RunPolicy] runs
// the background loops.
func (a *App) initPolicy(ctx context.Context, cfg *config.Config) error {
	pc, err := policy.FromConfig(cfg)
	if err != nil {
		return err
	}
	live, err := policy.NewLive(pc)
	if err != nil {
		return err
	}
	bg, err := breakglass.New(ctx, a.State, breakglass.DenyAll.Get(cfg))
	if err != nil {
		return err
	}
	resolve := func(ref config.SecretRef) (secret.Value, error) { return cfg.ResolveRef(ctx, ref) }
	signer := approval.RandomSigner()
	if key, ok := cfg.Secret(approval.SigningKey); ok {
		if signer, err = approval.NewSigner("k1", map[string]secret.Value{"k1": key}); err != nil {
			return fmt.Errorf("approvals.signing-key: %w", err)
		}
	} else if a.State.Backend() != "memory" {
		a.Log.Warn("approvals.signing-key is not set: decision links stop working on restart and on other replicas")
	}
	limits := func(gs policy.GrantSettings) grant.Limits { return grant.LimitsFor(a.Config.Current(), gs) }
	p := &Policy{Rules: live, BreakGlass: bg, Grants: grant.NewService(a.State, bg)}

	if terminal.Enabled.Get(cfg) {
		p.Notifiers = append(p.Notifiers, &terminal.Notifier{W: os.Stderr})
	}
	if n, ok, err := ntfy.FromConfig(cfg, resolve); err != nil {
		return err
	} else if ok {
		p.Notifiers = append(p.Notifiers, n)
	}
	var settle webhook.SettlerFunc = func(ctx context.Context, id, tok string) error {
		return p.Approvals.SettleToken(ctx, id, tok)
	}
	if u := webhook.URL.Get(cfg); u != "" {
		o := webhook.Options{URL: u, Hold: webhook.Hold.Get(cfg), PollInterval: webhook.PollInterval.Get(cfg),
			Settler: settle, TokenFromLink: approval.TokenFromLink, Log: a.Log}
		if v, ok := cfg.Secret(webhook.Secret); ok {
			o.Secret = v
		} else if webhook.Secret.Get(cfg) != "" {
			return errors.New("notify.webhook.secret is set but could not be resolved")
		}
		n, err := webhook.New(o)
		if err != nil {
			return err
		}
		p.Notifiers = append(p.Notifiers, n)
	}

	var metrics *obs.Metrics
	if obs.MetricsEnabled.Get(cfg) {
		metrics = a.Metrics
	}
	p.Approvals, err = approval.New(approval.Options{
		State: a.State, Notifiers: p.Notifiers, Signer: signer, BreakGlass: bg,
		PublicURL: approval.PublicURL.Get(cfg), Timeout: approval.Timeout.Get(cfg), PollInterval: approval.PollInterval.Get(cfg),
		Grants: func(rule string) (grant.Limits, policy.GrantSettings) {
			r, _ := live.Rule(rule)
			return limits(r.Grant), r.Grant
		},
		Log: a.Log, Metrics: metrics,
	})
	if err != nil {
		return err
	}
	bg.OnChange(func(active bool) {
		if active {
			if _, err := p.Approvals.DenyAllPending(context.Background(), "break-glass"); err != nil {
				a.Log.Error("denying pending approvals for break-glass", "err", err)
			}
		}
	})
	p.Gate = &gate.Gate{Engine: bg.Engine(live), Rules: live, Grants: p.Grants, Approvals: p.Approvals,
		BreakGlass: bg, State: a.State, Limits: limits, Log: a.Log}
	a.Policy = p.Gate.Engine
	a.Notifier = notify.Multi(p.Notifiers)
	a.PolicyParts = p
	// Hot reload: new rules are compiled and swapped in, or rejected with the
	// previous rules kept; policy.deny-all follows the configuration.
	a.Config.Subscribe(func(_, cur *config.Config) {
		pc, err := policy.FromConfig(cur)
		if err == nil {
			err = live.Reload(pc)
		}
		if err != nil {
			a.Log.Error("policy reload rejected; previous rules stay in force", "err", err)
		}
		bg.SetConfigured(breakglass.DenyAll.Get(cur))
	})
	a.Health.Ready("policy", func(context.Context) error {
		if _, err := live.Health(); err != nil {
			return fmt.Errorf("last policy reload rejected: %w", err)
		}
		return nil
	})
	return nil
}

// RunPolicy runs the approval sweeper and the break-glass refresh until ctx
// ends. The control plane server calls it; one-shot CLI commands do not.
func (a *App) RunPolicy(ctx context.Context) {
	p := a.PolicyParts
	if p == nil {
		return
	}
	go p.Approvals.Run(ctx, time.Second)
	p.BreakGlass.Run(ctx, breakglass.RefreshInterval.Get(a.Config.Current()), func(err error) {
		a.Log.Warn("break-glass refresh failed; keeping the last known state", "err", err)
	})
}
