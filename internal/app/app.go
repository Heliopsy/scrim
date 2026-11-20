// SPDX-License-Identifier: AGPL-3.0-only

// Package app is the composition root: it builds every long-lived component
// from the effective configuration and hands them to the commands. It holds
// no logic of its own; anything with behaviour belongs in its package.
//
// Backends and adapters are linked in by side-effect imports, one file per
// implementation (backend_<name>.go, store_<kind>.go), so adding one never
// touches another's file.
package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/dataplane"
	"github.com/heliopsy/scrim/internal/notify"
	"github.com/heliopsy/scrim/internal/obs"
	"github.com/heliopsy/scrim/internal/policy"
	"github.com/heliopsy/scrim/internal/state"
	"github.com/heliopsy/scrim/internal/stores"
	"github.com/heliopsy/scrim/internal/stores/refresh"
	"github.com/heliopsy/scrim/internal/stores/storeconfig"
	"github.com/heliopsy/scrim/internal/version"
)

// App is the running control plane's components.
type App struct {
	// Config owns the effective configuration and its hot reload.
	Config   *config.Manager
	Log      *slog.Logger
	Scrubber *obs.ScrubberSlot
	Metrics  *obs.Metrics
	Health   *obs.Health
	State    state.Store
	Stores   *stores.Set
	Policy   policy.Engine
	Notifier notify.Notifier
	// Refreshers keep each store's values for redaction and injection;
	// Start runs them.
	Refreshers []*refresh.Refresher
	// Instruments are the shared scrim metrics; Tracing the tracer.
	Instruments *obs.Instruments
	Tracing     *obs.Tracing
	// PolicyParts are the rule set, break-glass, grants, approvals and the
	// gate behind Policy.
	PolicyParts *Policy

	stop context.CancelFunc
	// SnapshotSource builds data plane snapshots; nil sends an empty one.
	SnapshotSource dataplane.SnapshotFunc
}

// New builds the components from the configuration opts names and starts
// watching it for reloads until Close. Log output goes to logw.
func New(ctx context.Context, opts config.Options, logw io.Writer) (*App, error) {
	a := &App{
		Scrubber: &obs.ScrubberSlot{},
		Metrics:  obs.NewMetrics(),
		Health:   obs.NewHealth(),
		Stores:   stores.NewSet(),
		Notifier: notify.Multi{},
	}
	a.Health.Scrubber = a.Scrubber
	a.Metrics.Scrubber = a.Scrubber

	// The logger's own settings come from a first build; the Manager then
	// builds the configuration it keeps and logs its warnings and every
	// weakened setting through that logger.
	boot, err := config.Build(opts)
	if err != nil {
		return nil, err
	}
	if a.Log, err = obs.LoggerFromConfig(logw, boot, a.Scrubber); err != nil {
		return nil, err
	}
	if a.Config, err = config.NewManager(opts, obs.WithComponent(a.Log, "config")); err != nil {
		return nil, err
	}
	cfg := a.Config.Current()
	a.Instruments = obs.NewInstruments(a.Metrics, a.Scrubber)
	weak := []string{}
	for _, w := range config.WeakenedSettings(cfg) {
		weak = append(weak, w.Key)
	}
	a.Instruments.Weakened(weak)
	if a.Tracing, err = obs.TracingFromConfig(cfg, version.Version, a.Scrubber); err != nil {
		return nil, err
	}

	effect, err := policy.ParseEffect(policy.DefaultEffect.Get(cfg))
	if err != nil {
		return nil, err
	}
	a.Policy = policy.Static{Effect: effect}

	if a.State, err = state.Open(ctx, cfg); err != nil {
		return nil, err
	}
	// SQL backends scrub every stored string and report transaction
	// durations.
	if in, ok := a.State.(interface {
		Instrument(sc interface{ Scrub(string) string }, observe func(string, time.Duration))
	}); ok {
		backend := a.State.Backend()
		in.Instrument(a.Scrubber, func(kind string, d time.Duration) { a.Instruments.StateTransaction(backend, kind, d) })
	}
	if err := a.State.Migrate(ctx); err != nil {
		_ = a.State.Close()
		return nil, fmt.Errorf("state: migrate: %w", err)
	}
	if err := a.initPolicy(ctx, cfg); err != nil {
		_ = a.State.Close()
		return nil, fmt.Errorf("policy: %w", err)
	}
	a.Health.Live("process", func(context.Context) error { return nil })
	a.Health.Ready("state", a.State.Health)

	opened, err := storeconfig.Open(ctx, cfg, stores.DefaultRegistry)
	if err != nil {
		_ = a.State.Close()
		return nil, err
	}
	a.Stores, a.Refreshers = opened.Set, opened.Refreshers
	for _, r := range a.Refreshers {
		// Not ready until the store's first load: requests that depend on
		// it are refused rather than forwarded with a partial redaction set.
		a.Health.Ready("store "+r.Store(), r.Ready)
	}
	runCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	a.stop = cancel
	go func() {
		if err := a.Config.Run(runCtx); err != nil {
			a.Log.Warn("configuration watch stopped", "err", err)
		}
	}()
	return a, nil
}

// Start runs every store refresher until ctx ends.
func (a *App) Start(ctx context.Context) {
	for _, r := range a.Refreshers {
		go r.Run(ctx)
	}
}

// Close releases everything New opened.
func (a *App) Close() error {
	if a.stop != nil {
		a.stop()
	}
	var errs []error
	if a.Tracing != nil {
		errs = append(errs, a.Tracing.Shutdown(context.Background()))
	}
	for _, r := range a.Refreshers {
		r.Close()
	}
	if a.Stores != nil {
		errs = append(errs, a.Stores.Close())
	}
	if a.State != nil {
		errs = append(errs, a.State.Close())
	}
	return errors.Join(errs...)
}
