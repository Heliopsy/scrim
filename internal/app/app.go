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

	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/notify"
	"github.com/heliopsy/scrim/internal/obs"
	"github.com/heliopsy/scrim/internal/policy"
	"github.com/heliopsy/scrim/internal/state"
	"github.com/heliopsy/scrim/internal/stores"
)

// App is the running control plane's components.
type App struct {
	Config   *config.Holder
	Log      *slog.Logger
	Scrubber *obs.ScrubberSlot
	Metrics  *obs.Metrics
	Health   *obs.Health
	State    state.Store
	Stores   *stores.Set
	Policy   policy.Engine
	Notifier notify.Notifier
}

// New builds the components from cfg. Log output goes to logw.
func New(ctx context.Context, cfg *config.Config, logw io.Writer) (*App, error) {
	a := &App{
		Config:   config.NewHolder(cfg),
		Scrubber: &obs.ScrubberSlot{},
		Metrics:  obs.NewMetrics(),
		Health:   obs.NewHealth(),
		Stores:   stores.NewSet(),
		Notifier: notify.Multi{},
	}
	a.Health.Scrubber = a.Scrubber

	log, err := obs.LoggerFromConfig(logw, cfg, a.Scrubber)
	if err != nil {
		return nil, err
	}
	a.Log = log
	for _, e := range cfg.Weakened() {
		a.Log.Warn("weakened protection active", "setting", e.Setting.Key, "source", e.Source.String())
	}

	effect, err := policy.ParseEffect(policy.DefaultEffect.Get(cfg))
	if err != nil {
		return nil, err
	}
	a.Policy = policy.Static{Effect: effect}

	if a.State, err = state.Open(ctx, cfg); err != nil {
		return nil, err
	}
	if err := a.State.Migrate(ctx); err != nil {
		_ = a.State.Close()
		return nil, fmt.Errorf("state: migrate: %w", err)
	}
	a.Health.Live("process", func(context.Context) error { return nil })
	a.Health.Ready("state", a.State.Health)
	return a, nil
}

// Close releases everything New opened.
func (a *App) Close() error {
	var errs []error
	if a.Stores != nil {
		errs = append(errs, a.Stores.Close())
	}
	if a.State != nil {
		errs = append(errs, a.State.Close())
	}
	return errors.Join(errs...)
}
