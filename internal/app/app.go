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
	"sync"
	"time"

	"github.com/heliopsy/scrim/internal/audit"
	"github.com/heliopsy/scrim/internal/audit/sinks"
	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/dataplane"
	"github.com/heliopsy/scrim/internal/events"
	"github.com/heliopsy/scrim/internal/notify"
	"github.com/heliopsy/scrim/internal/obs"
	"github.com/heliopsy/scrim/internal/policy"
	"github.com/heliopsy/scrim/internal/ratelimit"
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
	// Events follows the state outbox and wakes the policy components when
	// another replica changes something; RunPolicy runs it.
	Events *events.Bus
	// AuditSinks feeds the external audit sinks (audit.sinks) from the
	// state backend's audit tap; empty when only db is configured.
	AuditSinks *audit.Fanout
	// RateLimits enforces the per-agent limits (ratelimit.*).
	RateLimits *ratelimit.Set

	sinkTargets []audit.Target

	configs *configDigests
	stop    context.CancelFunc
	// SnapshotSource builds data plane snapshots; nil sends an empty one.
	SnapshotSource dataplane.SnapshotFunc

	valuesMu   sync.Mutex
	valuesSubs map[int]func(store string)
	valuesNext int
}

// OnValuesChange calls fn with the store's name after every change to a
// store's value set (load, refresh, write, expiry) and returns a function
// that removes it. fn runs on the refresher's goroutine and must not block.
func (a *App) OnValuesChange(fn func(store string)) (cancel func()) {
	a.valuesMu.Lock()
	defer a.valuesMu.Unlock()
	if a.valuesSubs == nil {
		a.valuesSubs = map[int]func(string){}
	}
	id := a.valuesNext
	a.valuesNext++
	a.valuesSubs[id] = fn
	return func() {
		a.valuesMu.Lock()
		defer a.valuesMu.Unlock()
		delete(a.valuesSubs, id)
	}
}

func (a *App) valuesChanged(store string) {
	a.valuesMu.Lock()
	subs := make([]func(string), 0, len(a.valuesSubs))
	for _, fn := range a.valuesSubs {
		subs = append(subs, fn)
	}
	a.valuesMu.Unlock()
	for _, fn := range subs {
		fn(store)
	}
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
	if obs.MetricsEnabled.Get(cfg) {
		a.Instruments = obs.NewInstruments(a.Metrics, a.Scrubber)
	} else {
		a.Instruments = obs.DisabledInstruments()
	}
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

	if err := events.CheckReplicas(cfg); err != nil {
		return nil, err
	}
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
	if err := a.initAuditSinks(cfg); err != nil {
		_ = a.State.Close()
		return nil, err
	}
	if a.RateLimits, err = ratelimit.FromConfig(cfg, a.Instruments); err != nil {
		_ = a.closeAuditSinks()
		_ = a.State.Close()
		return nil, err
	}
	a.Config.Subscribe(func(_, cur *config.Config) { a.RateLimits.SetLimits(ratelimit.Limits(cur)) })
	if err := a.initEvents(ctx, cfg); err != nil {
		_ = a.closeAuditSinks()
		_ = a.State.Close()
		return nil, err
	}
	if err := a.initPolicy(ctx, cfg); err != nil {
		_ = a.closeAuditSinks()
		_ = a.State.Close()
		return nil, fmt.Errorf("policy: %w", err)
	}
	a.Health.Live("process", func(context.Context) error { return nil })
	a.Health.Ready("state", a.State.Health)

	opened, err := storeconfig.OpenWith(ctx, cfg, stores.DefaultRegistry, storeconfig.Options{
		OnChange: a.valuesChanged,
		OnStatus: func(st refresh.Status) {
			a.Instruments.StoreHealth(st.Store, st.Healthy, st.LastSuccess, st.Values, st.State == refresh.StateDegraded)
			a.Instruments.StoreRefresh(st.Store, st.LastDuration, st.LastError != "")
		},
	})
	if err != nil {
		_ = a.closeAuditSinks()
		_ = a.State.Close()
		return nil, err
	}
	a.Stores, a.Refreshers = opened.Set, opened.Refreshers
	if a.PolicyParts != nil && a.PolicyParts.Gate != nil {
		a.PolicyParts.Gate.Labels = a.SecretLabels
	}
	for _, r := range a.Refreshers {
		// Not ready until the store's first load: requests that depend on
		// it are refused rather than forwarded with a partial redaction set.
		a.Health.Ready("store "+r.Store(), r.Ready)
	}
	runCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	a.stop = cancel
	a.AuditSinks.Start(runCtx)
	go func() {
		if err := a.Config.Run(runCtx); err != nil {
			a.Log.Warn("configuration watch stopped", "err", err)
		}
	}()
	return a, nil
}

// SecretLabels is the label set policy sees for the secret ref names
// (refresh.SecretLabels over the configured stores).
func (a *App) SecretLabels(ctx context.Context, ref stores.Ref) (map[string]string, error) {
	if a.Stores == nil {
		return nil, nil
	}
	return refresh.SecretLabels(ctx, a.Stores, a.Refreshers, ref)
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
	errs = append(errs, a.closeAuditSinks(), a.RateLimits.Close())
	if a.State != nil {
		errs = append(errs, a.State.Close())
	}
	return errors.Join(errs...)
}

// initAuditSinks builds the external audit sinks and taps the state
// backend: every write transaction that appends audit entries reserves room
// for them on the block-policy sinks before it commits (and is refused when
// there is none within the sink's timeout), and queues them on every sink
// once it has committed.
func (a *App) initAuditSinks(cfg *config.Config) error {
	targets, err := sinks.Targets(cfg)
	if err != nil {
		return err
	}
	a.sinkTargets = targets
	a.AuditSinks = audit.NewFanout(audit.FanoutOptions{Scrub: a.Scrubber.Scrub, Observer: a.Instruments,
		Log: obs.WithComponent(a.Log, "audit")}, targets...)
	if a.AuditSinks.Empty() {
		return nil
	}
	tap, ok := a.State.(state.AuditTap)
	if !ok {
		sinks.CloseAll(targets)
		return fmt.Errorf("audit.sinks: state backend %s cannot feed external audit sinks", a.State.Backend())
	}
	fan := a.AuditSinks
	tap.SetAuditTap(func(ctx context.Context, entries []audit.Entry) (func(bool), error) {
		r, err := fan.Reserve(ctx, len(entries))
		if err != nil {
			return nil, err
		}
		return func(committed bool) {
			if committed {
				r.Commit(entries)
			} else {
				r.Cancel()
			}
		}, nil
	})
	return nil
}

// closeAuditSinks drains the external sinks for up to ten seconds; what
// they did not take is counted and logged by the fanout.
func (a *App) closeAuditSinks() error {
	if a.AuditSinks.Empty() {
		return nil
	}
	if tap, ok := a.State.(state.AuditTap); ok {
		tap.SetAuditTap(nil)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := a.AuditSinks.Close(ctx)
	sinks.CloseAll(a.sinkTargets)
	return err
}
