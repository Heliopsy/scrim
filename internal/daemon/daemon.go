// SPDX-License-Identifier: AGPL-3.0-only

// Package daemon is the long-running scrim control plane (`scrim proxy`):
// it runs the composition root, supervises the data plane and keeps its
// snapshot current, and serves every control-plane socket.
//
//	              ┌────────────── control plane (this package) ──────────────┐
//	stores ──────▶│ refreshers ─┐                                            │
//	catalog ─────▶│ catalog ────┼─▶ SnapshotBuilder ─▶ pusher ─▶ Supervisor ─┼─▶ data plane
//	config ──────▶│ policy ─────┤        (debounced, on every change)        │   listeners:
//	keys, CA ────▶│ keys, CA ───┘                                            │   base URL, unix,
//	              │                                                          │   forward, tool proxy
//	              │ asks ◀── gate.Answer      captures ◀── store write       │◀── asks, captures,
//	              │ events ──▶ audit log + metrics                           │    events
//	              │                                                          │
//	              │ admin socket: approvals, grants, deny-all, /v1/daemon     │
//	              │ agent API socket + entry page, metrics + health          │
//	              └──────────────────────────────────────────────────────────┘
//
// The data plane refuses traffic until it holds a snapshot, and readiness
// stays false until then, so nothing is ever served unredacted. Start
// returns once every control-plane listener is bound; WaitReady waits for
// the data plane.
//
// `scrim run` uses [Ensure] to reuse a running daemon or start one in
// process, and [Daemon.Addrs] for the addresses it points the agent at.
package daemon

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/heliopsy/scrim/internal/agentapi"
	"github.com/heliopsy/scrim/internal/agentstore"
	"github.com/heliopsy/scrim/internal/app"
	"github.com/heliopsy/scrim/internal/approval"
	"github.com/heliopsy/scrim/internal/ca"
	"github.com/heliopsy/scrim/internal/catalog"
	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/dataplane"
	pb "github.com/heliopsy/scrim/internal/dataplane/dataplanev1"
	"github.com/heliopsy/scrim/internal/localapi"
	"github.com/heliopsy/scrim/internal/obs"
	"github.com/heliopsy/scrim/internal/placeholder"
	"github.com/heliopsy/scrim/internal/policy"
	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/status"
	"github.com/heliopsy/scrim/internal/stores"
	"github.com/heliopsy/scrim/internal/stores/refresh"
	"github.com/heliopsy/scrim/internal/version"
)

// Options configure Start.
type Options struct {
	// Config says where the configuration comes from.
	Config config.Options
	// LogOutput receives the daemon's logs; nil means os.Stderr.
	LogOutput io.Writer
	// Notices receives operator notices (entry-page links for
	// secret_ask_human); nil means LogOutput.
	Notices io.Writer
	// Capture, when set, turns on capture mode into this directory,
	// overriding proxy.capture.dir.
	Capture string
	// CA supplies the tool-proxy CA generations; nil uses the CA the
	// control plane keeps (tool-proxy.ca.*), opened by Start.
	CA func() []CAGeneration
	// CARun, when set, runs alongside the daemon and calls its argument
	// after every CA change (rotation), so a new snapshot is pushed.
	CARun func(ctx context.Context, changed func())
	// DataPlaneEnv is appended to the data plane's environment. For tests
	// that run a fake data plane.
	DataPlaneEnv []string
}

// Addrs are where the daemon serves. Empty fields are disabled.
type Addrs struct {
	// BaseURL is the LLM proxy base URL, for example http://127.0.0.1:9790.
	// Agents use BaseURL+"/anthropic" and BaseURL+"/openai/v1".
	BaseURL string `json:"base_url,omitempty"`
	// BaseURLSocket is the LLM proxy on a Unix socket.
	BaseURLSocket string `json:"base_url_socket,omitempty"`
	// ForwardProxy is host:port of the forward proxy (HTTPS_PROXY).
	ForwardProxy string `json:"forward_proxy,omitempty"`
	// ToolProxy is host:port of the tool proxy.
	ToolProxy string `json:"tool_proxy,omitempty"`
	// Transparent are host:port of the transparent listeners nftables
	// redirects covered users to.
	Transparent []string `json:"transparent,omitempty"`
	// SNI is host:port of the SNI listener of DNS override mode.
	SNI string `json:"sni,omitempty"`
	// AgentAPI is the agent local API socket (SCRIM_API_SOCKET).
	AgentAPI string `json:"agent_api,omitempty"`
	// EntryPage is the human entry page base URL.
	EntryPage string `json:"entry_page,omitempty"`
	// Admin is the admin API in admin.url form (unix:/path or http://host:port).
	Admin string `json:"admin,omitempty"`
	// Decision is the decision-link listener, host:port.
	Decision string `json:"decision,omitempty"`
	// Metrics is the metrics and health listener, host:port.
	Metrics string `json:"metrics,omitempty"`
}

// Info describes a running daemon. It holds no secret.
type Info struct {
	PID       int       `json:"pid"`
	Version   string    `json:"version"`
	StartedAt time.Time `json:"started_at"`
	// Ready is true while the data plane holds a snapshot and every
	// readiness check passes.
	Ready bool `json:"ready"`
	// Problems names the readiness checks that fail.
	Problems map[string]string `json:"problems,omitempty"`
	Addrs    Addrs             `json:"addrs"`
	// Capture is the capture directory while capture mode is on.
	Capture string `json:"capture,omitempty"`
	// Bypass lists loopback upstreams (a chained proxy, a local provider)
	// that agents must reach directly, never through the forward proxy, so
	// traffic does not loop.
	Bypass []string `json:"bypass,omitempty"`
	// DataPlane is what the data plane last reported, absent until it
	// answered once.
	DataPlane *DataPlaneInfo `json:"data_plane,omitempty"`
	// Runtime is what the daemon protects right now.
	Runtime Runtime `json:"runtime"`
	// Stores is every store's freshness and the values each redact target
	// holds.
	Stores []status.Store `json:"stores"`
	// AuditSinks is every external audit sink's queue and backpressure
	// state (audit.sinks beyond db).
	AuditSinks []status.AuditSink `json:"audit_sinks,omitempty"`
}

// DataPlaneInfo summarises the data plane's status. Counts and references,
// never values.
type DataPlaneInfo struct {
	Version         string   `json:"version,omitempty"`
	Snapshot        uint64   `json:"snapshot"`
	Values          uint32   `json:"values"`
	MemoryLocked    bool     `json:"memory_locked"`
	PolicyEngine    string   `json:"policy_engine,omitempty"`
	Matcher         string   `json:"matcher,omitempty"`
	Patterns        uint32   `json:"patterns,omitempty"`
	ShortValues     uint32   `json:"short_values,omitempty"`
	UnprotectedRefs []string `json:"unprotected_refs,omitempty"`
}

func dataPlaneInfo(st *pb.StatusResponse) *DataPlaneInfo {
	if st == nil {
		return nil
	}
	r := st.GetRedaction()
	return &DataPlaneInfo{Version: st.GetDataPlaneVersion(), Snapshot: st.GetAppliedSnapshotVersion(), Values: st.GetValueCount(),
		MemoryLocked: st.GetMemoryLocked(), PolicyEngine: st.GetPolicyEngine(), Matcher: r.GetEngine(),
		Patterns: r.GetPatterns(), ShortValues: r.GetShortValues(), UnprotectedRefs: r.GetUnprotectedRefs()}
}

// Daemon is a running control plane.
type Daemon struct {
	app     *app.App
	sup     *dataplane.Supervisor
	builder *SnapshotBuilder
	catalog *catalog.Manager
	runtime *agentapi.Runtime
	tokens  *sessionTokens
	// kubeTokens are the service account tokens scrim verified, redacted
	// until they expire.
	kubeTokens *sessionTokens
	pusher     *pusher
	log        *slog.Logger
	started    time.Time
	capture    string
	infoPath   string
	trust      func() string

	// project are the values scrim run found in each session's project
	// files, redacted until the session ends.
	project *projectValues

	mu        sync.Mutex
	addrs     Addrs
	dpReady   atomic.Bool
	dpProblem string
	dpStatus  *pb.StatusResponse

	control *controlMetrics

	cancel  context.CancelFunc
	servers []*http.Server
	wg      sync.WaitGroup
	done    chan struct{}
	errMu   sync.Mutex
	err     error
	stopped sync.Once
	cleanup []func()
}

// Run starts the daemon and serves until ctx ends, then shuts down
// gracefully. It is `scrim proxy`.
func Run(ctx context.Context, o Options) error {
	d, err := Start(ctx, o)
	if err != nil {
		return err
	}
	select {
	case <-ctx.Done():
	case <-d.Done():
	}
	shut, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
	defer cancel()
	serr := d.Shutdown(shut)
	if err := d.Err(); err != nil {
		return err
	}
	return serr
}

// Start builds the composition root, binds every control-plane listener,
// starts the data plane and returns. Stop it with Shutdown.
func Start(ctx context.Context, o Options) (_ *Daemon, err error) {
	logw := o.LogOutput
	if logw == nil {
		logw = os.Stderr
	}
	opts := o.Config
	if o.Capture != "" {
		abs, err := filepath.Abs(o.Capture)
		if err != nil {
			return nil, fmt.Errorf("capture: %w", err)
		}
		// The environment layer is below flags; a capture flag given to
		// `scrim proxy` is applied the same way by the CLI.
		opts.Environ = append(slices.Clone(opts.Environ), "SCRIM_PROXY_CAPTURE_DIR="+abs)
	}
	a, err := app.New(ctx, opts, logw)
	if err != nil {
		return nil, err
	}
	d := &Daemon{app: a, log: obs.WithComponent(a.Log, "daemon"), started: time.Now().UTC(), done: make(chan struct{})}
	defer func() {
		if err != nil {
			d.runCleanup()
			_ = a.Close()
		}
	}()
	cfg := a.Config.Current()
	runCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	d.cancel = cancel
	d.cleanup = append(d.cleanup, cancel)

	if dir := CaptureDir.Get(cfg); dir != "" {
		if err := prepareCaptureDir(dir); err != nil {
			return nil, err
		}
		d.capture = dir
		d.log.Warn("capture mode is on: every provider request and response is written to disk", "dir", dir,
			"retention", CaptureRetention.Get(cfg).String())
	}

	ring, err := placeholder.Load(ctx, cfg, obs.WithComponent(a.Log, "placeholder"))
	if err != nil {
		return nil, err
	}
	if len(placeholder.Keys.Get(cfg)) == 0 && a.State.Backend() == "postgres" {
		d.log.Warn("redaction.placeholder-keys is not set: each replica generates its own key and placeholders do not match across replicas")
	}

	d.catalog, err = catalog.NewManager(ctx, a.Config, a.Stores, obs.WithComponent(a.Log, "catalog"))
	if err != nil {
		ring.Wipe()
		return nil, err
	}
	d.cleanup = append(d.cleanup, d.catalog.Close)

	// ownCA is the daemon's own CA, whose generations are fresh copies the
	// metrics collector may wipe.
	var ownCA func() []CAGeneration
	if o.CA == nil {
		m, err := ca.Open(ctx, cfg, obs.WithComponent(a.Log, "ca"))
		if err != nil {
			ring.Wipe()
			return nil, err
		}
		d.cleanup = append(d.cleanup, m.Close)
		o.CA, o.CARun = caGenerations(m), m.Run
		ownCA = o.CA
		d.trust = m.TrustBundlePEM
	}

	d.tokens = newSessionTokens(sessionTokenStore, func() { d.pusher.Trigger() })
	d.cleanup = append(d.cleanup, d.tokens.close)
	d.kubeTokens = newSessionTokens(kubeTokenStore, func() { d.pusher.Trigger() })
	d.cleanup = append(d.cleanup, d.kubeTokens.close)
	d.project = newProjectValues(d.pushNow)
	d.cleanup = append(d.cleanup, d.project.close)
	values := make([]ValueSource, 0, len(a.Refreshers)+3)
	for _, r := range a.Refreshers {
		values = append(values, r)
	}
	values = append(values, d.tokens, d.kubeTokens, d.project)
	pp := a.PolicyParts
	// Per-agent store identity: the gate checks it on every use of a
	// governed store's secrets, and the snapshot sends those uses to the
	// control plane.
	access, err := agentstore.New(agentstore.Options{
		Login: agentstore.Login.Get(cfg), Credentials: agentstore.Credentials.Get(cfg), Lookup: a.Stores.Lookup,
		Resolve: func(ctx context.Context, ref config.SecretRef) (secret.Value, error) {
			return a.Config.Current().ResolveRef(ctx, ref)
		},
	})
	if err != nil {
		return nil, err
	}
	governed := access.Governed()
	if len(governed) > 0 {
		pp.Gate.StoreAccess = access
	}
	d.builder = &SnapshotBuilder{
		Config:    a.Config.Current,
		Values:    values,
		Catalog:   d.catalog.Current,
		CA:        o.CA,
		Listeners: ListenersFrom(cfg),
		Policy: func() *pb.Policy {
			ver, _ := pp.Rules.Health()
			rs := pp.Rules.RuleSet()
			snap := rs.Snapshot(ver, pp.BreakGlass.Active())
			if len(governed) > 0 {
				snap.Rules = append([]policy.SnapshotRule{policy.StoreIdentityRule(governed)}, snap.Rules...)
			}
			p := snap.Proto()
			p.AskTimeoutMillis = askTimeoutMillis(approval.Timeout.Get(a.Config.Current()), rs.Config())
			return p
		},
	}
	d.builder.SetKeys(ring)
	d.cleanup = append(d.cleanup, func() { d.builder.SetKeys(nil) })

	a.SnapshotSource = d.builder.Build
	d.sup, err = a.DataPlane()
	if err != nil {
		return nil, err
	}
	a.Health.Ready("dataplane listeners", d.listenersHealth)
	if d.capture != "" {
		// Capture mode is a data plane process setting: it is fixed for the
		// data plane's life, so the setting needs a restart.
		d.sup.Options.ExtraEnv = append(d.sup.Options.ExtraEnv, "SCRIM_DP_CAPTURE_DIR="+d.capture,
			fmt.Sprintf("SCRIM_DP_CAPTURE_RETENTION_SECS=%d", int64(CaptureRetention.Get(cfg).Seconds())))
	}
	d.sup.Options.ExtraEnv = append(d.sup.Options.ExtraEnv, o.DataPlaneEnv...)
	d.sup.OnAsk = pp.Gate.Answer
	sink := &eventSink{state: a.State, inst: a.Instruments, log: d.log}
	d.sup.OnEvents = sink.record
	cw := &captureWriter{gate: pp.Gate, refreshers: d.refresherFor, placeholder: d.builder.Placeholder, state: a.State, log: d.log}
	d.sup.OnCapture = cw.capture
	if obs.MetricsEnabled.Get(cfg) {
		// The data plane aggregates its own metrics only when asked to.
		d.sup.Options.ExtraEnv = append(d.sup.Options.ExtraEnv, "SCRIM_DP_METRICS=1")
		d.wireMetrics(a, ownCA)
	}

	d.pusher = newPusher(d.sup, func() time.Duration { return PushDebounce.Get(a.Config.Current()) }, d.log)
	d.subscribe(runCtx)

	notices := o.Notices
	if notices == nil {
		notices = logw
	}
	d.runtime, err = agentapi.New(a, agentapi.Options{Stderr: notices, Placeholders: placeholders{d.builder}, OnMint: d.tokens.add,
		OnKubeToken: d.kubeTokens.addKube})
	if err != nil {
		return nil, err
	}
	d.addrs.AgentAPI, d.addrs.EntryPage = d.runtime.Socket, d.runtime.EntryURL
	d.runtime.SetEndpoints(d.agentEndpoints)
	d.runtime.SetRedactor(d.redact)
	d.runtime.SetSessionValues(d.project.set, func(id string) {
		if d.project.end(id) {
			d.pusher.Trigger()
		}
	})
	// Asks name their caller by transport; the gate verifies sessions and
	// maps peers with the agent API's resolver. Set before anything runs.
	pp.Gate.Callers = d.runtime.Resolver

	if err := d.listenControl(cfg); err != nil {
		d.runtime.Close()
		return nil, err
	}
	d.setDataPlaneAddrs(nil)

	// Everything is bound: start the loops.
	a.Start(runCtx)
	d.watchFirstLoads(runCtx)
	d.goRun("policy", func() error { a.RunPolicy(runCtx); return nil })
	d.goRun("catalog", func() error { return ignoreCanceled(d.catalog.Run(runCtx)) })
	d.goRun("agent API", func() error { return ignoreCanceled(d.runtime.Serve(runCtx)) })
	d.goRun("pusher", func() error { d.pusher.Run(runCtx); return nil })
	d.goRun("dataplane", func() error { return ignoreCanceled(d.sup.Run(runCtx)) })
	d.goRun("sessions", func() error { d.sweepSessions(runCtx); return nil })
	d.goRun("addresses", func() error { d.watchReady(runCtx); return nil })
	if o.CARun != nil {
		d.goRun("ca", func() error { o.CARun(runCtx, d.pusher.Trigger); return nil })
	}
	if err := d.writeInfo(); err != nil {
		d.log.Warn("could not write the daemon info file; scrim run finds the daemon through the admin socket only", "err", err)
	}
	d.log.Info("scrim daemon started", "version", version.Version, "agent_api", d.addrs.AgentAPI,
		"admin", d.addrs.Admin, "base_url", d.addrs.BaseURL, "metrics", d.addrs.Metrics)
	return d, nil
}

func ignoreCanceled(err error) error {
	if errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}

// goRun runs fn until it returns. An error from it stops the daemon.
func (d *Daemon) goRun(name string, fn func() error) {
	d.wg.Go(func() {
		if err := fn(); err != nil {
			d.fail(fmt.Errorf("%s: %w", name, err))
		}
	})
}

func (d *Daemon) fail(err error) {
	d.errMu.Lock()
	if d.err == nil {
		d.err = err
		d.log.Error("daemon component failed; shutting down", "err", err)
	}
	d.errMu.Unlock()
	d.stopped.Do(func() { close(d.done) })
}

// subscribe pushes a new snapshot after every change that reaches it.
func (d *Daemon) subscribe(ctx context.Context) {
	a := d.app
	d.cleanup = append(d.cleanup,
		a.OnValuesChange(func(string) { d.pusher.Trigger() }),
		d.catalog.Subscribe(func(*catalog.Catalog) {
			d.pusher.Trigger()
			go d.warmCatalog(ctx)
		}),
	)
	a.PolicyParts.Rules.OnSwap(func(*policyRuleSet, uint64) { d.pusher.Trigger() })
	a.PolicyParts.BreakGlass.OnChange(func(bool) { d.pusher.Trigger() })
	d.cleanup = append(d.cleanup, a.Config.Subscribe(func(old, cur *config.Config) {
		d.reloadKeys(ctx, old, cur)
		d.pusher.Trigger()
	}))
}

// reloadKeys loads the placeholder keys again when their configuration
// changed. A failure keeps the keys in force.
func (d *Daemon) reloadKeys(ctx context.Context, old, cur *config.Config) {
	if old != nil && keysEqual(placeholder.Keys.Get(old), placeholder.Keys.Get(cur)) {
		return
	}
	ring, err := placeholder.Load(ctx, cur, d.log)
	if err != nil {
		d.log.Error("placeholder key reload rejected; previous keys stay in force", "err", err)
		return
	}
	d.builder.SetKeys(ring)
	d.log.Info("placeholder keys reloaded", "current_version", ring.Current().Version, "keys", len(ring.Keys))
}

func keysEqual(a, b []config.Instance) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Name != b[i].Name || fmt.Sprint(a[i].Fields) != fmt.Sprint(b[i].Fields) {
			return false
		}
	}
	return true
}

// warmCatalog reads, into the redaction set, every catalog-bound secret
// that no store's redact list loads, so it can be redacted and injected.
// Reads happen here, off the request path; a failure is retried on the next
// catalog change or refresh.
func (d *Daemon) warmCatalog(ctx context.Context) {
	cat := d.catalog.Current()
	if cat == nil {
		return
	}
	have := map[stores.Ref]bool{}
	for _, r := range d.app.Refreshers {
		r.EachValue(func(s refresh.Source, _ secret.Value) { have[s.Ref] = true; have[s.Ref.Secret()] = true })
	}
	for _, e := range cat.Entries() {
		if !e.OK || e.Binding.Ref.IsZero() || have[e.Binding.Ref] || have[e.Binding.Ref.Secret()] {
			continue
		}
		r, err := d.refresherFor(e.Binding.Ref)
		if err != nil {
			continue
		}
		rctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		v, err := r.Resolve(rctx, e.Binding.Ref)
		cancel()
		if err != nil {
			d.log.Warn("catalog secret could not be loaded for redaction", "name", e.Binding.Name, "ref", e.Binding.Ref.String(), "err", err)
			continue
		}
		v.Wipe()
	}
}

// refresherFor returns the refresher of the store ref names.
func (d *Daemon) refresherFor(ref stores.Ref) (*refresh.Refresher, error) {
	ad, err := d.app.Stores.Lookup(ref)
	if err != nil {
		return nil, err
	}
	for _, r := range d.app.Refreshers {
		if r.Store() == ad.Name() {
			return r, nil
		}
	}
	return nil, fmt.Errorf("store %s has no refresher", ad.Name())
}

// listenControl binds the admin, decision and metrics listeners.
func (d *Daemon) listenControl(cfg *config.Config) error {
	pp := d.app.PolicyParts
	tok, _ := cfg.Secret(AdminToken)
	adm, err := listenAdmin(approval.AdminURL.Get(cfg), tok)
	if err != nil {
		return err
	}
	if path, ok := strings.CutPrefix(adm.addr, "unix:"); ok {
		d.cleanup = append(d.cleanup, func() { _ = os.Remove(path) })
	}
	d.addrs.Admin = adm.addr
	admin := approval.AdminHandler(pp.Approvals, pp.Grants, pp.BreakGlass, adm.operator)
	mux := adminMux(adminServices{admin: admin, decision: pp.Approvals.DecisionHandler(), trust: d.trust}, adm.operator, d.Info)
	d.serve("admin", adm.ln, mux, localConnContext(adm.addr))

	if addr := DecisionListen.Get(cfg); addr != "" {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return fmt.Errorf("approvals.listen: %w", err)
		}
		dm := http.NewServeMux()
		dm.Handle("GET /v1/approvals/{id}/decide", pp.Approvals.DecisionHandler())
		dm.Handle("POST /v1/approvals/{id}/decide", pp.Approvals.DecisionHandler())
		d.addrs.Decision = ln.Addr().String()
		d.serve("decision", ln, dm, nil)
	}
	return d.listenMetrics(cfg)
}

// listenMetrics binds metrics.listen. With metrics.enabled it serves the
// health endpoints and metrics.path; with metrics.enabled false and
// metrics.listen set explicitly, the health endpoints only (as before the
// feature flag existed); otherwise nothing.
func (d *Daemon) listenMetrics(cfg *config.Config) error {
	a := d.app
	enabled := obs.MetricsEnabled.Get(cfg)
	addr := obs.MetricsListen.Get(cfg)
	explicit := false
	if e, ok := cfg.Entry(obs.MetricsListen.Name()); ok {
		explicit = e.Source.Kind != config.SourceDefault
	}
	switch {
	case enabled && addr == "":
		return errors.New("metrics.enabled is true but metrics.listen is empty: set an address such as " + obs.DefaultMetricsListen)
	case !enabled && (!explicit || addr == ""):
		return nil
	}
	var mux *http.ServeMux
	if enabled {
		tok, _ := cfg.Secret(obs.MetricsToken)
		if err := obs.CheckMetricsAuth(addr, tok, obs.MetricsAllowUnauthenticatedRemote.Get(cfg)); err != nil {
			return err
		}
		mux = obs.Mux(a.Health, a.Metrics, obs.MuxOptions{Path: obs.MetricsPath.Get(cfg), Token: tok})
	} else {
		mux = obs.Mux(a.Health, nil, obs.MuxOptions{})
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("metrics.listen: %w", err)
	}
	d.addrs.Metrics = ln.Addr().String()
	if enabled {
		d.log.Info("metrics enabled", "listen", d.addrs.Metrics, "path", obs.MetricsPath.Get(cfg))
	} else {
		d.log.Info("metrics.enabled is false: metrics.listen serves the health endpoints only", "listen", d.addrs.Metrics)
	}
	d.serve("metrics", ln, mux, nil)
	return nil
}

func (d *Daemon) serve(name string, ln net.Listener, h http.Handler, connCtx func(context.Context, net.Conn) context.Context) {
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second, ConnContext: connCtx,
		ErrorLog: slog.NewLogLogger(d.log.Handler(), slog.LevelWarn)}
	d.mu.Lock()
	d.servers = append(d.servers, srv)
	d.mu.Unlock()
	d.goRun(name, func() error {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	})
}

// setDataPlaneAddrs fills the data plane listener addresses: configured
// ones at start, bound ones (port 0 resolved) from the data plane status.
func (d *Daemon) setDataPlaneAddrs(st *pb.StatusResponse) {
	bound := map[string]string{}
	for _, l := range st.GetListeners() {
		if l.GetBound() && l.GetAddress() != "" {
			bound[l.GetName()] = l.GetAddress()
		}
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.addrs.Transparent = nil
	for _, l := range d.builder.Listeners {
		addr := l.GetAddress()
		if b, ok := bound[l.GetName()]; ok {
			addr = b
		}
		switch l.GetKind() {
		case pb.ListenerKind_LISTENER_KIND_BASE_URL:
			d.addrs.BaseURL = "http://" + addr
		case pb.ListenerKind_LISTENER_KIND_UNIX:
			d.addrs.BaseURLSocket = addr
		case pb.ListenerKind_LISTENER_KIND_FORWARD_PROXY:
			d.addrs.ForwardProxy = addr
		case pb.ListenerKind_LISTENER_KIND_TOOL_PROXY:
			d.addrs.ToolProxy = addr
		case pb.ListenerKind_LISTENER_KIND_TRANSPARENT:
			d.addrs.Transparent = append(d.addrs.Transparent, addr)
		case pb.ListenerKind_LISTENER_KIND_SNI:
			d.addrs.SNI = addr
		default:
		}
	}
}

// watchReady follows the data plane's own readiness (a snapshot applied and
// every listener bound), refreshes the bound addresses whenever it becomes
// ready (after every restart) and keeps the info file current.
func (d *Daemon) watchReady(ctx context.Context) {
	was := false
	t := time.NewTicker(200 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		now := false
		var st *pb.StatusResponse
		if d.sup.Ready() {
			sctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			var err error
			st, err = d.sup.Status(sctx)
			cancel()
			now = err == nil && st.GetReady()
			d.setListenerProblem(st, err)
		}
		d.dpReady.Store(now)
		if now && !was {
			d.setDataPlaneAddrs(st)
			d.log.Info("data plane ready", "base_url", d.Addrs().BaseURL)
			// A change made while the data plane was starting is pushed now.
			d.pusher.Trigger()
		}
		if now != was {
			_ = d.writeInfo()
		}
		was = now
	}
}

// setListenerProblem records why the data plane is not ready, for health.
func (d *Daemon) setListenerProblem(st *pb.StatusResponse, err error) {
	var problem string
	switch {
	case err != nil:
		problem = err.Error()
	case !st.GetReady():
		var unbound []string
		for _, l := range st.GetListeners() {
			if !l.GetBound() {
				unbound = append(unbound, l.GetName()+": "+l.GetError())
			}
		}
		problem = "data plane not ready"
		if len(unbound) > 0 {
			problem += "; unbound listeners: " + strings.Join(unbound, "; ")
		}
	}
	d.mu.Lock()
	d.dpProblem = problem
	if st != nil {
		d.dpStatus = st
	}
	d.mu.Unlock()
}

func (d *Daemon) listenersHealth(context.Context) error {
	if d.dpReady.Load() {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.dpProblem != "" {
		return errors.New(d.dpProblem)
	}
	return errors.New("data plane listeners are not bound yet")
}

// sweepSessions revokes sessions whose `scrim run` died without ending
// them.
func (d *Daemon) sweepSessions(ctx context.Context) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		active := func(id string) bool {
			s, err := d.runtime.Sessions.Get(ctx, id)
			return err == nil && s.Active(time.Now())
		}
		if a, b, c := d.tokens.prune(), d.kubeTokens.prune(), d.project.prune(active); a || b || c {
			d.pusher.Trigger()
		}
		if gone, err := d.runtime.Sessions.Sweep(ctx); err != nil {
			d.log.Warn("session sweep failed", "err", err)
		} else if len(gone) > 0 {
			d.log.Info("revoked sessions whose process exited", "count", len(gone))
		}
	}
}

// pushNow pushes a snapshot and returns once the data plane applied it, for
// changes the caller must see in force before it goes on (project values
// before the agent's first request).
func (d *Daemon) pushNow(ctx context.Context) error {
	for !d.sup.Ready() {
		select {
		case <-ctx.Done():
			return errors.New("the data plane is not ready")
		case <-time.After(50 * time.Millisecond):
		}
	}
	return d.sup.Push(ctx)
}

// App returns the composition root, for callers embedding the daemon.
func (d *Daemon) App() *app.App { return d.app }

// Supervisor returns the data plane supervisor.
func (d *Daemon) Supervisor() *dataplane.Supervisor { return d.sup }

// Addrs returns where the daemon serves.
func (d *Daemon) Addrs() Addrs {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.addrs
}

// Ready reports whether the data plane holds a snapshot and every readiness
// check passes.
func (d *Daemon) Ready(ctx context.Context) bool {
	return d.sup.Ready() && d.dpReady.Load() && d.app.Health.Run(ctx, true).Status == "ok"
}

// Info describes the daemon.
func (d *Daemon) Info() Info {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	rep := d.app.Health.Run(ctx, true)
	in := Info{PID: os.Getpid(), Version: version.Version, StartedAt: d.started, Addrs: d.Addrs(), Capture: d.capture,
		Ready: d.sup.Ready() && d.dpReady.Load() && rep.Status == "ok", Bypass: bypass(d.app.Config.Current())}
	d.mu.Lock()
	in.DataPlane = dataPlaneInfo(d.dpStatus)
	d.mu.Unlock()
	in.Runtime = d.runtimeInfo(ctx, in.Ready)
	in.Stores = d.storeStatus()
	in.AuditSinks = status.FromFanout(d.app.AuditSinks.Status())
	for k, v := range rep.Checks {
		if v != "ok" {
			if in.Problems == nil {
				in.Problems = map[string]string{}
			}
			in.Problems[k] = v
		}
	}
	return in
}

// agentEndpoints is what the agent API tells callers that did not start
// this daemon and cannot reach the admin API (agents of other users when
// scrim runs as a system service). Public material only.
func (d *Daemon) agentEndpoints() localapi.Endpoints {
	in := d.Info()
	ep := localapi.Endpoints{Ready: in.Ready, Problems: in.Problems, BaseURL: in.Addrs.BaseURL,
		ForwardProxy: in.Addrs.ForwardProxy, Bypass: in.Bypass}
	if d.trust != nil {
		ep.CAPEM = d.trust()
	}
	return ep
}

// WaitReady blocks until the daemon is ready, it stops, or ctx ends.
func (d *Daemon) WaitReady(ctx context.Context) error {
	t := time.NewTicker(50 * time.Millisecond)
	defer t.Stop()
	for {
		if d.Ready(ctx) {
			return nil
		}
		select {
		case <-ctx.Done():
			in := d.Info()
			return fmt.Errorf("daemon not ready: %v (%w)", in.Problems, ctx.Err())
		case <-d.done:
			if err := d.Err(); err != nil {
				return err
			}
			return errors.New("daemon stopped")
		case <-t.C:
		}
	}
}

// Done is closed when a component fails or Shutdown is called.
func (d *Daemon) Done() <-chan struct{} { return d.done }

// Err returns the error that stopped the daemon, if any.
func (d *Daemon) Err() error {
	d.errMu.Lock()
	defer d.errMu.Unlock()
	return d.err
}

// Shutdown stops serving: listeners close, in-flight admin requests finish
// until ctx ends, the data plane is stopped (it denies held asks), state is
// closed and every value and key is wiped.
func (d *Daemon) Shutdown(ctx context.Context) error {
	d.stopped.Do(func() { close(d.done) })
	d.mu.Lock()
	servers := slices.Clone(d.servers)
	d.mu.Unlock()
	var errs []error
	for _, s := range servers {
		if err := s.Shutdown(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	d.cancel()
	waited := make(chan struct{})
	go func() { d.wg.Wait(); close(waited) }()
	select {
	case <-waited:
	case <-ctx.Done():
		errs = append(errs, errors.New("daemon: components did not stop in time"))
	}
	if d.infoPath != "" {
		_ = os.Remove(d.infoPath)
	}
	d.runCleanup()
	errs = append(errs, d.app.Close())
	d.log.Info("scrim daemon stopped")
	return errors.Join(errs...)
}

func (d *Daemon) runCleanup() {
	for i := len(d.cleanup) - 1; i >= 0; i-- {
		d.cleanup[i]()
	}
	d.cleanup = nil
}

// TrustBundlePEM returns the tool-proxy CA certificates clients must trust,
// or "" when the CA was supplied by the caller. Public material.
func (d *Daemon) TrustBundlePEM() string {
	if d.trust == nil {
		return ""
	}
	return d.trust()
}

func caGenerations(m *ca.Manager) func() []CAGeneration {
	return func() []CAGeneration {
		gens := m.Generations()
		out := make([]CAGeneration, len(gens))
		for i, g := range gens {
			out[i] = CAGeneration{CertPEM: g.CertPEM, Key: g.Key, Current: g.Current}
		}
		return out
	}
}

// placeholders adapts the builder to the agent API.
type placeholders struct{ b *SnapshotBuilder }

func (p placeholders) Placeholder(ref stores.Ref) string { return p.b.PlaceholderFor(ref) }

// prepareCaptureDir creates the capture directory with mode 0700 and
// refuses one group or others can access (leak-assurance "Capture mode").
// The data plane checks again before it writes.
func prepareCaptureDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("proxy.capture.dir: %w", err)
	}
	fi, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("proxy.capture.dir: %w", err)
	}
	if !fi.IsDir() {
		return fmt.Errorf("proxy.capture.dir: %s is not a directory", dir)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("proxy.capture.dir: %s is accessible to group or others (mode %04o); use mode 0700", dir, fi.Mode().Perm())
	}
	return nil
}
