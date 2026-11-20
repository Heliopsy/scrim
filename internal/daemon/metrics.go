// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"regexp"
	"slices"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/heliopsy/scrim/internal/app"
	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/dataplane"
	pb "github.com/heliopsy/scrim/internal/dataplane/dataplanev1"
	"github.com/heliopsy/scrim/internal/obs"
	"github.com/heliopsy/scrim/internal/state"
	"github.com/heliopsy/scrim/internal/version"
)

// Control-plane metrics that need the daemon's components
// (specs/observability "Control plane metrics"). Everything here is wired
// only while metrics.enabled is true; otherwise none of the hooks is set and
// none of the collectors runs.

// dpMetricName is what a data plane family name must look like.
var dpMetricName = regexp.MustCompile(`^scrim_dataplane_[a-z0-9_]+$`)

// dpLabels are the only label names a data plane family may use. Values
// are route names, codec names, codes and enumerations; they are scrubbed
// anyway.
var dpLabels = map[string]bool{
	"route": true, "provider": true, "stage": true, "outcome": true, "class": true, "code": true,
	"source": true, "action": true, "listener": true, "kind": true, "result": true, "status_class": true,
}

// maxLabelValue bounds a data plane label value; longer values are cut.
const maxLabelValue = 128

// dataPlaneCollector exposes the data plane's own metrics, read over the
// Metrics call once per scrape, plus whether the data plane is up.
type dataPlaneCollector struct {
	sup     *dataplane.Supervisor
	sc      obs.Scrubber
	timeout time.Duration

	up, restarts, metricsUp *prometheus.Desc
}

func newDataPlaneCollector(sup *dataplane.Supervisor, sc obs.Scrubber) *dataPlaneCollector {
	return &dataPlaneCollector{
		sup: sup, sc: sc, timeout: 2 * time.Second,
		up:        prometheus.NewDesc("scrim_dataplane_up", "1 while the data plane runs with a snapshot applied.", nil, nil),
		restarts:  prometheus.NewDesc("scrim_dataplane_restarts_total", "Times the data plane was started again after the first start.", nil, nil),
		metricsUp: prometheus.NewDesc("scrim_dataplane_metrics_up", "1 when this scrape read the data plane's own metrics.", nil, nil),
	}
}

// Describe sends nothing: the data plane's families are only known when
// scraped, which makes this an unchecked collector.
func (c *dataPlaneCollector) Describe(chan<- *prometheus.Desc) {}

func (c *dataPlaneCollector) Collect(ch chan<- prometheus.Metric) {
	ch <- prometheus.MustNewConstMetric(c.up, prometheus.GaugeValue, b2f(c.sup.Ready()))
	ch <- prometheus.MustNewConstMetric(c.restarts, prometheus.CounterValue, float64(c.sup.Restarts()))
	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()
	resp, err := c.sup.Metrics(ctx)
	ok := err == nil && resp.GetEnabled()
	if err != nil && status.Code(err) == codes.Unimplemented {
		ok = false // a data plane older than the Metrics call
	}
	ch <- prometheus.MustNewConstMetric(c.metricsUp, prometheus.GaugeValue, b2f(ok))
	if !ok {
		return
	}
	for _, f := range resp.GetFamilies() {
		c.family(ch, f)
	}
}

// family turns one data plane family into const metrics. A family with an
// unexpected name, type or label name is dropped whole.
func (c *dataPlaneCollector) family(ch chan<- prometheus.Metric, f *pb.MetricFamily) {
	if !dpMetricName.MatchString(f.GetName()) || slices.ContainsFunc(f.GetLabelNames(), func(l string) bool { return !dpLabels[l] }) {
		return
	}
	desc := prometheus.NewDesc(f.GetName(), c.sc.Scrub(f.GetHelp()), f.GetLabelNames(), nil)
	bounds := f.GetBucketBounds()
	for _, s := range f.GetSamples() {
		if len(s.GetLabelValues()) != len(f.GetLabelNames()) {
			continue
		}
		lv := make([]string, len(s.GetLabelValues()))
		for i, v := range s.GetLabelValues() {
			if len(v) > maxLabelValue {
				v = v[:maxLabelValue]
			}
			lv[i] = c.sc.Scrub(v)
		}
		var m prometheus.Metric
		var err error
		switch f.GetType() {
		case pb.MetricType_METRIC_TYPE_COUNTER:
			m, err = prometheus.NewConstMetric(desc, prometheus.CounterValue, s.GetValue(), lv...)
		case pb.MetricType_METRIC_TYPE_GAUGE:
			m, err = prometheus.NewConstMetric(desc, prometheus.GaugeValue, s.GetValue(), lv...)
		case pb.MetricType_METRIC_TYPE_HISTOGRAM:
			if len(s.GetBucketCounts()) != len(bounds) {
				continue
			}
			buckets := make(map[float64]uint64, len(bounds))
			for i, b := range bounds {
				buckets[b] = s.GetBucketCounts()[i]
			}
			m, err = prometheus.NewConstHistogram(desc, s.GetCount(), s.GetSum(), buckets, lv...)
		default:
			return
		}
		if err == nil {
			ch <- m
		}
	}
}

// stateCollector reports what the state backend holds right now: pending
// approvals, active grants and sessions, and whether it answers. It reads
// once per scrape, at most every cacheFor.
type stateCollector struct {
	st       state.Store
	now      func() time.Time
	cacheFor time.Duration

	mu      sync.Mutex
	at      time.Time
	cached  []prometheus.Metric
	pending *prometheus.Desc
	oldest  *prometheus.Desc
	grants  *prometheus.Desc
	session *prometheus.Desc
	up      *prometheus.Desc
}

func newStateCollector(st state.Store) *stateCollector {
	return &stateCollector{
		st: st, now: time.Now, cacheFor: 5 * time.Second,
		pending: prometheus.NewDesc("scrim_approvals_pending", "Approvals waiting for a decision.", nil, nil),
		oldest:  prometheus.NewDesc("scrim_approvals_oldest_pending_age_seconds", "Age of the oldest pending approval, 0 when none.", nil, nil),
		grants:  prometheus.NewDesc("scrim_grants_active", "Grants usable now.", nil, nil),
		session: prometheus.NewDesc("scrim_sessions_active", "Agent sessions not ended.", nil, nil),
		up:      prometheus.NewDesc("scrim_state_up", "1 when the state backend answered its health check.", []string{"backend"}, nil),
	}
}

func (c *stateCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range []*prometheus.Desc{c.pending, c.oldest, c.grants, c.session, c.up} {
		ch <- d
	}
}

func (c *stateCollector) Collect(ch chan<- prometheus.Metric) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if c.cached == nil || now.Sub(c.at) >= c.cacheFor {
		c.cached, c.at = c.read(now), now
	}
	for _, m := range c.cached {
		ch <- m
	}
}

func (c *stateCollector) read(now time.Time) []prometheus.Metric {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	healthy := c.st.Health(ctx) == nil
	out := []prometheus.Metric{prometheus.MustNewConstMetric(c.up, prometheus.GaugeValue, b2f(healthy), c.st.Backend())}
	if !healthy {
		return out
	}
	var pending []state.Approval
	var grants []state.Grant
	var sessions []state.Session
	err := c.st.View(ctx, func(tx state.Tx) error {
		var err error
		if pending, err = tx.ListApprovals(ctx, state.ApprovalFilter{Status: state.ApprovalPending}); err != nil {
			return err
		}
		if grants, err = tx.ListGrants(ctx, state.GrantFilter{UsableAt: now}); err != nil {
			return err
		}
		sessions, err = tx.ListSessions(ctx, state.SessionFilter{Open: true})
		return err
	})
	if err != nil {
		return out
	}
	oldest := 0.0
	for _, a := range pending {
		oldest = max(oldest, now.Sub(a.CreatedAt).Seconds())
	}
	active := 0
	for _, s := range sessions {
		if s.ExpiresAt.IsZero() || s.ExpiresAt.After(now) {
			active++
		}
	}
	return append(out,
		prometheus.MustNewConstMetric(c.pending, prometheus.GaugeValue, float64(len(pending))),
		prometheus.MustNewConstMetric(c.oldest, prometheus.GaugeValue, oldest),
		prometheus.MustNewConstMetric(c.grants, prometheus.GaugeValue, float64(len(grants))),
		prometheus.MustNewConstMetric(c.session, prometheus.GaugeValue, float64(active)),
	)
}

// caCollector reports when each tool-proxy CA generation expires.
type caCollector struct {
	gens func() []CAGeneration
	desc *prometheus.Desc
}

func newCACollector(gens func() []CAGeneration) *caCollector {
	return &caCollector{gens: gens, desc: prometheus.NewDesc("scrim_ca_certificate_not_after_timestamp_seconds",
		"Unix time the tool-proxy CA certificate expires, by generation (current, previous).", []string{"generation"}, nil)}
}

func (c *caCollector) Describe(ch chan<- *prometheus.Desc) { ch <- c.desc }

func (c *caCollector) Collect(ch chan<- prometheus.Metric) {
	for _, g := range c.gens() {
		g.Key.Wipe() // only the public certificate is read
		block, _ := pem.Decode([]byte(g.CertPEM))
		if block == nil {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		gen := "previous"
		if g.Current {
			gen = "current"
		}
		ch <- prometheus.MustNewConstMetric(c.desc, prometheus.GaugeValue, float64(cert.NotAfter.Unix()), gen)
	}
}

// controlMetrics are the daemon's own counters and histograms.
type controlMetrics struct {
	asks         *prometheus.CounterVec
	askSeconds   *prometheus.HistogramVec
	builds       *prometheus.CounterVec
	buildSeconds prometheus.Observer
	pushes       *prometheus.CounterVec
	pushSeconds  prometheus.Observer
	entries      *prometheus.GaugeVec
	version      prometheus.Gauge
	reloads      *prometheus.CounterVec
	grantUses    *prometheus.CounterVec
	sc           obs.Scrubber
	buildInfo    *prometheus.GaugeVec
}

func newControlMetrics(m *obs.Metrics, sc obs.Scrubber) *controlMetrics {
	ops := []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}
	c := &controlMetrics{
		sc:   sc,
		asks: m.Counter("", "asks_total", "Asks from the data plane, by outcome (allow, deny).", "outcome"),
		askSeconds: m.Histogram("", "ask_duration_seconds", "Time to answer an ask from the data plane, approval waits included.",
			[]float64{0.001, 0.01, 0.1, 1, 5, 15, 30, 60, 120, 300, 600}, "outcome"),
		builds:       m.Counter("snapshot", "builds_total", "Data plane snapshots built, by result (ok, error).", "result"),
		buildSeconds: m.Histogram("snapshot", "build_duration_seconds", "Time to build one data plane snapshot.", ops).WithLabelValues(),
		pushes:       m.Counter("snapshot", "pushes_total", "Snapshots sent to the data plane, by result (ok, error).", "result"),
		pushSeconds:  m.Histogram("snapshot", "push_duration_seconds", "Time the data plane took to apply a pushed snapshot.", ops).WithLabelValues(),
		entries:      m.Gauge("snapshot", "entries", "Entries in the last snapshot pushed, by kind.", "kind"),
		version:      m.Gauge("snapshot", "version", "Version of the last snapshot the data plane applied.").WithLabelValues(),
		reloads:      m.Counter("config", "reloads_total", "Configuration reloads, by result (applied, unchanged, rejected).", "result"),
		grantUses:    m.Counter("grants", "uses_total", "Grant uses, by rule.", "rule"),
		buildInfo:    m.Gauge("", "build_info", "Always 1; the labels name the running build.", "version", "commit"),
	}
	c.buildInfo.WithLabelValues(version.Version, version.Commit).Set(1)
	for _, r := range []string{"ok", "error"} {
		c.builds.WithLabelValues(r)
		c.pushes.WithLabelValues(r)
	}
	for _, r := range []string{config.ReloadApplied, config.ReloadUnchanged, config.ReloadRejected} {
		c.reloads.WithLabelValues(r)
	}
	for _, o := range []string{"allow", "deny"} {
		c.asks.WithLabelValues(o)
	}
	return c
}

func (c *controlMetrics) push(r dataplane.PushReport) {
	if r.BuildErr != nil {
		c.builds.WithLabelValues("error").Inc()
		c.buildSeconds.Observe(r.Build.Seconds())
		return
	}
	c.builds.WithLabelValues("ok").Inc()
	c.buildSeconds.Observe(r.Build.Seconds())
	c.pushSeconds.Observe(r.Apply.Seconds())
	if r.ApplyErr != nil {
		c.pushes.WithLabelValues("error").Inc()
		return
	}
	c.pushes.WithLabelValues("ok").Inc()
	c.version.Set(float64(r.Version))
	for k, n := range r.Entries {
		c.entries.WithLabelValues(k).Set(float64(n))
	}
}

// ask wraps an ask handler with its count and latency.
func (c *controlMetrics) ask(next dataplane.AskFunc) dataplane.AskFunc {
	return func(ctx context.Context, req *pb.AskRequest) *pb.AskAnswer {
		began := time.Now()
		ans := next(ctx, req)
		outcome := "deny"
		if ans.GetEffect() == pb.Effect_EFFECT_ALLOW {
			outcome = "allow"
		}
		c.asks.WithLabelValues(outcome).Inc()
		c.askSeconds.WithLabelValues(outcome).Observe(time.Since(began).Seconds())
		return ans
	}
}

func (c *controlMetrics) grantUsed(rule string) { c.grantUses.WithLabelValues(c.sc.Scrub(rule)).Inc() }

// wireMetrics registers the daemon's collectors and hooks on a's registry.
// gens is the CA generation source, nil when there is none.
func (d *Daemon) wireMetrics(a *app.App, gens func() []CAGeneration) {
	cm := newControlMetrics(a.Metrics, a.Scrubber)
	d.control = cm
	a.Metrics.Registry.MustRegister(newDataPlaneCollector(d.sup, a.Scrubber), newStateCollector(a.State))
	if gens != nil {
		a.Metrics.Registry.MustRegister(newCACollector(gens))
	}
	d.sup.OnPush = cm.push
	if d.sup.OnAsk != nil {
		d.sup.OnAsk = cm.ask(d.sup.OnAsk)
	}
	a.Config.OnReload(func(outcome string) { cm.reloads.WithLabelValues(outcome).Inc() })
	a.PolicyParts.Grants.OnUse(cm.grantUsed)
}

func b2f(b bool) float64 {
	if b {
		return 1
	}
	return 0
}
