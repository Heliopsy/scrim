// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	pb "github.com/heliopsy/scrim/internal/dataplane/dataplanev1"
)

// sample returns the value of the series name{labels} on a Prometheus text
// page; every label in want must match, others are ignored.
func sample(page, name string, want map[string]string) (float64, bool) {
	for line := range strings.SplitSeq(page, "\n") {
		if line == "" || line[0] == '#' {
			continue
		}
		sp := strings.LastIndexByte(line, ' ')
		if sp < 0 {
			continue
		}
		series, val := line[:sp], line[sp+1:]
		n, labels, _ := strings.Cut(series, "{")
		if n != name {
			continue
		}
		got := map[string]string{}
		for kv := range strings.SplitSeq(strings.TrimSuffix(labels, "}"), ",") {
			if k, v, ok := strings.Cut(kv, "="); ok {
				got[k] = strings.Trim(v, `"`)
			}
		}
		match := true
		for k, v := range want {
			if got[k] != v {
				match = false
				break
			}
		}
		if match {
			f, err := strconv.ParseFloat(val, 64)
			return f, err == nil
		}
	}
	return 0, false
}

func scrapeMetrics(t *testing.T, addr, path, token string) (int, string) {
	t.Helper()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://"+addr+path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var b strings.Builder
	buf := make([]byte, 32<<10)
	for {
		n, err := resp.Body.Read(buf)
		b.Write(buf[:n])
		if err != nil {
			break
		}
	}
	return resp.StatusCode, b.String()
}

// encodings are the forms of v a leak check looks for.
func encodings(v string) map[string]string {
	return map[string]string{
		"raw": v, "base64": base64.StdEncoding.EncodeToString([]byte(v)), "base64url": base64.RawURLEncoding.EncodeToString([]byte(v)),
		"hex": hex.EncodeToString([]byte(v)), "url": url.QueryEscape(v), "upper": strings.ToUpper(v),
	}
}

func assertNoLeak(t *testing.T, page string, values ...string) {
	t.Helper()
	for _, v := range values {
		for form, f := range encodings(v) {
			if strings.Contains(page, f) {
				t.Errorf("metrics page holds a seeded value (%s form)", form)
			}
		}
	}
}

func startDaemon(t *testing.T, h *harness) *Daemon {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	d, err := Start(ctx, h.opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Shutdown(context.Background()) })
	if err := d.WaitReady(ctx); err != nil {
		t.Fatalf("%v\n%s", err, h.logs.String())
	}
	return d
}

// TestMetricsListenWithoutFlagServesHealthOnly: metrics.listen set
// explicitly while metrics.enabled is false keeps serving the health
// endpoints, and only them.
func TestMetricsListenWithoutFlagServesHealthOnly(t *testing.T) {
	h := newHarness(t, seed(t, "tok-"))
	d := startDaemon(t, h)
	addr := d.Addrs().Metrics
	if code, _ := scrapeMetrics(t, addr, "/healthz", ""); code != http.StatusOK {
		t.Fatalf("/healthz = %d", code)
	}
	if code, _ := scrapeMetrics(t, addr, "/metrics", ""); code != http.StatusNotFound {
		t.Fatalf("/metrics = %d with metrics.enabled false", code)
	}
	if !strings.Contains(h.logs.String(), "serves the health endpoints only") {
		t.Fatal("no log line says metrics are off")
	}
	if d.control != nil {
		t.Fatal("metrics hooks are wired while metrics.enabled is false")
	}
}

// TestMetricsEnabledControlPlane enables metrics with a bearer token against
// the fake data plane (which does not implement the Metrics call) and checks
// the control-plane series, the token and the absence of the seeded value.
func TestMetricsEnabledControlPlane(t *testing.T) {
	token := seed(t, "tok-")
	scrapeToken := seed(t, "scrape-")
	h := newHarness(t, token, "SCRIM_FAKE_ASK_REF=testenv://SCRIMTEST_TOKEN")
	h.opts.Config.Environ = append(h.opts.Config.Environ, "SCRIMTEST_METRICS_TOKEN="+scrapeToken, "SCRIM_METRICS_ENABLED=true",
		"SCRIM_METRICS_PATH=/scrape", "SCRIM_METRICS_AUTH_TOKEN=env:SCRIMTEST_METRICS_TOKEN")
	d := startDaemon(t, h)
	addr := d.Addrs().Metrics

	if code, _ := scrapeMetrics(t, addr, "/scrape", ""); code != http.StatusUnauthorized {
		t.Fatalf("scrape without token = %d", code)
	}
	if code, _ := scrapeMetrics(t, addr, "/healthz", ""); code != http.StatusOK {
		t.Fatalf("/healthz needs no token, got %d", code)
	}
	var page string
	eventually(t, "the ask counted", func() bool {
		_, page = scrapeMetrics(t, addr, "/scrape", scrapeToken)
		// The counter and the histogram are updated one after the other, so
		// wait for both before checking the page.
		v, ok := sample(page, "scrim_asks_total", map[string]string{"outcome": "deny"})
		n, hok := sample(page, "scrim_ask_duration_seconds_count", map[string]string{"outcome": "deny"})
		return ok && v >= 1 && hok && n >= 1
	})
	for _, c := range []struct {
		name   string
		labels map[string]string
		min    float64
	}{
		{"scrim_build_info", nil, 1},
		{"scrim_dataplane_up", nil, 1},
		{"scrim_dataplane_metrics_up", nil, 0},
		{"scrim_snapshot_pushes_total", map[string]string{"result": "ok"}, 1},
		{"scrim_snapshot_builds_total", map[string]string{"result": "ok"}, 1},
		{"scrim_snapshot_version", nil, 1},
		{"scrim_snapshot_entries", map[string]string{"kind": "values"}, 1},
		{"scrim_store_up", map[string]string{"store": "testenv"}, 1},
		{"scrim_store_refresh_duration_seconds_count", map[string]string{"store": "testenv"}, 1},
		{"scrim_store_staleness_seconds", map[string]string{"store": "testenv"}, 0},
		{"scrim_state_up", map[string]string{"backend": "sqlite"}, 1},
		{"scrim_approvals_pending", nil, 0},
		{"scrim_sessions_active", nil, 0},
		{"scrim_grants_active", nil, 0},
		{"scrim_config_reloads_total", map[string]string{"result": "rejected"}, 0},
		{"scrim_ask_duration_seconds_count", map[string]string{"outcome": "deny"}, 1},
		{"scrim_ca_certificate_not_after_timestamp_seconds", map[string]string{"generation": "current"}, float64(time.Now().Unix())},
	} {
		v, ok := sample(page, c.name, c.labels)
		if !ok || v < c.min {
			t.Errorf("%s%v = %v (present %v), want >= %v", c.name, c.labels, v, ok, c.min)
		}
	}
	assertNoLeak(t, page, token, scrapeToken)
}

// TestMetricsRefusesRemoteListenWithoutToken: a non-loopback metrics
// listener needs a token or the weakening setting.
func TestMetricsRefusesRemoteListenWithoutToken(t *testing.T) {
	h := newHarness(t, seed(t, "tok-"))
	h.opts.Config.Environ = append(h.opts.Config.Environ, "SCRIM_METRICS_ENABLED=true", "SCRIM_METRICS_LISTEN=0.0.0.0:0")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	d, err := Start(ctx, h.opts)
	if err == nil {
		_ = d.Shutdown(context.Background())
		t.Fatal("started with an unauthenticated non-loopback metrics listener")
	}
	if !strings.Contains(err.Error(), "metrics.auth.token") {
		t.Fatalf("error does not name the fix: %v", err)
	}
	h.opts.Config.Environ = append(h.opts.Config.Environ, "SCRIM_METRICS_LISTEN=")
	if _, err := Start(ctx, h.opts); err == nil || !strings.Contains(err.Error(), "metrics.listen is empty") {
		t.Fatalf("empty metrics.listen with metrics enabled: %v", err)
	}
}

type markScrubber struct{ bad string }

func (m markScrubber) Scrub(s string) string { return strings.ReplaceAll(s, m.bad, "[scrim:redacted]") }

// TestDataPlaneFamiliesAreChecked: a family with a foreign name or label
// name is dropped, label values are scrubbed and cut, histograms convert.
func TestDataPlaneFamiliesAreChecked(t *testing.T) {
	c := newDataPlaneCollector(nil, markScrubber{bad: "seeded-value"})
	fams := []*pb.MetricFamily{
		{Name: "go_goroutines", Type: pb.MetricType_METRIC_TYPE_GAUGE, Samples: []*pb.MetricSample{{Value: 1}}},
		{Name: "scrim_dataplane_x_total", Type: pb.MetricType_METRIC_TYPE_COUNTER, LabelNames: []string{"ref"},
			Samples: []*pb.MetricSample{{LabelValues: []string{"bao://kv/a"}, Value: 1}}},
		{Name: "scrim_dataplane_ok_total", Help: "ok", Type: pb.MetricType_METRIC_TYPE_COUNTER, LabelNames: []string{"route"},
			Samples: []*pb.MetricSample{{LabelValues: []string{"r-seeded-value"}, Value: 2}, {LabelValues: []string{strings.Repeat("x", 500)}, Value: 1}}},
		{Name: "scrim_dataplane_h_seconds", Help: "h", Type: pb.MetricType_METRIC_TYPE_HISTOGRAM, BucketBounds: []float64{0.001, 0.01},
			Samples: []*pb.MetricSample{{BucketCounts: []uint64{1, 3}, Count: 4, Sum: 0.5}, {BucketCounts: []uint64{1}, Count: 1}}},
	}
	ch := make(chan prometheus.Metric, 16)
	for _, f := range fams {
		c.family(ch, f)
	}
	close(ch)
	var got []string
	for m := range ch {
		got = append(got, m.Desc().String())
	}
	if len(got) != 3 {
		t.Fatalf("got %d metrics, want 2 counters and 1 histogram: %v", len(got), got)
	}
	reg := prometheus.NewRegistry()
	reg.MustRegister(collectorFunc(func(ch chan<- prometheus.Metric) {
		for _, f := range fams {
			c.family(ch, f)
		}
	}))
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, mf := range mfs {
		for _, m := range mf.GetMetric() {
			for _, l := range m.GetLabel() {
				if strings.Contains(l.GetValue(), "seeded-value") || len(l.GetValue()) > maxLabelValue {
					t.Errorf("label value %q not scrubbed or cut", l.GetValue())
				}
			}
			if h := m.GetHistogram(); h != nil && (h.GetSampleCount() != 4 || len(h.GetBucket()) != 2) {
				t.Errorf("histogram = %v", h)
			}
		}
	}
}

type collectorFunc func(chan<- prometheus.Metric)

func (collectorFunc) Describe(chan<- *prometheus.Desc)      {}
func (f collectorFunc) Collect(ch chan<- prometheus.Metric) { f(ch) }
