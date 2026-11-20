// SPDX-License-Identifier: AGPL-3.0-only

package obs

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"

	"github.com/heliopsy/scrim/internal/secret"
)

func TestLogContextFieldsAndDefaultComponent(t *testing.T) {
	var buf bytes.Buffer
	l := NewLogger(&buf, LogOptions{Format: "json"})
	ctx := WithRequestID(WithAgent(context.Background(), "claude-laptop"), "req-1")
	WithComponent(l, "proxy").InfoContext(ctx, "forwarded")
	l.Info("plain")
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("lines: %q", buf.String())
	}
	var rec map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &rec); err != nil {
		t.Fatal(err)
	}
	if rec["component"] != "proxy" || rec["agent"] != "claude-laptop" || rec["request_id"] != "req-1" {
		t.Errorf("record = %v", rec)
	}
	if strings.Count(lines[0], `"component"`) != 1 {
		t.Errorf("component repeated: %s", lines[0])
	}
	_ = json.Unmarshal([]byte(lines[1]), &rec)
	if rec["component"] != DefaultComponent {
		t.Errorf("default component: %v", rec)
	}
}

func TestLogScrubsAttrsBoundBeforeValueKnown(t *testing.T) {
	var buf bytes.Buffer
	slot := &ScrubberSlot{}
	l := NewLogger(&buf, LogOptions{Format: "json", Scrubber: slot})
	early := l.With("early", "token="+testValue).WithGroup("g")
	slot.Set(NewValueScrubber(secret.FromString(testValue)))
	early.Info("x", "m", map[string]string{"k": testValue})
	if strings.Contains(buf.String(), "sk-test-0123456789abcdef") {
		t.Fatalf("log holds the value:\n%s", buf.String())
	}
}

func TestLogTraceIDs(t *testing.T) {
	exp := tracetest.NewInMemoryExporter()
	tr, _ := NewTracing(TraceOptions{Exporter: exp, SampleRatio: 1})
	defer func() { _ = tr.Shutdown(context.Background()) }()
	ctx, span := tr.Tracer.Start(context.Background(), "x")
	var buf bytes.Buffer
	NewLogger(&buf, LogOptions{Format: "json"}).InfoContext(ctx, "in span")
	span.End()
	if !strings.Contains(buf.String(), span.SpanContext().TraceID().String()) {
		t.Fatalf("no trace id: %s", buf.String())
	}
}

func TestDisabledInstrumentsRecordNothing(t *testing.T) {
	var nilIn *Instruments
	for _, in := range []*Instruments{DisabledInstruments(), nilIn} {
		if in.On() {
			t.Fatal("disabled instruments report on")
		}
		in.Redaction("p", "r", "a", 1)
		in.GuardRefusal("p", "a")
		in.StoreHealth("s", true, time.Now(), 1, false)
		in.StoreRefresh("s", time.Second, true)
		in.AuditDropped("x", 1)
		in.StateTransaction("b", "view", time.Millisecond)
		in.Weakened([]string{"k"})
	}
}

func TestRequireBearer(t *testing.T) {
	tok := secret.New([]byte("0123456789abcdef-token"))
	defer tok.Wipe()
	mux := Mux(NewHealth(), NewMetrics(), MuxOptions{Path: "/m", Token: tok})
	for _, c := range []struct {
		path, auth string
		want       int
	}{
		{"/m", "", http.StatusUnauthorized},
		{"/m", "Bearer wrong", http.StatusUnauthorized},
		{"/m", "Bearer 0123456789abcdef-token", http.StatusOK},
		{"/healthz", "", http.StatusOK},
		{"/metrics", "Bearer 0123456789abcdef-token", http.StatusNotFound},
	} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, c.path, nil)
		if c.auth != "" {
			req.Header.Set("Authorization", c.auth)
		}
		mux.ServeHTTP(rec, req)
		if rec.Code != c.want {
			t.Errorf("%s %q: status %d, want %d", c.path, c.auth, rec.Code, c.want)
		}
		if strings.Contains(rec.Body.String(), "0123456789abcdef") {
			t.Errorf("%s: response echoes the token", c.path)
		}
	}
}

func TestCheckMetricsAuth(t *testing.T) {
	short := secret.New([]byte("short"))
	long := secret.New([]byte("0123456789abcdef"))
	defer short.Wipe()
	defer long.Wipe()
	for _, c := range []struct {
		addr  string
		tok   secret.Value
		allow bool
		ok    bool
	}{
		{"127.0.0.1:9792", secret.Value{}, false, true},
		{"[::1]:9792", secret.Value{}, false, true},
		{"localhost:9792", secret.Value{}, false, true},
		{"0.0.0.0:9792", secret.Value{}, false, false},
		{":9792", secret.Value{}, false, false},
		{"10.0.0.5:9792", long, false, true},
		{"10.0.0.5:9792", secret.Value{}, true, true},
		{"127.0.0.1:9792", short, false, false},
	} {
		err := CheckMetricsAuth(c.addr, c.tok, c.allow)
		if (err == nil) != c.ok {
			t.Errorf("%s allow=%v: err %v, want ok=%v", c.addr, c.allow, err, c.ok)
		}
	}
}

func scrape(t *testing.T, m *Metrics) string {
	t.Helper()
	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body, _ := io.ReadAll(rec.Result().Body)
	if rec.Code != 200 {
		t.Fatalf("status %d", rec.Code)
	}
	return string(body)
}

func TestInstruments(t *testing.T) {
	m := NewMetrics()
	in := NewInstruments(m, nil)
	in.GuardRefusal("anthropic", "claude-laptop")
	in.StoreHealth("bao", false, time.Unix(1700000000, 0), 12, true)
	in.StoreRefresh("bao", 250*time.Millisecond, true)
	in.AuditDropped("kafka", 3)
	in.AuditDelivered("db", 1)
	in.StateTransaction("sqlite", "update", time.Millisecond)
	in.Weakened([]string{"state.sqlite.allow-network-filesystem"})
	in.Redaction("anthropic", "known", "a1", 2)
	in.GuardRepair("anthropic", "known", "a1")
	in.FallbackHit("anthropic", "entropy", "a1")
	body := scrape(t, m)
	for _, want := range []string{
		`scrim_guard_refusals_total{agent="claude-laptop",provider="anthropic"} 1`,
		`scrim_store_up{store="bao"} 0`,
		`scrim_store_degraded{store="bao"} 1`,
		`scrim_store_values_loaded{store="bao"} 12`,
		`scrim_store_last_refresh_timestamp_seconds{store="bao"} 1.7e+09`,
		`scrim_store_refresh_duration_seconds_count{store="bao"} 1`,
		`scrim_store_refresh_errors_total{store="bao"} 1`,
		`scrim_store_staleness_seconds{store="bao"} `,
		`scrim_audit_dropped_total{sink="kafka"} 3`,
		`scrim_audit_delivered_total{sink="db"} 1`,
		`scrim_state_transaction_seconds_count{backend="sqlite",kind="update"} 1`,
		`scrim_config_weakened_settings{setting="state.sqlite.allow-network-filesystem"} 1`,
		`scrim_redaction_replacements_total{agent="a1",provider="anthropic",rule="known"} 2`,
		`scrim_guard_repairs_total{agent="a1",provider="anthropic",rule="known"} 1`,
		`scrim_detector_fallback_hits_total{agent="a1",provider="anthropic",rule="entropy"} 1`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %s", want)
		}
	}
}

func TestMetricLabelsAndPageScrubbed(t *testing.T) {
	sc := NewValueScrubber(secret.FromString(testValue))
	m := NewMetrics()
	m.Scrubber = sc
	NewInstruments(m, sc).Redaction("anthropic", "rule", testValue, 1)
	// A collector registered without the instruments: only the page scrub
	// stands between it and the scrape.
	m.Counter("raw", "total", "x", "l").WithLabelValues(testValue).Inc()
	if body := scrape(t, m); strings.Contains(body, "sk-test-0123456789abcdef") {
		t.Fatalf("metrics page holds the value:\n%s", body)
	}
}

func TestMuxEndpoints(t *testing.T) {
	h := NewHealth()
	h.Live("process", func(context.Context) error { return nil })
	h.Ready("store:bao", func(context.Context) error { return errors.New("never loaded") })
	mux := Mux(h, NewMetrics(), MuxOptions{})
	for path, want := range map[string]int{"/healthz": 200, "/livez": 200, "/readyz": 503, "/metrics": 200, "/nope": 404} {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != want {
			t.Errorf("%s = %d, want %d", path, rec.Code, want)
		}
		if path == "/readyz" && !strings.Contains(rec.Body.String(), "store:bao") {
			t.Errorf("readyz does not name the store: %s", rec.Body.String())
		}
	}
}

func TestTraceContextPropagated(t *testing.T) {
	exp := tracetest.NewInMemoryExporter()
	tr, err := NewTracing(TraceOptions{Exporter: exp, SampleRatio: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tr.Shutdown(context.Background()) }()
	h := tr.Middleware("scrim.request", httpHandlerFunc(func(ctx context.Context) {
		_, end := Timed(ctx, tr.Tracer, SpanRedaction)
		end(nil)
	}))
	req := httptest.NewRequest(http.MethodPost, "/v1/messages", nil)
	req.Header.Set("traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
	h.ServeHTTP(httptest.NewRecorder(), req)
	_ = tr.ForceFlush(context.Background())
	spans := exp.GetSpans()
	if len(spans) != 2 {
		t.Fatalf("got %d spans", len(spans))
	}
	for _, s := range spans {
		if s.SpanContext.TraceID().String() != "4bf92f3577b34da6a3ce929d0e0e4736" {
			t.Errorf("span %s is not in the incoming trace", s.Name)
		}
		if s.Name == "scrim.request" && s.Parent.SpanID().String() != "00f067aa0ba902b7" {
			t.Errorf("server span parent = %s", s.Parent.SpanID())
		}
	}
	out := make(map[string][]string)
	tr.Inject(trace.ContextWithSpanContext(context.Background(), spans[0].SpanContext), out)
	if len(out["Traceparent"]) == 0 {
		t.Errorf("Inject wrote %v", out)
	}
}

func TestTracingConfigValidation(t *testing.T) {
	tr, err := NewTracing(TraceOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, span := tr.Tracer.Start(context.Background(), "x"); span.IsRecording() {
		t.Error("disabled tracer records spans")
	}
	if _, err := NewTracing(TraceOptions{Endpoint: "ftp://x"}); err == nil {
		t.Error("accepted ftp endpoint")
	}
	if _, err := NewTracing(TraceOptions{Endpoint: "http://127.0.0.1:4318", SampleRatio: 2}); err == nil {
		t.Error("accepted sample ratio 2")
	}
	ok, err := NewTracing(TraceOptions{Endpoint: "http://127.0.0.1:4318", SampleRatio: 1})
	if err != nil {
		t.Fatal(err)
	}
	_ = ok.Shutdown(context.Background())
}

func TestSpansScrubbed(t *testing.T) {
	exp := tracetest.NewInMemoryExporter()
	tr, _ := NewTracing(TraceOptions{Exporter: exp, SampleRatio: 1, Scrubber: NewValueScrubber(secret.FromString(testValue))})
	ctx, span := tr.Tracer.Start(context.Background(), "op "+testValue,
		trace.WithAttributes(attribute.String("k", testValue), attribute.StringSlice("ks", []string{testValue})))
	span.AddEvent("ev "+testValue, trace.WithAttributes(attribute.String("e", testValue)))
	_, end := Timed(ctx, tr.Tracer, SpanUpstream)
	end(errors.New("upstream echoed " + testValue))
	span.End()
	_ = tr.ForceFlush(context.Background())
	if dump := dumpSpans(exp); strings.Contains(dump, "sk-test-0123456789abcdef") {
		t.Fatalf("spans hold the value: %s", dump)
	}
}

func dumpSpans(exp *tracetest.InMemoryExporter) string {
	var b strings.Builder
	for _, s := range exp.GetSpans() {
		b.WriteString(s.Name + "\n" + s.Status.Description + "\n")
		for _, a := range s.Attributes {
			b.WriteString(string(a.Key) + "=" + a.Value.String() + "\n")
		}
		for _, e := range s.Events {
			b.WriteString(e.Name + "\n")
			for _, a := range e.Attributes {
				b.WriteString(string(a.Key) + "=" + a.Value.String() + "\n")
			}
		}
	}
	return b.String()
}
