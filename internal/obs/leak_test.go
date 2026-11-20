// SPDX-License-Identifier: AGPL-3.0-only

package obs

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"

	"github.com/heliopsy/scrim/internal/secret"
)

// seeded are generated test values, never real secrets.
var seeded = []string{
	"sk-ant-api03-LEAKTEST-9f8e7d6c5b4a39281706f5e4d3c2b1a0",
	"ghp_LEAKTESTabcdefghijklmnopqrstuvwxyz0123",
	"p@ss w0rd&with=specials/+\"quotes\"",
}

// forms lists the encodings a leaked value plausibly takes.
func forms(v string) map[string]string {
	return map[string]string{
		"raw":    v,
		"query":  url.QueryEscape(v),
		"hex":    hex.EncodeToString([]byte(v)),
		"base64": base64.StdEncoding.EncodeToString([]byte(v)),
		"b64url": base64.RawURLEncoding.EncodeToString([]byte(v)),
	}
}

// TestTelemetryLeak is the 5.3 leak check: it seeds known values, drives
// every telemetry path with them (log messages, attributes, errors, context
// fields, metric labels, span names, attributes, events, statuses and
// readiness errors), then greps all of the logs, the metrics page, the
// exported spans and the health responses for every value in every
// encoding.
func TestTelemetryLeak(t *testing.T) {
	vals := make([]secret.Value, len(seeded))
	for i, s := range seeded {
		vals[i] = secret.FromString(s)
	}
	slot := &ScrubberSlot{}
	slot.Set(NewValueScrubber(vals...))

	var jsonLogs, textLogs bytes.Buffer
	loggers := []*slog.Logger{
		NewLogger(&jsonLogs, LogOptions{Format: "json", Level: slog.LevelDebug, Scrubber: slot}),
		NewLogger(&textLogs, LogOptions{Format: "text", Level: slog.LevelDebug, Scrubber: slot}),
	}
	metrics := NewMetrics()
	metrics.Scrubber = slot
	in := NewInstruments(metrics, slot)
	exp := tracetest.NewInMemoryExporter()
	tracing, err := NewTracing(TraceOptions{Exporter: exp, SampleRatio: 1, Scrubber: slot})
	if err != nil {
		t.Fatal(err)
	}
	health := NewHealth()
	health.Scrubber = slot
	// A collector registered without the instruments: only the page scrub
	// guards it.
	raw := metrics.Counter("leak", "unguarded_total", "Unguarded collector.", "l")

	for i, v := range seeded {
		for name, f := range forms(v) {
			ctx := WithRequestID(WithAgent(context.Background(), f), f)
			ctx, span := tracing.Tracer.Start(ctx, "request "+f, trace.WithAttributes(attribute.String("arg", f)))
			for _, l := range loggers {
				l.With("bound", f).ErrorContext(ctx, "upstream error: "+f,
					"form", name, "value", vals[i], "err", fmt.Errorf("wrapped: %w", errors.New(f)),
					"body", []byte(`{"key":"`+f+`"}`), "headers", map[string][]string{"Authorization": {"Bearer " + f}},
					slog.Group("g", "inner", f))
			}
			in.Redaction("anthropic", "rule-"+f, f, 1)
			in.GuardRefusal(f, "agent")
			in.StoreHealth(f, false, time.Now(), 1, true)
			raw.WithLabelValues(f).Inc()
			span.AddEvent("event "+f, trace.WithAttributes(attribute.String("detail", f)))
			_, end := Timed(ctx, tracing.Tracer, SpanGuard, attribute.String("rule", f))
			end(errors.New("guard saw " + f))
			span.End()
			health.Ready("store:"+name+fmt.Sprint(i), func(context.Context) error { return errors.New("store said " + f) })
		}
	}
	_ = tracing.ForceFlush(context.Background())

	var dump strings.Builder
	dump.WriteString(jsonLogs.String())
	dump.WriteString(textLogs.String())
	mux := Mux(health, metrics)
	for _, p := range []string{"/metrics", "/readyz", "/healthz"} {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, p, nil))
		dump.WriteString(rec.Body.String())
	}
	dump.WriteString(dumpSpans(exp))

	out := dump.String()
	if !strings.Contains(out, secret.Marker) {
		t.Fatal("no marker anywhere: the test did not exercise the scrubber")
	}
	for i, v := range seeded {
		for name, f := range forms(v) {
			if strings.Contains(out, f) {
				t.Errorf("seeded value %d found in telemetry as %s", i, name)
			}
		}
	}
}
