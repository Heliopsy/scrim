// SPDX-License-Identifier: AGPL-3.0-only

package obs

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"

	"github.com/heliopsy/scrim/internal/config"
)

// Span names scrim emits around the stages of a request.
const (
	SpanRedaction    = "scrim.redaction"
	SpanGuard        = "scrim.guard"
	SpanUpstream     = "scrim.upstream"
	SpanResolution   = "scrim.resolution"
	SpanPolicy       = "scrim.policy"
	SpanApprovalWait = "scrim.approval_wait"
)

// Settings owned by tracing.
var (
	TracingEndpoint = config.Register(config.Spec[string]{
		Key: "tracing.endpoint",
		Description: "OTLP/HTTP collector URL for traces, for example http://127.0.0.1:4318. " +
			"Empty disables export; incoming W3C trace context is still propagated.",
		Flag:            true,
		RestartRequired: true,
	})
	TracingSampleRatio = config.Register(config.Spec[float64]{
		Key:         "tracing.sample-ratio",
		Default:     1,
		Description: "Fraction of new root traces sampled, 0 to 1. A sampled incoming parent is always followed.",
		Validate: func(f float64) error {
			if f < 0 || f > 1 {
				return fmt.Errorf("%v is not between 0 and 1", f)
			}
			return nil
		},
		RestartRequired: true,
	})
)

// TracingFromConfig builds tracing from tracing.endpoint and
// tracing.sample-ratio.
func TracingFromConfig(c *config.Config, version string, sc Scrubber) (*Tracing, error) {
	return NewTracing(TraceOptions{
		Endpoint:    TracingEndpoint.Get(c),
		SampleRatio: TracingSampleRatio.Get(c),
		Version:     version,
		Scrubber:    sc,
	})
}

// TracerName is the instrumentation scope of scrim's spans.
const TracerName = "github.com/heliopsy/scrim"

// TraceOptions configures [NewTracing].
type TraceOptions struct {
	// Endpoint is the OTLP/HTTP collector URL, for example
	// http://127.0.0.1:4318. Empty disables tracing: spans are not recorded,
	// but incoming trace context is still propagated.
	Endpoint string
	// SampleRatio is the fraction of new root traces sampled, 0 to 1. A
	// sampled parent is always followed.
	SampleRatio float64
	// Version is reported as service.version.
	Version string
	// Scrubber is applied to every span name, attribute, event and status
	// before export; nil means none.
	Scrubber Scrubber
	// Exporter replaces the OTLP exporter, for tests.
	Exporter sdktrace.SpanExporter
}

// Tracing owns the tracer provider and its shutdown.
type Tracing struct {
	Tracer     trace.Tracer
	Propagator propagation.TextMapPropagator
	provider   *sdktrace.TracerProvider
}

// NewTracing builds the tracer. With no endpoint and no exporter it returns a
// no-op tracer that still propagates W3C trace context.
func NewTracing(o TraceOptions) (*Tracing, error) {
	prop := propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{})
	exp := o.Exporter
	if exp == nil && o.Endpoint == "" {
		return &Tracing{Tracer: noop.NewTracerProvider().Tracer(TracerName), Propagator: prop}, nil
	}
	if exp == nil {
		u, err := url.Parse(o.Endpoint)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return nil, fmt.Errorf("tracing.endpoint %q must be an http or https URL", o.Endpoint)
		}
		opts := []otlptracehttp.Option{otlptracehttp.WithEndpointURL(u.String())}
		if u.Scheme == "http" {
			opts = append(opts, otlptracehttp.WithInsecure())
		}
		exp, err = otlptracehttp.New(context.Background(), opts...)
		if err != nil {
			return nil, fmt.Errorf("creating OTLP exporter: %w", err)
		}
	}
	ratio := o.SampleRatio
	if ratio < 0 || ratio > 1 {
		return nil, fmt.Errorf("tracing.sample-ratio %v must be between 0 and 1", ratio)
	}
	res := resource.NewWithAttributes(semconv.SchemaURL,
		semconv.ServiceName("scrim"), semconv.ServiceVersion(o.Version))
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(&scrubExporter{next: exp, sc: orNoScrub(o.Scrubber)}),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.TraceIDRatioBased(ratio))),
	)
	return &Tracing{Tracer: tp.Tracer(TracerName), Propagator: prop, provider: tp}, nil
}

// Shutdown flushes and stops the exporter.
func (t *Tracing) Shutdown(ctx context.Context) error {
	if t.provider == nil {
		return nil
	}
	return t.provider.Shutdown(ctx)
}

// ForceFlush exports every finished span now.
func (t *Tracing) ForceFlush(ctx context.Context) error {
	if t.provider == nil {
		return nil
	}
	return t.provider.ForceFlush(ctx)
}

// Extract returns ctx carrying the trace context of the incoming headers, so
// scrim's spans become children of the caller's trace.
func (t *Tracing) Extract(ctx context.Context, h http.Header) context.Context {
	return t.Propagator.Extract(ctx, propagation.HeaderCarrier(h))
}

// Inject writes ctx's trace context into outgoing headers.
func (t *Tracing) Inject(ctx context.Context, h http.Header) {
	t.Propagator.Inject(ctx, propagation.HeaderCarrier(h))
}

// Middleware extracts incoming trace context and starts a server span named
// name around next.
func (t *Tracing) Middleware(name string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := t.Extract(r.Context(), r.Header)
		ctx, span := t.Tracer.Start(ctx, name, trace.WithSpanKind(trace.SpanKindServer),
			trace.WithAttributes(attribute.String("http.request.method", r.Method)))
		defer span.End()
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// scrubExporter rewrites every span through the scrubber before handing it
// to the real exporter. Attributes are otherwise free text set by many
// packages; this is the one place all of them pass.
type scrubExporter struct {
	next sdktrace.SpanExporter
	sc   Scrubber
}

func (e *scrubExporter) ExportSpans(ctx context.Context, spans []sdktrace.ReadOnlySpan) error {
	out := make([]sdktrace.ReadOnlySpan, len(spans))
	for i, s := range spans {
		out[i] = &scrubbedSpan{ReadOnlySpan: s, sc: e.sc}
	}
	return e.next.ExportSpans(ctx, out)
}

func (e *scrubExporter) Shutdown(ctx context.Context) error { return e.next.Shutdown(ctx) }

type scrubbedSpan struct {
	sdktrace.ReadOnlySpan
	sc Scrubber
}

func (s *scrubbedSpan) Name() string { return s.sc.Scrub(s.ReadOnlySpan.Name()) }

func (s *scrubbedSpan) Attributes() []attribute.KeyValue {
	return scrubKVs(s.sc, s.ReadOnlySpan.Attributes())
}

func (s *scrubbedSpan) Events() []sdktrace.Event {
	evs := s.ReadOnlySpan.Events()
	out := make([]sdktrace.Event, len(evs))
	for i, ev := range evs {
		ev.Name = s.sc.Scrub(ev.Name)
		ev.Attributes = scrubKVs(s.sc, ev.Attributes)
		out[i] = ev
	}
	return out
}

func (s *scrubbedSpan) Links() []sdktrace.Link {
	ls := s.ReadOnlySpan.Links()
	out := make([]sdktrace.Link, len(ls))
	for i, l := range ls {
		l.Attributes = scrubKVs(s.sc, l.Attributes)
		out[i] = l
	}
	return out
}

func (s *scrubbedSpan) Status() sdktrace.Status {
	st := s.ReadOnlySpan.Status()
	st.Description = s.sc.Scrub(st.Description)
	return st
}

func scrubKVs(sc Scrubber, kvs []attribute.KeyValue) []attribute.KeyValue {
	out := make([]attribute.KeyValue, len(kvs))
	for i, kv := range kvs {
		switch kv.Value.Type() {
		case attribute.STRING:
			kv.Value = attribute.StringValue(sc.Scrub(kv.Value.AsString()))
		case attribute.STRINGSLICE:
			ss := kv.Value.AsStringSlice()
			for j := range ss {
				ss[j] = sc.Scrub(ss[j])
			}
			kv.Value = attribute.StringSliceValue(ss)
		}
		kv.Key = attribute.Key(sc.Scrub(string(kv.Key)))
		out[i] = kv
	}
	return out
}

func orNoScrub(sc Scrubber) Scrubber {
	if sc == nil {
		return noScrub{}
	}
	return sc
}

// Timed starts a span named name and returns a function that ends it and
// returns the elapsed time, for stages that also feed a latency histogram.
func Timed(ctx context.Context, tr trace.Tracer, name string, attrs ...attribute.KeyValue) (context.Context, func(err error) time.Duration) {
	start := time.Now()
	ctx, span := tr.Start(ctx, name, trace.WithAttributes(attrs...))
	return ctx, func(err error) time.Duration {
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, strings.TrimSpace(err.Error()))
		}
		span.End()
		return time.Since(start)
	}
}
