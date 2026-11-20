// SPDX-License-Identifier: AGPL-3.0-only

// Package obs is scrim's logging, metrics, tracing and health surface
// (specs/observability). Nothing it emits may contain a secret value:
// secret.Value renders as a marker by type, raw byte slices are never
// printed, and every string passes a [Scrubber] that replaces known values
// that reached a message by another route (an upstream error that echoes a
// value). Logs are scrubbed twice, per attribute and again over the
// finished line; metric pages, span data and health responses are scrubbed
// before they leave the process.
package obs

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"

	"go.opentelemetry.io/otel/trace"

	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/secret"
)

// Settings owned by this package.
var (
	LogLevel = config.Register(config.Spec[string]{
		Key:         "log.level",
		Default:     "info",
		Enum:        []string{"debug", "info", "warn", "error"},
		Description: "Minimum level of log records.",
		Flag:        true,
	})
	LogFormat = config.Register(config.Spec[string]{
		Key:         "log.format",
		Default:     "text",
		Enum:        []string{"text", "json"},
		Description: "Log record format: text (logfmt) or json, one object per line.",
		Flag:        true,
	})
)

// Record keys every log line carries or may carry.
const (
	KeyComponent = "component"
	KeyAgent     = "agent"
	KeyRequestID = "request_id"
	KeyTraceID   = "trace_id"
	KeySpanID    = "span_id"
)

// DefaultComponent is the component of a record logged without
// [WithComponent].
const DefaultComponent = "scrim"

// Scrubber replaces known secret values in s with [secret.Marker]. The real
// implementation is fed by the redaction set; it must be safe for concurrent
// use and fast on strings that contain nothing.
type Scrubber interface {
	Scrub(s string) string
}

// ScrubFunc adapts a function to [Scrubber].
type ScrubFunc func(string) string

// Scrub implements [Scrubber].
func (f ScrubFunc) Scrub(s string) string { return f(s) }

type noScrub struct{}

func (noScrub) Scrub(s string) string { return s }

// ScrubberSlot holds the process scrubber. It starts as a no-op and is
// replaced when the first redaction set loads. Every consumer reads it at
// use time, so a value loaded later is still scrubbed from an attribute
// bound earlier.
type ScrubberSlot struct{ v atomic.Value }

// Set installs s.
func (p *ScrubberSlot) Set(s Scrubber) { p.v.Store(&s) }

// Scrub implements [Scrubber].
func (p *ScrubberSlot) Scrub(s string) string {
	if p == nil {
		return s
	}
	if v, ok := p.v.Load().(*Scrubber); ok && *v != nil {
		return (*v).Scrub(s)
	}
	return s
}

// LogOptions configures [NewLogger].
type LogOptions struct {
	Level  slog.Leveler
	Format string // "text" or "json"
	// Scrubber filters every message, string attribute and finished line;
	// nil means none.
	Scrubber Scrubber
}

// NewLogger returns a logger writing to w with secret-safe attribute
// handling. Records carry `time`, `level`, `component` (DefaultComponent
// unless set with [WithComponent]) and `msg`, plus `agent`, `request_id`,
// `trace_id` and `span_id` when the context carries them ([WithAgent],
// [WithRequestID], an OpenTelemetry span).
func NewLogger(w io.Writer, o LogOptions) *slog.Logger {
	sc := o.Scrubber
	if sc == nil {
		sc = noScrub{}
	}
	sw := &scrubWriter{w: w, sc: sc}
	opts := &slog.HandlerOptions{Level: o.Level, ReplaceAttr: replacer(sc)}
	var h slog.Handler
	if o.Format == "json" {
		h = slog.NewJSONHandler(sw, opts)
	} else {
		h = slog.NewTextHandler(sw, opts)
	}
	return slog.New(&scrubHandler{inner: h, sc: sc, component: DefaultComponent})
}

// LoggerFromConfig builds the process logger from log.level and log.format.
func LoggerFromConfig(w io.Writer, c *config.Config, sc Scrubber) (*slog.Logger, error) {
	var lvl slog.Level
	if err := lvl.UnmarshalText([]byte(LogLevel.Get(c))); err != nil {
		return nil, fmt.Errorf("log.level: %w", err)
	}
	return NewLogger(w, LogOptions{Level: lvl, Format: LogFormat.Get(c), Scrubber: sc}), nil
}

// WithComponent tags every record of l with component=name.
func WithComponent(l *slog.Logger, name string) *slog.Logger {
	return l.With(slog.String(KeyComponent, name))
}

type ctxKey int

const (
	agentKey ctxKey = iota
	requestKey
)

// WithAgent returns ctx carrying the calling agent's identity for logs.
func WithAgent(ctx context.Context, agentID string) context.Context {
	return context.WithValue(ctx, agentKey, agentID)
}

// WithRequestID returns ctx carrying a request correlation id for logs.
func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestKey, id)
}

// AgentFrom returns the agent identity in ctx, if any.
func AgentFrom(ctx context.Context) string { s, _ := ctx.Value(agentKey).(string); return s }

// RequestIDFrom returns the request correlation id in ctx, if any.
func RequestIDFrom(ctx context.Context) string { s, _ := ctx.Value(requestKey).(string); return s }

// replacer makes attribute values safe: byte slices never print, strings
// and errors are scrubbed. secret.Value already renders as the marker
// through slog.LogValuer before this runs.
func replacer(sc Scrubber) func([]string, slog.Attr) slog.Attr {
	return func(_ []string, a slog.Attr) slog.Attr {
		if a.Value.Kind() == slog.KindAny {
			switch v := a.Value.Any().(type) {
			case []byte:
				a.Value = slog.StringValue(fmt.Sprintf("[%d bytes]", len(v)))
				return a
			case secret.Value:
				a.Value = slog.StringValue(secret.Marker)
				return a
			case error:
				a.Value = slog.StringValue(sc.Scrub(v.Error()))
				return a
			case fmt.Stringer:
				a.Value = slog.StringValue(sc.Scrub(v.String()))
				return a
			default:
				a.Value = slog.StringValue(sc.Scrub(fmt.Sprintf("%+v", v)))
				return a
			}
		}
		if a.Value.Kind() == slog.KindString {
			a.Value = slog.StringValue(sc.Scrub(a.Value.String()))
		}
		return a
	}
}

// scrubHandler scrubs the message, which ReplaceAttr does not see, adds the
// context fields, and applies bound attributes and groups at Handle time
// rather than at With time: the built-in handlers run ReplaceAttr on bound
// attributes once, when bound, and a value loaded after that would
// otherwise stay in every later line.
type scrubHandler struct {
	inner     slog.Handler
	sc        Scrubber
	component string
	ops       []handlerOp
}

type handlerOp struct {
	group string
	attrs []slog.Attr
}

func (h *scrubHandler) clone() *scrubHandler {
	c := *h
	c.ops = append([]handlerOp(nil), h.ops...)
	return &c
}

func (h *scrubHandler) Enabled(ctx context.Context, l slog.Level) bool {
	return h.inner.Enabled(ctx, l)
}

func (h *scrubHandler) WithAttrs(as []slog.Attr) slog.Handler {
	if len(as) == 0 {
		return h
	}
	c := h.clone()
	keep := make([]slog.Attr, 0, len(as))
	for _, a := range as {
		// A top-level component replaces the default rather than
		// repeating the key.
		if a.Key == KeyComponent && len(c.ops) == 0 && a.Value.Kind() == slog.KindString {
			c.component = a.Value.String()
			continue
		}
		keep = append(keep, a)
	}
	if len(keep) > 0 {
		c.ops = append(c.ops, handlerOp{attrs: keep})
	}
	return c
}

func (h *scrubHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	c := h.clone()
	c.ops = append(c.ops, handlerOp{group: name})
	return c
}

func (h *scrubHandler) Handle(ctx context.Context, r slog.Record) error {
	head := []slog.Attr{slog.String(KeyComponent, h.component)}
	if a := AgentFrom(ctx); a != "" {
		head = append(head, slog.String(KeyAgent, a))
	}
	if id := RequestIDFrom(ctx); id != "" {
		head = append(head, slog.String(KeyRequestID, id))
	}
	if sc := trace.SpanContextFromContext(ctx); sc.IsValid() {
		head = append(head, slog.String(KeyTraceID, sc.TraceID().String()), slog.String(KeySpanID, sc.SpanID().String()))
	}
	inner := h.inner.WithAttrs(head)
	for _, op := range h.ops {
		if op.group != "" {
			inner = inner.WithGroup(op.group)
		} else {
			inner = inner.WithAttrs(op.attrs)
		}
	}
	nr := slog.NewRecord(r.Time, r.Level, h.sc.Scrub(r.Message), r.PC)
	r.Attrs(func(a slog.Attr) bool { nr.AddAttrs(a); return true })
	return inner.Handle(ctx, nr)
}

// scrubWriter scrubs each finished line, which also catches a value in the
// JSON-escaped form the handler wrote. slog handlers write one record per
// Write call.
type scrubWriter struct {
	mu sync.Mutex
	w  io.Writer
	sc Scrubber
}

func (s *scrubWriter) Write(p []byte) (int, error) {
	out := s.sc.Scrub(string(p))
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := io.WriteString(s.w, out); err != nil {
		return 0, err
	}
	return len(p), nil
}

// ReplaceAll is a simple [Scrubber] over a fixed list of plain strings, for
// tests and small sets. [NewValueScrubber] also matches encoded forms; the
// control plane's real scrubber is built from the redaction set.
func ReplaceAll(values ...string) Scrubber {
	pairs := make([]string, 0, 2*len(values))
	for _, v := range values {
		if v != "" {
			pairs = append(pairs, v, secret.Marker)
		}
	}
	r := strings.NewReplacer(pairs...)
	return ScrubFunc(r.Replace)
}
