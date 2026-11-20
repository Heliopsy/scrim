// SPDX-License-Identifier: AGPL-3.0-only

// Package obs is scrim's logging, metrics and health surface
// (specs/observability). Nothing it emits may contain a secret value:
// secret.Value renders as a marker by type, raw byte slices are never
// printed, and every string passes a [Scrubber] that replaces known values
// that reached a message by another route (an upstream error that echoes a
// value).
package obs

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync/atomic"

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
// replaced when the first redaction set loads.
type ScrubberSlot struct{ v atomic.Value }

// Set installs s.
func (p *ScrubberSlot) Set(s Scrubber) { p.v.Store(&s) }

// Scrub implements [Scrubber].
func (p *ScrubberSlot) Scrub(s string) string {
	if v, ok := p.v.Load().(*Scrubber); ok {
		return (*v).Scrub(s)
	}
	return s
}

// LogOptions configures [NewLogger].
type LogOptions struct {
	Level  slog.Leveler
	Format string // "text" or "json"
	// Scrubber filters every message and string attribute; nil means none.
	Scrubber Scrubber
}

// NewLogger returns a logger writing to w with secret-safe attribute
// handling. Records carry `time`, `level`, `msg` and, through
// [WithComponent], `component`.
func NewLogger(w io.Writer, o LogOptions) *slog.Logger {
	sc := o.Scrubber
	if sc == nil {
		sc = noScrub{}
	}
	opts := &slog.HandlerOptions{Level: o.Level, ReplaceAttr: replacer(sc)}
	var h slog.Handler
	if o.Format == "json" {
		h = slog.NewJSONHandler(w, opts)
	} else {
		h = slog.NewTextHandler(w, opts)
	}
	return slog.New(&scrubHandler{Handler: h, sc: sc})
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
	return l.With(slog.String("component", name))
}

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

// scrubHandler scrubs the message, which ReplaceAttr does not see.
type scrubHandler struct {
	slog.Handler
	sc Scrubber
}

func (h *scrubHandler) Handle(ctx context.Context, r slog.Record) error {
	if msg := h.sc.Scrub(r.Message); msg != r.Message {
		nr := slog.NewRecord(r.Time, r.Level, msg, r.PC)
		r.Attrs(func(a slog.Attr) bool { nr.AddAttrs(a); return true })
		r = nr
	}
	return h.Handler.Handle(ctx, r)
}

func (h *scrubHandler) WithAttrs(as []slog.Attr) slog.Handler {
	return &scrubHandler{Handler: h.Handler.WithAttrs(as), sc: h.sc}
}

func (h *scrubHandler) WithGroup(name string) slog.Handler {
	return &scrubHandler{Handler: h.Handler.WithGroup(name), sc: h.sc}
}

// ReplaceAll is a simple [Scrubber] over a fixed list of plain strings, for
// tests and small sets. The control plane's real scrubber is built from the
// redaction set.
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
