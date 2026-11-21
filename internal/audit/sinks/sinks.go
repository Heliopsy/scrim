// SPDX-License-Identifier: AGPL-3.0-only

// Package sinks holds the external audit sinks, OTLP logs, Loki and Kafka
// (specs/state-and-scaling "Multiple audit sinks", "Audit backpressure is
// explicit"; design D9), and builds the [audit.Fanout] that feeds them from
// the audit.* settings. Each sink is optional and additive: the database
// audit log, written in the transaction of the change it records, stays the
// record, and every external sink receives a copy.
//
// What a sink sends is the machine-readable audit record of `scrim audit
// log --output json` (auditlog.Record), after every string has passed the
// value scrubber: metadata only, never a value.
package sinks

import (
	"encoding/json"
	"fmt"
	"slices"
	"time"

	"github.com/heliopsy/scrim/internal/audit"
	"github.com/heliopsy/scrim/internal/auditlog"
	"github.com/heliopsy/scrim/internal/config"
)

// Sink names.
const (
	DB    = "db"
	OTLP  = "otlp"
	Loki  = "loki"
	Kafka = "kafka"
)

// Sinks selects the audit sinks.
var Sinks = config.Register(config.Spec[[]string]{
	Key:     "audit.sinks",
	Default: []string{DB},
	Description: "Where audit entries go: db (the state backend's audit log, always written, in the transaction of the change it records) " +
		"plus any of otlp, loki and kafka, each fed from its own bounded queue with the backpressure policy audit.<sink>.policy.",
	Validate: func(v []string) error {
		for _, s := range v {
			if !slices.Contains([]string{DB, OTLP, Loki, Kafka}, s) {
				return fmt.Errorf("unknown sink %q (want db, otlp, loki or kafka)", s)
			}
		}
		return nil
	},
	RestartRequired: true,
})

// common are the backpressure settings every external sink has.
type common struct {
	p    config.Key[string]
	t, w config.Key[time.Duration]
	q, b config.Key[int]
}

func atLeast(n int) func(int) error {
	return func(v int) error {
		if v < n {
			return fmt.Errorf("must be at least %d", n)
		}
		return nil
	}
}

func durBetween(lo, hi time.Duration) func(time.Duration) error {
	return func(d time.Duration) error {
		if d < lo || d > hi {
			return fmt.Errorf("must be between %s and %s", lo, hi)
		}
		return nil
	}
}

func commonSettings(sink string) common {
	k := "audit." + sink + "."
	return common{
		p: config.Register(config.Spec[string]{
			Key: k + "policy", Default: "drop", Enum: []string{"block", "drop"}, RestartRequired: true,
			Description: "What happens when the " + sink + " sink's queue is full because the sink is slow or down: block makes the audited " +
				"operation wait up to audit." + sink + ".timeout and then refuses it; drop lets it through and counts the entry in " +
				"scrim_audit_sink_dropped_total (it stays in the database audit log). Never silent either way.",
		}),
		t: config.Register(config.Spec[time.Duration]{
			Key: k + "timeout", Default: audit.DefaultTimeout, RestartRequired: true, Validate: durBetween(10*time.Millisecond, 5*time.Minute),
			Description: "With audit." + sink + ".policy block, how long an audited operation waits for room in the " + sink + " queue before it is refused.",
		}),
		q: config.Register(config.Spec[int]{
			Key: k + "queue-size", Default: audit.DefaultQueueSize, RestartRequired: true, Validate: atLeast(1),
			Description: "How many audit entries wait for the " + sink + " sink at most.",
		}),
		b: config.Register(config.Spec[int]{
			Key: k + "batch-size", Default: audit.DefaultBatchSize, RestartRequired: true, Validate: atLeast(1),
			Description: "How many audit entries one write to the " + sink + " sink carries at most.",
		}),
		w: config.Register(config.Spec[time.Duration]{
			Key: k + "write-timeout", Default: audit.DefaultWriteTimeout, RestartRequired: true, Validate: durBetween(100*time.Millisecond, 5*time.Minute),
			Description: "How long one write to the " + sink + " sink may take before it counts as failed and is retried.",
		}),
	}
}

func (c common) target(cfg *config.Config, s audit.Sink) (audit.Target, error) {
	p, err := audit.ParsePolicy(c.p.Get(cfg))
	if err != nil {
		return audit.Target{}, err
	}
	return audit.Target{Sink: s, Policy: p, Timeout: c.t.Get(cfg), QueueSize: c.q.Get(cfg),
		BatchSize: c.b.Get(cfg), WriteTimeout: c.w.Get(cfg)}, nil
}

var (
	otlpCommon  = commonSettings(OTLP)
	lokiCommon  = commonSettings(Loki)
	kafkaCommon = commonSettings(Kafka)
)

// Targets builds a target for every external sink audit.sinks names.
// Close the returned sinks with [CloseAll] after the fanout.
func Targets(cfg *config.Config) ([]audit.Target, error) {
	var out []audit.Target
	for _, name := range Sinks.Get(cfg) {
		var (
			s   audit.Sink
			c   common
			err error
		)
		switch name {
		case DB:
			continue
		case OTLP:
			s, err = otlpFromConfig(cfg)
			c = otlpCommon
		case Loki:
			s, err = lokiFromConfig(cfg)
			c = lokiCommon
		case Kafka:
			s, err = kafkaFromConfig(cfg)
			c = kafkaCommon
		}
		if err != nil {
			CloseAll(out)
			return nil, fmt.Errorf("audit sink %s: %w", name, err)
		}
		t, err := c.target(cfg, s)
		if err != nil {
			CloseAll(append(out, audit.Target{Sink: s}))
			return nil, err
		}
		out = append(out, t)
	}
	return out, nil
}

// closer is a sink holding connections.
type closer interface{ Close() error }

// CloseAll closes every sink that holds connections.
func CloseAll(ts []audit.Target) {
	for _, t := range ts {
		if c, ok := t.Sink.(closer); ok {
			_ = c.Close()
		}
	}
}

// encode is the JSON line every sink sends for e.
func encode(e audit.Entry) ([]byte, error) {
	return json.Marshal(auditlog.FromEntry(e))
}
