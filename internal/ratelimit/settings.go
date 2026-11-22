// SPDX-License-Identifier: AGPL-3.0-only

package ratelimit

import (
	"errors"
	"fmt"
	"time"

	"github.com/heliopsy/scrim/internal/config"
)

// BackendSetting selects the rate-limit backend.
var BackendSetting = config.Register(config.Spec[string]{
	Key:     "ratelimit.backend",
	Default: "local",
	Enum:    []string{"local", "valkey"},
	Description: "Where per-agent rate limits are counted. local counts in each replica's memory, so with several replicas an agent " +
		"can get up to that many times each limit (approximate); valkey counts in Valkey (valkey.*), one exact limit shared by every replica. " +
		"When the backend cannot answer, the request is refused.",
	Flag:            true,
	RestartRequired: true,
})

type classSettings struct {
	rate     config.Key[int]
	interval config.Key[time.Duration]
	burst    config.Key[int]
}

func nonNegative(n int) error {
	if n < 0 {
		return errors.New("must not be negative")
	}
	return nil
}

func positiveDuration(d time.Duration) error {
	if d < time.Second || d > 24*time.Hour {
		return errors.New("must be between 1s and 24h")
	}
	return nil
}

func class(name, what string, rate int, interval time.Duration, burst int) classSettings {
	return classSettings{
		rate: config.Register(config.Spec[int]{
			Key: "ratelimit." + name + ".rate", Default: rate, Validate: nonNegative,
			Description: fmt.Sprintf("How many %s one agent may make per ratelimit.%s.interval, after its burst; 0 turns the limit off.", what, name),
		}),
		interval: config.Register(config.Spec[time.Duration]{
			Key: "ratelimit." + name + ".interval", Default: interval, Validate: positiveDuration,
			Description: fmt.Sprintf("The interval ratelimit.%s.rate counts over.", name),
		}),
		burst: config.Register(config.Spec[int]{
			Key: "ratelimit." + name + ".burst", Default: burst, Validate: nonNegative,
			Description: fmt.Sprintf("How many %s one agent may make at once before ratelimit.%s.rate applies.", what, name),
		}),
	}
}

var classes = map[string]classSettings{
	ClassAgentAPI:  class(ClassAgentAPI, "agent API calls (local API and MCP tools)", 600, time.Minute, 120),
	ClassApprovals: class(ClassApprovals, "approval requests (tool calls and proxied requests held for a human)", 60, time.Hour, 10),
	ClassAsks:      class(ClassAsks, "secret_ask_human asks", 30, time.Hour, 5),
}

// Limits reads every class's limit.
func Limits(cfg *config.Config) map[string]Limit {
	out := make(map[string]Limit, len(classes))
	for name, c := range classes {
		out[name] = Limit{Rate: c.rate.Get(cfg), Interval: c.interval.Get(cfg), Burst: c.burst.Get(cfg)}
	}
	return out
}

// FromConfig opens the backend ratelimit.backend names with the configured
// limits. obs may be nil.
func FromConfig(cfg *config.Config, obs Observer) (*Set, error) {
	name := BackendSetting.Get(cfg)
	open, ok := opener(name)
	if !ok {
		return nil, fmt.Errorf("ratelimit: ratelimit.backend %q is not built into this binary (have %v)", name, backendNames())
	}
	l, err := open(cfg)
	if err != nil {
		return nil, fmt.Errorf("ratelimit: ratelimit.backend %s: %w", name, err)
	}
	return &Set{Limiter: l, Limits: Limits(cfg), Observe: obs}, nil
}
