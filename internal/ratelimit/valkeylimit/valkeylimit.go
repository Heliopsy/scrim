// SPDX-License-Identifier: AGPL-3.0-only

// Package valkeylimit is the valkey rate-limit backend: the GCRA state of
// each key lives in Valkey and one Lua script reads Valkey's own clock,
// decides and updates atomically, so every replica shares one exact limit
// whatever their clocks say. A key expires once its limit has fully
// recovered.
package valkeylimit

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/valkey-io/valkey-go"

	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/ratelimit"
	"github.com/heliopsy/scrim/internal/valkeyconn"
)

// Prefix namespaces the keys.
var Prefix = config.Register(config.Spec[string]{
	Key:     "ratelimit.valkey.prefix",
	Default: "scrim:rl:",
	Description: "Prefix of the Valkey keys ratelimit.backend valkey keeps its counters in. Replicas of one deployment share it; " +
		"two deployments on one Valkey need different prefixes.",
	RestartRequired: true,
})

func init() {
	ratelimit.RegisterBackend("valkey", func(cfg *config.Config) (ratelimit.Limiter, error) {
		o, err := valkeyconn.FromConfig(cfg)
		if err != nil {
			return nil, err
		}
		o.ClientName = "scrim-ratelimit"
		c, err := valkeyconn.New(o)
		if err != nil {
			return nil, err
		}
		l := New(c, Prefix.Get(cfg))
		l.owns = true
		return l, nil
	})
}

// script: KEYS[1] the key; ARGV[1] emission interval and ARGV[2] burst
// tolerance (emission times burst), both in microseconds. Returns
// {allowed, retry_after_us, remaining}.
var script = valkey.NewLuaScript(`
local t = tonumber(ARGV[1])
local tol = tonumber(ARGV[2])
local clock = redis.call('TIME')
local now = tonumber(clock[1]) * 1000000 + tonumber(clock[2])
local tat = tonumber(redis.call('GET', KEYS[1]) or now)
if tat < now then tat = now end
local nxt = tat + t
local allow_at = nxt - tol
if now < allow_at then
  return {0, allow_at - now, 0}
end
redis.call('SET', KEYS[1], nxt, 'PX', math.ceil((nxt - now) / 1000) + 1)
return {1, 0, math.floor((now - allow_at) / t)}
`)

// Limiter implements [ratelimit.Limiter] over Valkey.
type Limiter struct {
	c      valkey.Client
	prefix string
	owns   bool
}

// New returns a limiter over c with keys under prefix.
func New(c valkey.Client, prefix string) *Limiter { return &Limiter{c: c, prefix: prefix} }

// Allow implements [ratelimit.Limiter].
func (l *Limiter) Allow(ctx context.Context, key string, lim ratelimit.Limit) (ratelimit.Result, error) {
	t := lim.Interval / time.Duration(lim.Rate)
	if t < time.Microsecond {
		return ratelimit.Result{}, errors.New("limit finer than a microsecond per request")
	}
	tol := t * time.Duration(max(lim.Burst, 1))
	vals, err := script.Exec(ctx, l.c, []string{l.prefix + key},
		[]string{strconv.FormatInt(t.Microseconds(), 10), strconv.FormatInt(tol.Microseconds(), 10)}).AsIntSlice()
	if err != nil {
		return ratelimit.Result{}, fmt.Errorf("valkey: %w", err)
	}
	if len(vals) != 3 {
		return ratelimit.Result{}, fmt.Errorf("valkey: script returned %d values", len(vals))
	}
	return ratelimit.Result{Allowed: vals[0] == 1, RetryAfter: time.Duration(vals[1]) * time.Microsecond, Remaining: int(vals[2])}, nil
}

// Backend implements [ratelimit.Limiter].
func (*Limiter) Backend() string { return "valkey" }

// Close implements [ratelimit.Limiter].
func (l *Limiter) Close() error {
	if l.owns {
		l.c.Close()
	}
	return nil
}
