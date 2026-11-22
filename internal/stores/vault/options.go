// SPDX-License-Identifier: AGPL-3.0-only

package vault

import (
	"strings"
	"time"

	"github.com/heliopsy/scrim/internal/stores/internal/options"
	"github.com/heliopsy/scrim/internal/stores/internal/vaultapi"
)

// Option keys, relative to `stores.<instance>.`, besides the connection
// and auth keys shared with the openbao adapter (package vaultapi).
// docs/stores/vault.md documents each one; keep the two in step.
const (
	optMounts               = "mounts"
	optKVv1Mounts           = "kv-v1-mounts"
	optDynamicPaths         = "dynamic-paths"
	optMountDetect          = "mounts.detect"
	optWatchInterval        = "watch.interval"
	optWatchMaxBackoff      = "watch.max-backoff"
	optWriteOnly            = "write-only-paths"
	optLabelLookups         = "labels.lookups"
	optLeaseCheckInterval   = "leases.check-interval"
	optLeaseIncrement       = "leases.increment"
	optLeaseRevokeOnClose   = "leases.revoke-on-close"
	optLeaseRevokeTimeout   = "leases.revoke-timeout"
	defaultLeaseCheck       = 10 * time.Second
	defaultLeaseRevokeLimit = 10 * time.Second
)

// Defaults.
const (
	DefaultWatchInterval   = 30 * time.Second
	DefaultWatchMaxBackoff = 5 * time.Minute
)

// Options is the decoded configuration of one Vault instance.
type Options struct {
	vaultapi.Options
	// Mounts lists mount paths that span more than one path segment (for
	// example "teams/kv"), for when the mount cannot be looked up.
	Mounts []string
	// KVv1Mounts lists KV version 1 mounts, for when the mount cannot be
	// looked up. Every other KV mount is taken as version 2.
	KVv1Mounts []string
	// DynamicPaths lists path prefixes (mount included) that issue dynamic
	// secrets, for when the mount cannot be looked up. A mount that is not
	// KV is dynamic anyway.
	DynamicPaths []string
	// MountDetect allows looking up the mount of a reference (its path,
	// type and KV version) with sys/internal/ui/mounts.
	MountDetect     bool
	WatchInterval   time.Duration
	WatchMaxBackoff time.Duration
	// WriteOnly lists path prefixes (mount included) that scrim writes but
	// never reads back from the store.
	WriteOnly []string
	// LabelLookups allows the optional requests that fill native labels.
	LabelLookups bool
	// LeaseCheck is how often a lease's holder is asked whether it is
	// still active; LeaseIncrement the renewal asked for (zero: the
	// store's default TTL).
	LeaseCheck     time.Duration
	LeaseIncrement time.Duration
	// RevokeOnClose revokes every held lease when the adapter closes (scrim
	// stops), within RevokeTimeout.
	RevokeOnClose bool
	RevokeTimeout time.Duration
}

// ParseOptions decodes and validates raw instance options. Every problem is
// reported, each naming its key; values of credential settings are never
// echoed.
func ParseOptions(raw map[string]any) (Options, error) {
	return parseOptions(Kind, raw)
}

func trimmed(d *options.Decoder, key string) []string {
	var out []string
	for _, p := range d.Strings(key) {
		if p = strings.Trim(p, "/"); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func parseOptions(store string, raw map[string]any) (Options, error) {
	d := options.New(store, raw)
	o := Options{Options: vaultapi.Parse(d, vaultapi.Features{JWT: true, AuthNamespace: true})}
	o.Mounts = trimmed(d, optMounts)
	o.KVv1Mounts = trimmed(d, optKVv1Mounts)
	o.DynamicPaths = trimmed(d, optDynamicPaths)
	o.WriteOnly = trimmed(d, optWriteOnly)
	o.MountDetect = d.Bool(optMountDetect, true)
	o.WatchInterval = d.Duration(optWatchInterval, DefaultWatchInterval)
	o.WatchMaxBackoff = d.Duration(optWatchMaxBackoff, DefaultWatchMaxBackoff)
	o.LabelLookups = d.Bool(optLabelLookups, true)
	o.LeaseCheck = d.Duration(optLeaseCheckInterval, defaultLeaseCheck)
	o.LeaseIncrement = d.Duration(optLeaseIncrement, 0)
	o.RevokeOnClose = d.Bool(optLeaseRevokeOnClose, true)
	o.RevokeTimeout = d.Duration(optLeaseRevokeTimeout, defaultLeaseRevokeLimit)
	for _, kv := range []struct {
		key string
		v   time.Duration
	}{{optWatchInterval, o.WatchInterval}, {optWatchMaxBackoff, o.WatchMaxBackoff}, {optLeaseCheckInterval, o.LeaseCheck}, {optLeaseRevokeTimeout, o.RevokeTimeout}} {
		if kv.v <= 0 {
			d.Errorf("option %s must be positive", kv.key)
		}
	}
	if o.LeaseIncrement < 0 {
		d.Errorf("option %s must not be negative", optLeaseIncrement)
	}
	if o.WatchMaxBackoff < o.WatchInterval {
		o.WatchMaxBackoff = o.WatchInterval
	}
	return o, d.Finish()
}
