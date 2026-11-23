// SPDX-License-Identifier: AGPL-3.0-only

package openbao

import (
	"strings"
	"time"

	"github.com/heliopsy/scrim/internal/stores/internal/options"
	"github.com/heliopsy/scrim/internal/stores/internal/vaultapi"
)

// Option keys, relative to `stores.<instance>.`. docs/stores/openbao.md
// documents each one; keep the two in step. The connection and auth keys
// are shared with the vault adapter (package vaultapi).
const (
	optMounts          = "mounts"
	optAuthToken       = vaultapi.OptAuthToken
	optK8sTokenFile    = vaultapi.OptK8sTokenFile
	optWatchInterval   = "watch.interval"
	optWatchMaxBackoff = "watch.max-backoff"
	optWriteOnly       = "write-only-paths"
	optLabelLookups    = "labels.lookups"
)

// Auth methods.
const (
	AuthToken      = vaultapi.AuthToken
	AuthAppRole    = vaultapi.AuthAppRole
	AuthKubernetes = vaultapi.AuthKubernetes
)

// Defaults.
const (
	DefaultTimeout         = vaultapi.DefaultTimeout
	DefaultWatchInterval   = 30 * time.Second
	DefaultWatchMaxBackoff = 5 * time.Minute
	DefaultAppRoleMount    = vaultapi.DefaultAppRoleMount
	DefaultK8sMount        = vaultapi.DefaultK8sMount
	// DefaultK8sTokenFile is where the kubelet mounts the pod's default
	// service account token. A projected token with a dedicated audience
	// is the better choice; see docs/stores/openbao.md.
	DefaultK8sTokenFile = vaultapi.DefaultK8sTokenFile
)

// Options is the decoded configuration of one OpenBao instance: how to
// reach and log in to it (vaultapi.Options: address, namespace, auth, TLS,
// timeout) and what the adapter does there.
type Options struct {
	vaultapi.Options
	// Mounts lists KV v2 mount paths that span more than one path segment
	// (for example "teams/kv"). A reference's mount is the longest listed
	// mount it starts with, or else its first segment.
	Mounts          []string
	WatchInterval   time.Duration
	WatchMaxBackoff time.Duration
	// WriteOnly lists path prefixes (mount included) that scrim writes but
	// never reads back from the store.
	WriteOnly []string
	// LabelLookups allows the optional requests that fill native labels:
	// a secret's metadata on read and its mount's information.
	LabelLookups bool
}

// ParseOptions decodes and validates raw instance options. Every problem is
// reported, each naming its key; values of credential settings are never
// echoed.
func ParseOptions(raw map[string]any) (Options, error) {
	return parseOptions("openbao", raw)
}

func parseOptions(store string, raw map[string]any) (Options, error) {
	d := options.New(store, raw)
	o := Options{Options: vaultapi.Parse(d, vaultapi.Features{})}
	for _, m := range d.Strings(optMounts) {
		if m = strings.Trim(m, "/"); m != "" {
			o.Mounts = append(o.Mounts, m)
		}
	}
	o.WatchInterval = d.Duration(optWatchInterval, DefaultWatchInterval)
	o.WatchMaxBackoff = d.Duration(optWatchMaxBackoff, DefaultWatchMaxBackoff)
	o.LabelLookups = d.Bool(optLabelLookups, true)
	for _, p := range d.Strings(optWriteOnly) {
		if p = strings.Trim(p, "/"); p != "" {
			o.WriteOnly = append(o.WriteOnly, p)
		}
	}
	for key, v := range map[string]time.Duration{optWatchInterval: o.WatchInterval, optWatchMaxBackoff: o.WatchMaxBackoff} {
		if v <= 0 {
			d.Errorf("option %s must be positive", key)
		}
	}
	if o.WatchMaxBackoff < o.WatchInterval {
		o.WatchMaxBackoff = o.WatchInterval
	}
	return o, d.Finish()
}
