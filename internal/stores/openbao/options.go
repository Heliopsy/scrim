// SPDX-License-Identifier: AGPL-3.0-only

package openbao

import (
	"errors"
	"fmt"
	"net/url"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/heliopsy/scrim/internal/config"
)

// Option keys, relative to `stores.<instance>.`. docs/stores/openbao.md
// documents each one; keep the two in step.
const (
	optAddress         = "address"
	optNamespace       = "namespace"
	optMounts          = "mounts"
	optAuthMethod      = "auth.method"
	optAuthToken       = "auth.token"
	optAppRoleMount    = "auth.approle.mount"
	optAppRoleRoleID   = "auth.approle.role-id"
	optAppRoleSecretID = "auth.approle.secret-id"
	optTimeout         = "timeout"
	optCAFile          = "tls.ca-file"
	optServerName      = "tls.server-name"
	optWatchInterval   = "watch.interval"
	optWatchMaxBackoff = "watch.max-backoff"
	optWriteOnly       = "write-only-paths"
)

var knownOptions = []string{
	optAddress, optNamespace, optMounts, optAuthMethod, optAuthToken,
	optAppRoleMount, optAppRoleRoleID, optAppRoleSecretID, optTimeout,
	optCAFile, optServerName, optWatchInterval, optWatchMaxBackoff, optWriteOnly,
}

// Auth methods.
const (
	AuthToken   = "token"
	AuthAppRole = "approle"
)

// Defaults.
const (
	DefaultTimeout         = 10 * time.Second
	DefaultWatchInterval   = 30 * time.Second
	DefaultWatchMaxBackoff = 5 * time.Minute
	DefaultAppRoleMount    = "approle"
)

// Options is the decoded configuration of one OpenBao instance.
type Options struct {
	Address   *url.URL
	Namespace string
	// Mounts lists KV v2 mount paths that span more than one path segment
	// (for example "teams/kv"). A reference's mount is the longest listed
	// mount it starts with, or else its first segment.
	Mounts          []string
	AuthMethod      string
	Token           config.SecretRef
	AppRoleMount    string
	RoleID          config.SecretRef
	SecretID        config.SecretRef
	Timeout         time.Duration
	CAFile          string
	ServerName      string
	WatchInterval   time.Duration
	WatchMaxBackoff time.Duration
	// WriteOnly lists path prefixes (mount included) that scrim writes but
	// never reads back from the store.
	WriteOnly []string
}

// flatten turns nested maps into dotted keys, so both
// `auth: {method: approle}` and `auth.method: approle` work.
func flatten(prefix string, in map[string]any, out map[string]any) {
	for k, v := range in {
		key := k
		if prefix != "" {
			key = prefix + "." + k
		}
		if m, ok := v.(map[string]any); ok {
			flatten(key, m, out)
			continue
		}
		out[key] = v
	}
}

func closest(key string, known []string) string {
	best, bestD := "", 1<<30
	for _, k := range known {
		if d := levenshtein(key, k); d < bestD {
			best, bestD = k, d
		}
	}
	return best
}

func levenshtein(a, b string) int {
	prev := make([]int, len(b)+1)
	cur := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		cur[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
		}
		prev, cur = cur, prev
	}
	return prev[len(b)]
}

// ParseOptions decodes and validates raw instance options. Every problem is
// reported, each naming its key; values of credential settings are never
// echoed.
func ParseOptions(raw map[string]any) (Options, error) {
	flat := map[string]any{}
	flatten("", raw, flat)
	var errs []error
	keys := make([]string, 0, len(flat))
	for k := range flat {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if !slices.Contains(knownOptions, k) {
			errs = append(errs, fmt.Errorf("unknown option %q (did you mean %q?)", k, closest(k, knownOptions)))
		}
	}
	o := Options{
		AppRoleMount:    DefaultAppRoleMount,
		Timeout:         DefaultTimeout,
		WatchInterval:   DefaultWatchInterval,
		WatchMaxBackoff: DefaultWatchMaxBackoff,
	}
	str := func(key string) string {
		v, ok := flat[key]
		if !ok || v == nil {
			return ""
		}
		switch s := v.(type) {
		case string:
			return s
		case config.SecretRef:
			return string(s)
		}
		errs = append(errs, fmt.Errorf("option %q must be a string", key))
		return ""
	}
	dur := func(key string, def time.Duration) time.Duration {
		v, ok := flat[key]
		if !ok || v == nil {
			return def
		}
		var d time.Duration
		switch x := v.(type) {
		case time.Duration:
			d = x
		case string:
			var err error
			if d, err = time.ParseDuration(x); err != nil {
				errs = append(errs, fmt.Errorf("option %q: %v", key, err))
				return def
			}
		default:
			errs = append(errs, fmt.Errorf("option %q must be a duration such as 30s", key))
			return def
		}
		if d <= 0 {
			errs = append(errs, fmt.Errorf("option %q must be positive", key))
			return def
		}
		return d
	}
	list := func(key string) []string {
		v, ok := flat[key]
		if !ok || v == nil {
			return nil
		}
		switch x := v.(type) {
		case []string:
			return x
		case string:
			var out []string
			for _, p := range strings.Split(x, ",") {
				if p = strings.TrimSpace(p); p != "" {
					out = append(out, p)
				}
			}
			return out
		case []any:
			out := make([]string, 0, len(x))
			for _, e := range x {
				s, ok := e.(string)
				if !ok {
					errs = append(errs, fmt.Errorf("option %q must be a list of strings", key))
					return nil
				}
				out = append(out, s)
			}
			return out
		}
		errs = append(errs, fmt.Errorf("option %q must be a list of strings", key))
		return nil
	}
	secretRef := func(key string) config.SecretRef { return config.SecretRef(str(key)) }

	addr := str(optAddress)
	if addr == "" {
		errs = append(errs, fmt.Errorf("option %q is required", optAddress))
	} else if u, err := url.Parse(addr); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		errs = append(errs, fmt.Errorf("option %q must be an http or https URL", optAddress))
	} else {
		u.Path = strings.TrimSuffix(u.Path, "/")
		o.Address = u
	}
	o.Namespace = strings.Trim(str(optNamespace), "/")
	for _, m := range list(optMounts) {
		if m = strings.Trim(m, "/"); m != "" {
			o.Mounts = append(o.Mounts, m)
		}
	}
	o.AuthMethod = str(optAuthMethod)
	if o.AuthMethod == "" {
		o.AuthMethod = AuthToken
	}
	o.Token = secretRef(optAuthToken)
	if m := strings.Trim(str(optAppRoleMount), "/"); m != "" {
		o.AppRoleMount = m
	}
	o.RoleID = secretRef(optAppRoleRoleID)
	o.SecretID = secretRef(optAppRoleSecretID)
	switch o.AuthMethod {
	case AuthToken:
		if o.Token == "" {
			errs = append(errs, fmt.Errorf("option %q is required with auth.method %q", optAuthToken, AuthToken))
		}
	case AuthAppRole:
		if o.RoleID == "" {
			errs = append(errs, fmt.Errorf("option %q is required with auth.method %q", optAppRoleRoleID, AuthAppRole))
		}
		if o.SecretID == "" {
			errs = append(errs, fmt.Errorf("option %q is required with auth.method %q", optAppRoleSecretID, AuthAppRole))
		}
	default:
		errs = append(errs, fmt.Errorf("option %q must be %q or %q", optAuthMethod, AuthToken, AuthAppRole))
	}
	o.Timeout = dur(optTimeout, DefaultTimeout)
	o.CAFile = str(optCAFile)
	o.ServerName = str(optServerName)
	o.WatchInterval = dur(optWatchInterval, DefaultWatchInterval)
	o.WatchMaxBackoff = dur(optWatchMaxBackoff, DefaultWatchMaxBackoff)
	if o.WatchMaxBackoff < o.WatchInterval {
		o.WatchMaxBackoff = o.WatchInterval
	}
	for _, p := range list(optWriteOnly) {
		if p = strings.Trim(p, "/"); p != "" {
			o.WriteOnly = append(o.WriteOnly, p)
		}
	}
	return o, errors.Join(errs...)
}
