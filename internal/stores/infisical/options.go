// SPDX-License-Identifier: AGPL-3.0-only

package infisical

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores"
)

// Option keys, relative to stores.<instance>. The full configuration key is
// stores.<instance>.<key>; the environment variable is SCRIM_ plus that key
// upper-cased with dots and dashes as underscores.
const (
	optAddress       = "address"
	optAuthMethod    = "auth.method"
	optClientID      = "auth.universal-auth.client-id"
	optClientSecret  = "auth.universal-auth.client-secret"
	optTimeout       = "timeout"
	optCAFile        = "tls.ca-file"
	optWatchInterval = "watch.interval"
	optWatchBackoff  = "watch.max-backoff"
	optCreateFolders = "create-folders"
	optExpandRefs    = "expand-references"
)

var knownOptions = []string{
	optAddress, optAuthMethod, optClientID, optClientSecret, optTimeout, optCAFile,
	optWatchInterval, optWatchBackoff, optCreateFolders, optExpandRefs,
}

// Defaults.
const (
	defaultTimeout       = 10 * time.Second
	defaultWatchInterval = 30 * time.Second
	defaultWatchBackoff  = 5 * time.Minute
	methodUniversalAuth  = "universal-auth"
)

// settings is the decoded, validated configuration of one instance.
type settings struct {
	address       *url.URL
	clientID      string
	clientSecret  secret.Value
	timeout       time.Duration
	caPEM         []byte
	watchInterval time.Duration
	watchBackoff  time.Duration
	createFolders bool
	expandRefs    bool
}

// flatten turns nested option maps into dotted keys, so both
// {"auth": {"method": "x"}} and {"auth.method": "x"} decode the same way.
func flatten(prefix string, in map[string]any, out map[string]any) error {
	for k, v := range in {
		key := k
		if prefix != "" {
			key = prefix + "." + k
		}
		switch t := v.(type) {
		case map[string]any:
			if err := flatten(key, t, out); err != nil {
				return err
			}
		default:
			if _, dup := out[key]; dup {
				return fmt.Errorf("option %s is set twice", key)
			}
			out[key] = v
		}
	}
	return nil
}

func decodeSettings(ctx context.Context, inst stores.Instance) (*settings, error) {
	flat := map[string]any{}
	if err := flatten("", inst.Options, flat); err != nil {
		return nil, err
	}
	var errs []error
	for _, k := range slices.Sorted(maps.Keys(flat)) {
		if !slices.Contains(knownOptions, k) {
			errs = append(errs, fmt.Errorf("unknown option %s (did you mean %s?)", k, closest(k, knownOptions)))
		}
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	s := &settings{
		timeout:       defaultTimeout,
		watchInterval: defaultWatchInterval,
		watchBackoff:  defaultWatchBackoff,
		createFolders: true,
		expandRefs:    true,
	}
	str := func(k string) (string, bool, error) {
		v, ok := flat[k]
		if !ok {
			return "", false, nil
		}
		switch t := v.(type) {
		case string:
			return t, true, nil
		case fmt.Stringer:
			return t.String(), true, nil
		}
		return "", true, fmt.Errorf("option %s must be a string", k)
	}
	dur := func(k string, dst *time.Duration) error {
		v, ok := flat[k]
		if !ok {
			return nil
		}
		var d time.Duration
		switch t := v.(type) {
		case time.Duration:
			d = t
		case string:
			p, err := time.ParseDuration(t)
			if err != nil {
				return fmt.Errorf("option %s: %w", k, err)
			}
			d = p
		default:
			return fmt.Errorf("option %s must be a duration", k)
		}
		if d <= 0 {
			return fmt.Errorf("option %s must be positive", k)
		}
		*dst = d
		return nil
	}
	boolean := func(k string, dst *bool) error {
		v, ok := flat[k]
		if !ok {
			return nil
		}
		switch t := v.(type) {
		case bool:
			*dst = t
		case string:
			b, err := strconv.ParseBool(t)
			if err != nil {
				return fmt.Errorf("option %s must be true or false", k)
			}
			*dst = b
		default:
			return fmt.Errorf("option %s must be true or false", k)
		}
		return nil
	}

	addr, ok, err := str(optAddress)
	switch {
	case err != nil:
		errs = append(errs, err)
	case !ok || addr == "":
		errs = append(errs, fmt.Errorf("option %s is required (for Infisical Cloud use https://app.infisical.com)", optAddress))
	default:
		u, err := url.Parse(strings.TrimRight(addr, "/"))
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			errs = append(errs, fmt.Errorf("option %s must be an http or https URL", optAddress))
		} else {
			s.address = u
		}
	}
	if m, ok, err := str(optAuthMethod); err != nil {
		errs = append(errs, err)
	} else if ok && m != methodUniversalAuth {
		errs = append(errs, fmt.Errorf("option %s: unsupported method %q (supported: %s)", optAuthMethod, m, methodUniversalAuth))
	}
	if id, ok, err := str(optClientID); err != nil {
		errs = append(errs, err)
	} else if !ok || id == "" {
		errs = append(errs, fmt.Errorf("option %s is required", optClientID))
	} else {
		s.clientID = id
	}
	if ca, ok, err := str(optCAFile); err != nil {
		errs = append(errs, err)
	} else if ok && ca != "" {
		pem, err := os.ReadFile(ca)
		if err != nil {
			errs = append(errs, fmt.Errorf("option %s: %w", optCAFile, err))
		}
		s.caPEM = pem
	}
	for _, e := range []error{
		dur(optTimeout, &s.timeout),
		dur(optWatchInterval, &s.watchInterval),
		dur(optWatchBackoff, &s.watchBackoff),
		boolean(optCreateFolders, &s.createFolders),
		boolean(optExpandRefs, &s.expandRefs),
	} {
		if e != nil {
			errs = append(errs, e)
		}
	}

	// The client secret is resolved last, and only if everything else is
	// valid, so a bad configuration does not read credential sources.
	var ref config.SecretRef
	switch t := flat[optClientSecret].(type) {
	case nil:
		errs = append(errs, fmt.Errorf("option %s is required", optClientSecret))
	case config.SecretRef:
		ref = t
	case string:
		ref = config.SecretRef(t)
	default:
		errs = append(errs, fmt.Errorf("option %s must be a secret reference", optClientSecret))
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	if inst.Resolve == nil {
		return nil, fmt.Errorf("option %s: no secret resolver configured", optClientSecret)
	}
	v, err := inst.Resolve(ctx, ref)
	if err != nil {
		// The resolver's error names the reference, never a value.
		return nil, fmt.Errorf("option %s: %w", optClientSecret, err)
	}
	if v.IsZero() {
		v.Wipe()
		return nil, fmt.Errorf("option %s resolved to an empty value", optClientSecret)
	}
	s.clientSecret = v
	return s, nil
}

// closest returns the candidate with the smallest edit distance to k.
func closest(k string, candidates []string) string {
	best, bestD := "", -1
	for _, c := range candidates {
		if d := levenshtein(k, c); bestD < 0 || d < bestD {
			best, bestD = c, d
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
