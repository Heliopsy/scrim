// SPDX-License-Identifier: AGPL-3.0-only

package infisical

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores"
	"github.com/heliopsy/scrim/internal/stores/internal/options"
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

func decodeSettings(ctx context.Context, inst stores.Instance) (*settings, error) {
	d := options.New(inst.Name, inst.Options)
	s := &settings{
		timeout:       d.Duration(optTimeout, defaultTimeout),
		watchInterval: d.Duration(optWatchInterval, defaultWatchInterval),
		watchBackoff:  d.Duration(optWatchBackoff, defaultWatchBackoff),
		createFolders: d.Bool(optCreateFolders, true),
		expandRefs:    d.Bool(optExpandRefs, true),
		clientID:      d.String(optClientID, ""),
	}
	for key, v := range map[string]time.Duration{optTimeout: s.timeout, optWatchInterval: s.watchInterval, optWatchBackoff: s.watchBackoff} {
		if v <= 0 {
			d.Errorf("option %s must be positive", key)
		}
	}
	if addr := d.String(optAddress, ""); addr == "" {
		d.Errorf("option %s is required (for Infisical Cloud use https://app.infisical.com)", optAddress)
	} else if u, err := url.Parse(strings.TrimRight(addr, "/")); err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		d.Errorf("option %s must be an http or https URL", optAddress)
	} else {
		s.address = u
	}
	if m := d.String(optAuthMethod, methodUniversalAuth); m != methodUniversalAuth {
		d.Errorf("option %s: unsupported method %q (supported: %s)", optAuthMethod, m, methodUniversalAuth)
	}
	if s.clientID == "" {
		d.Errorf("option %s is required", optClientID)
	}
	if ca := d.String(optCAFile, ""); ca != "" {
		pem, err := os.ReadFile(ca)
		if err != nil {
			d.Errorf("option %s: %v", optCAFile, err)
		}
		s.caPEM = pem
	}
	ref := d.SecretRef(optClientSecret)
	if ref == "" {
		d.Errorf("option %s is required", optClientSecret)
	}
	// The client secret is resolved only once everything else is valid,
	// so a bad configuration does not read credential sources.
	if err := d.Finish(); err != nil {
		return nil, err
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
