// SPDX-License-Identifier: AGPL-3.0-only

package bws

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores"
	"github.com/heliopsy/scrim/internal/stores/internal/options"
)

// Option keys, relative to stores.<instance>. The full configuration key is
// stores.<instance>.<key>; the environment variable is SCRIM_ plus that key
// upper-cased with dots and dashes as underscores.
const (
	optToken         = "token"
	optAPIURL        = "api-url"
	optIdentityURL   = "identity-url"
	optServerURL     = "server-url"
	optTimeout       = "timeout"
	optCAFile        = "tls.ca-file"
	optWatchInterval = "watch.interval"
	optWatchBackoff  = "watch.max-backoff"
)

// Defaults: Bitwarden's US cloud, as in the SDK's ClientSettings.
const (
	defaultAPIURL        = "https://api.bitwarden.com"
	defaultIdentityURL   = "https://identity.bitwarden.com"
	defaultTimeout       = 10 * time.Second
	defaultWatchInterval = 30 * time.Second
	defaultWatchBackoff  = 5 * time.Minute
)

// settings is the decoded, validated configuration of one instance.
type settings struct {
	api           *url.URL
	identity      *url.URL
	tokenRef      config.SecretRef
	resolve       func(context.Context, config.SecretRef) (secret.Value, error)
	timeout       time.Duration
	caPEM         []byte
	watchInterval time.Duration
	watchBackoff  time.Duration
}

func parseBase(d *options.Decoder, key, raw string) *url.URL {
	u, err := url.Parse(strings.TrimRight(raw, "/"))
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.RawQuery != "" || u.Fragment != "" {
		d.Errorf("option %s must be an http or https URL without query or fragment", key)
		return nil
	}
	return u
}

func decodeSettings(inst stores.Instance) (*settings, error) {
	d := options.New(inst.Name, inst.Options)
	s := &settings{
		timeout:       d.Duration(optTimeout, defaultTimeout),
		watchInterval: d.Duration(optWatchInterval, defaultWatchInterval),
		watchBackoff:  d.Duration(optWatchBackoff, defaultWatchBackoff),
	}
	for key, v := range map[string]time.Duration{optTimeout: s.timeout, optWatchInterval: s.watchInterval, optWatchBackoff: s.watchBackoff} {
		if v <= 0 {
			d.Errorf("option %s must be positive", key)
		}
	}
	// server-url is the self-hosted shorthand the bws CLI uses: the API
	// and identity services under /api and /identity of one address.
	server := d.String(optServerURL, "")
	apiURL, idURL := d.String(optAPIURL, ""), d.String(optIdentityURL, "")
	switch {
	case server != "" && (apiURL != "" || idURL != ""):
		d.Errorf("option %s cannot be combined with %s or %s", optServerURL, optAPIURL, optIdentityURL)
	case server != "":
		if u := parseBase(d, optServerURL, server); u != nil {
			a, i := *u, *u
			a.Path += "/api"
			i.Path += "/identity"
			s.api, s.identity = &a, &i
		}
	default:
		if apiURL == "" {
			apiURL = defaultAPIURL
		}
		if idURL == "" {
			idURL = defaultIdentityURL
		}
		s.api = parseBase(d, optAPIURL, apiURL)
		s.identity = parseBase(d, optIdentityURL, idURL)
	}
	s.tokenRef = d.SecretRef(optToken)
	if s.tokenRef == "" {
		d.Errorf("option %s is required: a reference to the machine account access token", optToken)
	}
	if ca := d.String(optCAFile, ""); ca != "" {
		pem, err := os.ReadFile(ca)
		if err != nil {
			d.Errorf("option %s: %v", optCAFile, err)
		}
		s.caPEM = pem
	}
	if err := d.Finish(); err != nil {
		return nil, err
	}
	if inst.Resolve == nil {
		return nil, fmt.Errorf("option %s: no secret resolver configured", optToken)
	}
	// The token is resolved at the first login, not here: building an
	// adapter (for `scrim config validate`, for instance) reads no
	// credential source and contacts nothing.
	s.resolve = inst.Resolve
	return s, nil
}
