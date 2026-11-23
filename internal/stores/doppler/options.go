// SPDX-License-Identifier: AGPL-3.0-only

package doppler

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

// Option keys, relative to stores.<instance>.
const (
	optAddress       = "address"
	optToken         = "token"
	optTimeout       = "timeout"
	optCAFile        = "tls.ca-file"
	optWatchInterval = "watch.interval"
	optWatchBackoff  = "watch.max-backoff"
)

// Defaults.
const (
	defaultAddress       = "https://api.doppler.com"
	defaultTimeout       = 10 * time.Second
	defaultWatchInterval = time.Minute
	defaultWatchBackoff  = 5 * time.Minute
)

// settings is the decoded, validated configuration of one instance.
type settings struct {
	address       *url.URL
	tokenRef      config.SecretRef
	resolve       func(context.Context, config.SecretRef) (secret.Value, error)
	timeout       time.Duration
	caPEM         []byte
	watchInterval time.Duration
	watchBackoff  time.Duration
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
	addr := d.String(optAddress, defaultAddress)
	if u, err := url.Parse(strings.TrimRight(addr, "/")); err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		d.Errorf("option %s must be an http or https URL", optAddress)
	} else {
		s.address = u
	}
	s.tokenRef = d.SecretRef(optToken)
	if s.tokenRef == "" {
		d.Errorf("option %s is required (a Doppler service token, service account token or personal token)", optToken)
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
	// The token is resolved at the first request, not here: building an
	// adapter (for `scrim config validate`, for instance) reads no
	// credential source and contacts nothing.
	s.resolve = inst.Resolve
	return s, nil
}

// resolveToken resolves the token reference. Errors name the option and the
// reference form, never a value.
func (s *settings) resolveToken(ctx context.Context) (secret.Value, error) {
	v, err := s.resolve(ctx, s.tokenRef)
	if err != nil {
		return secret.Value{}, fmt.Errorf("option %s: cannot resolve %s: %w", optToken, s.tokenRef, err)
	}
	if v.IsZero() {
		v.Wipe()
		return secret.Value{}, fmt.Errorf("option %s resolved to an empty value", optToken)
	}
	return v, nil
}
