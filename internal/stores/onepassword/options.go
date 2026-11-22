// SPDX-License-Identifier: AGPL-3.0-only

package onepassword

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"slices"
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
	optCategory      = "write.category"
	optVaultCacheTTL = "vault-cache-ttl"
)

// Defaults.
const (
	defaultTimeout       = 10 * time.Second
	defaultWatchInterval = 30 * time.Second
	defaultWatchBackoff  = 5 * time.Minute
	defaultCategory      = "API_CREDENTIAL"
	defaultVaultCacheTTL = 5 * time.Minute
)

// writableCategories are the item categories a new item may be created
// with. CUSTOM and DOCUMENT are left out: Connect refuses to create the
// first and the second needs a file.
var writableCategories = []string{
	"LOGIN", "PASSWORD", "API_CREDENTIAL", "SERVER", "DATABASE", "CREDIT_CARD", "MEMBERSHIP",
	"PASSPORT", "SOFTWARE_LICENSE", "OUTDOOR_LICENSE", "SECURE_NOTE", "WIRELESS_ROUTER",
	"BANK_ACCOUNT", "DRIVER_LICENSE", "IDENTITY", "REWARD_PROGRAM", "EMAIL_ACCOUNT",
	"SOCIAL_SECURITY_NUMBER", "MEDICAL_RECORD", "SSH_KEY",
}

// settings is the decoded, validated configuration of one instance.
type settings struct {
	address       *url.URL
	tokenRef      config.SecretRef
	resolve       func(context.Context, config.SecretRef) (secret.Value, error)
	timeout       time.Duration
	caPEM         []byte
	watchInterval time.Duration
	watchBackoff  time.Duration
	category      string
	vaultTTL      time.Duration
}

func decodeSettings(inst stores.Instance) (*settings, error) {
	d := options.New(inst.Name, inst.Options)
	s := &settings{
		timeout:       d.Duration(optTimeout, defaultTimeout),
		watchInterval: d.Duration(optWatchInterval, defaultWatchInterval),
		watchBackoff:  d.Duration(optWatchBackoff, defaultWatchBackoff),
		vaultTTL:      d.Duration(optVaultCacheTTL, defaultVaultCacheTTL),
		category:      strings.ToUpper(strings.TrimSpace(d.String(optCategory, defaultCategory))),
	}
	for key, v := range map[string]time.Duration{optTimeout: s.timeout, optWatchInterval: s.watchInterval, optWatchBackoff: s.watchBackoff, optVaultCacheTTL: s.vaultTTL} {
		if v <= 0 {
			d.Errorf("option %s must be positive", key)
		}
	}
	if addr := d.String(optAddress, ""); addr == "" {
		d.Errorf("option %s is required: the URL of your 1Password Connect server, for example http://op-connect:8080", optAddress)
	} else if u, err := url.Parse(strings.TrimRight(addr, "/")); err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		d.Errorf("option %s must be an http or https URL", optAddress)
	} else {
		s.address = u
	}
	s.tokenRef = d.SecretRef(optToken)
	if s.tokenRef == "" {
		d.Errorf("option %s is required: a reference to the Connect server access token", optToken)
	}
	if !slices.Contains(writableCategories, s.category) {
		d.Errorf("option %s: unsupported category %q (supported: %s)", optCategory, s.category, strings.Join(writableCategories, ", "))
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
	// adapter (for `scrim config validate`) reads no credential source.
	s.resolve = inst.Resolve
	return s, nil
}
