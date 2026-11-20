// SPDX-License-Identifier: AGPL-3.0-only

package vaultwarden

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/heliopsy/scrim/internal/config"
)

// Option keys of a Vaultwarden store instance.
const (
	OptURL               = "url"
	OptClientID          = "client-id"
	OptClientSecret      = "client-secret"
	OptEmail             = "email"
	OptUnlock            = "unlock"
	OptScope             = "scope"
	OptPollInterval      = "poll-interval"
	OptTimeout           = "timeout"
	OptDeviceID          = "device-id"
	OptCAFile            = "ca-file"
	OptAllowInsecureHTTP = "allow-insecure-http"
)

// Options is the decoded configuration of one instance.
type Options struct {
	// URL is the server's base URL, for example https://vault.example.com.
	URL *url.URL
	// ClientID is the personal API key's client_id ("user.<uuid>"). With
	// ClientSecret it selects API key login, which is preferred.
	ClientID string
	// ClientSecret is a reference to the API key's client_secret.
	ClientSecret config.SecretRef
	// Email is the account email. It is required for password login and,
	// when set with an API key, checked against the account.
	Email string
	// Unlock is a reference to the master password. It is never a literal.
	Unlock config.SecretRef
	// Scope limits scrim to items under these path prefixes. Empty means the
	// whole vault, which doctor warns about.
	Scope []string
	// PollInterval is how often Watch checks the account revision date.
	PollInterval time.Duration
	// Timeout bounds each HTTP request.
	Timeout time.Duration
	// DeviceID identifies scrim to the server; default derived from the
	// instance name and account.
	DeviceID string
	// CAFile adds a PEM bundle of trusted roots.
	CAFile string
	// AllowInsecureHTTP permits plain http:// to a non-loopback host. It
	// weakens transport security: tokens would travel in clear text.
	AllowInsecureHTTP bool
}

var refPrefix = regexp.MustCompile(`^[a-z][a-z0-9+.-]*:\S`)

// isReference reports whether s has the form of a secret reference
// (`file:/path`, `keyring:service/user`, `bao://...`) rather than a literal.
func isReference(s string) bool {
	return refPrefix.MatchString(s) && !strings.HasPrefix(s, "literal:")
}

func decodeOptions(instance string, m map[string]any) (Options, error) {
	o := Options{PollInterval: 30 * time.Second, Timeout: 30 * time.Second}
	known := map[string]bool{}
	for _, k := range []string{OptURL, OptClientID, OptClientSecret, OptEmail, OptUnlock, OptScope,
		OptPollInterval, OptTimeout, OptDeviceID, OptCAFile, OptAllowInsecureHTTP} {
		known[k] = true
	}
	for k := range m {
		if !known[k] {
			return o, fmt.Errorf("vaultwarden %s: unknown option %q", instance, k)
		}
	}
	str := func(k string) (string, error) {
		v, ok := m[k]
		if !ok || v == nil {
			return "", nil
		}
		switch t := v.(type) {
		case string:
			return t, nil
		case config.SecretRef:
			return string(t), nil
		}
		return "", fmt.Errorf("vaultwarden %s: option %s must be a string", instance, k)
	}
	var err error
	raw, err := str(OptURL)
	if err != nil {
		return o, err
	}
	if raw == "" {
		return o, fmt.Errorf("vaultwarden %s: option %s is required", instance, OptURL)
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil {
		return o, fmt.Errorf("vaultwarden %s: option %s must be an http(s) URL without credentials", instance, OptURL)
	}
	u.RawQuery, u.Fragment = "", ""
	o.URL = u
	if o.ClientID, err = str(OptClientID); err != nil {
		return o, err
	}
	cs, err := str(OptClientSecret)
	if err != nil {
		return o, err
	}
	o.ClientSecret = config.SecretRef(cs)
	if o.Email, err = str(OptEmail); err != nil {
		return o, err
	}
	ul, err := str(OptUnlock)
	if err != nil {
		return o, err
	}
	o.Unlock = config.SecretRef(ul)
	if o.DeviceID, err = str(OptDeviceID); err != nil {
		return o, err
	}
	if o.CAFile, err = str(OptCAFile); err != nil {
		return o, err
	}
	for _, d := range []struct {
		k   string
		dst *time.Duration
	}{{OptPollInterval, &o.PollInterval}, {OptTimeout, &o.Timeout}} {
		v, ok := m[d.k]
		if !ok || v == nil {
			continue
		}
		switch t := v.(type) {
		case time.Duration:
			*d.dst = t
		case string:
			p, err := time.ParseDuration(t)
			if err != nil {
				return o, fmt.Errorf("vaultwarden %s: option %s: %w", instance, d.k, err)
			}
			*d.dst = p
		default:
			return o, fmt.Errorf("vaultwarden %s: option %s must be a duration", instance, d.k)
		}
		if *d.dst <= 0 {
			return o, fmt.Errorf("vaultwarden %s: option %s must be positive", instance, d.k)
		}
	}
	if v, ok := m[OptAllowInsecureHTTP]; ok && v != nil {
		b, ok := v.(bool)
		if !ok {
			return o, fmt.Errorf("vaultwarden %s: option %s must be a boolean", instance, OptAllowInsecureHTTP)
		}
		o.AllowInsecureHTTP = b
	}
	if v, ok := m[OptScope]; ok && v != nil {
		switch t := v.(type) {
		case []string:
			o.Scope = t
		case []any:
			for _, e := range t {
				s, ok := e.(string)
				if !ok {
					return o, fmt.Errorf("vaultwarden %s: option %s must be a list of strings", instance, OptScope)
				}
				o.Scope = append(o.Scope, s)
			}
		case string:
			o.Scope = strings.Split(t, ",")
		default:
			return o, fmt.Errorf("vaultwarden %s: option %s must be a list of strings", instance, OptScope)
		}
		for i, s := range o.Scope {
			o.Scope[i] = strings.Trim(strings.TrimSpace(s), "/")
			if o.Scope[i] == "" {
				return o, fmt.Errorf("vaultwarden %s: option %s has an empty prefix", instance, OptScope)
			}
		}
	}
	return o, o.validate(instance)
}

func (o Options) validate(instance string) error {
	if o.Unlock == "" {
		return fmt.Errorf("vaultwarden %s: option %s is required (a reference to the master password)", instance, OptUnlock)
	}
	if !isReference(string(o.Unlock)) {
		return fmt.Errorf("vaultwarden %s: option %s must be a reference (file:, keyring:, a systemd credential or a store reference), never a literal", instance, OptUnlock)
	}
	if o.ClientSecret != "" && !isReference(string(o.ClientSecret)) {
		return fmt.Errorf("vaultwarden %s: option %s must be a reference, never a literal", instance, OptClientSecret)
	}
	switch {
	case o.ClientID != "" && o.ClientSecret != "":
	case o.ClientID == "" && o.ClientSecret == "":
		if o.Email == "" {
			return fmt.Errorf("vaultwarden %s: set %s and %s (preferred) or %s for password login", instance, OptClientID, OptClientSecret, OptEmail)
		}
	default:
		return fmt.Errorf("vaultwarden %s: %s and %s must be set together", instance, OptClientID, OptClientSecret)
	}
	if o.URL.Scheme == "http" && !o.AllowInsecureHTTP && !isLoopback(o.URL.Hostname()) {
		return fmt.Errorf("vaultwarden %s: plain http to %s would send tokens in clear text; use https or set %s", instance, o.URL.Hostname(), OptAllowInsecureHTTP)
	}
	return nil
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// deviceID returns the configured device identifier or a stable one
// derived from the instance and account, so the server sees one device per
// scrim instance rather than a new one per start.
func (o Options) deviceID(instance string) string {
	if o.DeviceID != "" {
		return o.DeviceID
	}
	h := sha256.Sum256([]byte("scrim-vaultwarden-device\x00" + instance + "\x00" + o.URL.String() + "\x00" + o.ClientID + "\x00" + strings.ToLower(o.Email)))
	b := h[:16]
	b[6] = (b[6] & 0x0f) | 0x50 // version 5 layout
	b[8] = (b[8] & 0x3f) | 0x80
	s := hex.EncodeToString(b)
	return s[0:8] + "-" + s[8:12] + "-" + s[12:16] + "-" + s[16:20] + "-" + s[20:32]
}

func (o Options) httpClient() (*http.Client, error) {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	if o.CAFile != "" {
		pem, err := os.ReadFile(o.CAFile)
		if err != nil {
			return nil, fmt.Errorf("vaultwarden: %s: %w", OptCAFile, err)
		}
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("vaultwarden: " + OptCAFile + " holds no PEM certificates")
		}
		tr.TLSClientConfig.RootCAs = pool
	}
	return &http.Client{
		Transport: tr,
		Timeout:   o.Timeout,
		// Never follow redirects: a redirect could carry the bearer token
		// to another host.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}, nil
}
