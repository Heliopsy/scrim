// SPDX-License-Identifier: AGPL-3.0-only

package issuer

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/heliopsy/scrim/internal/config"
)

// Defaults of the token lifetime and the rotation period.
const (
	DefaultTokenTTL    = 10 * time.Minute
	DefaultRotateEvery = 24 * time.Hour
)

// Settings of scrim as an identity provider (specs/agent-identity "scrim as
// an identity provider for agents"). All are read at start-up.
var (
	URLSetting = config.Register(config.Spec[string]{
		Key: "identity.issuer.url",
		Description: "Issuer URL of the identity tokens scrim signs for agents (the iss claim). Stores and clouds fetch " +
			"<url>/.well-known/openid-configuration and the JWKS it names from here, so it must reach identity.issuer.listen, " +
			"usually through a TLS reverse proxy. https, or http on a loopback host; plain http elsewhere needs identity.issuer.insecure-http. " +
			"Empty turns the issuer off.",
		RestartRequired: true,
		Validate:        validIssuerURL,
	})
	ListenSetting = config.Register(config.Spec[string]{
		Key: "identity.issuer.listen",
		Description: "TCP address that serves the issuer's discovery document and JWKS, and nothing else. " +
			"Required when identity.issuer.url is set.",
		RestartRequired: true,
		Validate:        optionalHostPort,
	})
	InsecureHTTPSetting = config.Register(config.Spec[bool]{
		Key: "identity.issuer.insecure-http",
		Description: "Allow an http:// identity.issuer.url on a host other than loopback. Anyone on the path between a store and scrim " +
			"could then substitute signing keys, and the store would trust tokens they sign.",
		Weakening:       true,
		RestartRequired: true,
	})
	TokenTTLSetting = config.Register(config.Spec[time.Duration]{
		Key: "identity.issuer.token-ttl",
		Description: "Lifetime of each identity token, never past the end of the session it is minted for. " +
			"Between 1m and 1h.",
		Default:         DefaultTokenTTL,
		RestartRequired: true,
		Validate: func(d time.Duration) error {
			if d < time.Minute || d > time.Hour {
				return errors.New("must be between 1m and 1h")
			}
			return nil
		},
	})
	KeyDirSetting = config.Register(config.Spec[string]{
		Key:         "identity.issuer.key-dir",
		KeyMaterial: true,
		KeyMaterialWhen: func(c *config.Config) bool {
			return URLSetting.Get(c) != "" && SigningKeysSetting.Get(c) == ""
		},
		Description: "Directory of the issuer's generated signing keys and their rotation state. " +
			"Empty means $XDG_STATE_HOME/scrim/issuer (~/.local/state/scrim/issuer). Created with mode 0700. " +
			"Not used with identity.issuer.signing-keys.",
		RestartRequired: true,
	})
	RotateEverySetting = config.Register(config.Spec[time.Duration]{
		Key: "identity.issuer.rotate-every",
		Description: "How often a generated signing key is replaced. The next key is published one period before it signs, " +
			"and a replaced key stays published until the last token it signed has expired. At least 1h.",
		Default:         DefaultRotateEvery,
		RestartRequired: true,
		Validate: func(d time.Duration) error {
			if d < time.Hour {
				return errors.New("must be at least 1h")
			}
			return nil
		},
	})
	SigningKeysSetting = config.Register(config.Spec[config.SecretRef]{
		Key: "identity.issuer.signing-keys",
		Description: "Reference to operator-managed signing keys: one or more PKCS#8 PEM RSA private keys (2048 bits or more). " +
			"The first signs and all are published, so replicas that share the reference agree on the JWKS. " +
			"scrim does not rotate these; empty means scrim generates and rotates its own keys in identity.issuer.key-dir.",
		RequireReference: true,
		RestartRequired:  true,
	})
)

func validIssuerURL(s string) error {
	if s == "" {
		return nil
	}
	u, err := url.Parse(s)
	if err != nil || !u.IsAbs() || u.Host == "" {
		return errors.New("must be an absolute http(s) URL")
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return errors.New("must be an https URL")
	}
	if u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return errors.New("must not carry a query, fragment or user info")
	}
	if strings.HasSuffix(u.Path, "/") {
		return errors.New("must not end with a slash")
	}
	return nil
}

// loopbackHost reports whether an issuer URL's host is loopback, where
// plain http is accepted.
func loopbackHost(u *url.URL) bool {
	h := u.Hostname()
	if h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

func optionalHostPort(s string) error {
	if s == "" {
		return nil
	}
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return errors.New("must be host:port")
	}
	if _, err := strconv.ParseUint(port, 10, 16); err != nil || host == "" {
		return errors.New("must be host:port")
	}
	return nil
}

// checkURL applies the scheme rule that needs two settings.
func checkURL(raw string, insecure bool) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", URLSetting.Name(), err)
	}
	if u.Scheme == "http" && !loopbackHost(u) && !insecure {
		return nil, fmt.Errorf("%s %q: use https (terminate TLS in front of %s), or set %s",
			URLSetting.Name(), raw, ListenSetting.Name(), InsecureHTTPSetting.Name())
	}
	return u, nil
}
