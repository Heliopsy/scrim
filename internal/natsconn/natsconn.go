// SPDX-License-Identifier: AGPL-3.0-only

// Package natsconn builds the NATS connection options of the nats events
// backend from the nats.* settings (specs/state-and-scaling, design D9).
// NATS only ever carries wake-up hints with an empty payload.
package natsconn

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"math/rand/v2"
	"os"
	"strings"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/secret"
)

// Settings of the NATS connection.
var (
	Servers = config.Register(config.Spec[[]string]{
		Key:             "nats.servers",
		Description:     "NATS server URLs (nats://host:4222, tls://host:4222) used by events.backend nats.",
		RestartRequired: true,
	})
	Token = config.Register(config.Spec[config.SecretRef]{
		Key:              "nats.token",
		Description:      "Reference to a NATS authentication token; empty for none.",
		RequireReference: true,
		RestartRequired:  true,
	})
	Username = config.Register(config.Spec[string]{
		Key:             "nats.username",
		Description:     "NATS user for user and password authentication; empty for none.",
		RestartRequired: true,
	})
	Password = config.Register(config.Spec[config.SecretRef]{
		Key:              "nats.password",
		Description:      "Reference to the password of nats.username.",
		RequireReference: true,
		RestartRequired:  true,
	})
	CredentialsFile = config.Register(config.Spec[string]{
		Key:             "nats.credentials-file",
		Description:     "Path to a NATS credentials file (JWT and NKey seed), for decentralised authentication; empty for none.",
		RestartRequired: true,
	})
	TLSCAFile = config.Register(config.Spec[string]{
		Key:             "nats.tls-ca-file",
		Description:     "PEM file of the certificate authorities that sign the NATS server certificate; empty uses the system roots.",
		RestartRequired: true,
	})
	Timeout = config.Register(config.Spec[time.Duration]{
		Key:     "nats.timeout",
		Default: 5 * time.Second,
		Description: "Dial timeout, and the bound on the round trip that confirms a subscription after each reconnect. " +
			"The client also pings the server at this interval and treats two missed answers as a lost connection.",
		Validate: func(d time.Duration) error {
			if d < 100*time.Millisecond || d > time.Minute {
				return errors.New("must be between 100ms and 1m")
			}
			return nil
		},
		RestartRequired: true,
	})
)

// Options are what a connection is built from; tests set them directly.
type Options struct {
	Servers  []string
	Token    secret.Value
	Username string
	Password secret.Value
	Creds    string
	TLS      *tls.Config
	Timeout  time.Duration
	// Name is the client name the server shows.
	Name string
	// Dialer, if set, replaces the network dialer (tests cut connections
	// with it).
	Dialer nats.CustomDialer
	// ReconnectWait is the base wait between reconnect attempts.
	ReconnectWait time.Duration
}

// FromConfig reads the nats.* settings.
func FromConfig(cfg *config.Config) (Options, error) {
	o := Options{
		Servers:  Servers.Get(cfg),
		Username: Username.Get(cfg),
		Creds:    CredentialsFile.Get(cfg),
		Timeout:  Timeout.Get(cfg),
	}
	if len(o.Servers) == 0 {
		return o, errors.New("nats.servers is empty")
	}
	for _, k := range []struct {
		key config.Key[config.SecretRef]
		dst *secret.Value
	}{{Token, &o.Token}, {Password, &o.Password}} {
		if v, ok := cfg.Secret(k.key); ok {
			*k.dst = v
		} else if k.key.Get(cfg) != "" {
			return o, fmt.Errorf("%s is set but did not resolve", k.key.Name())
		}
	}
	if o.Username != "" && o.Password.IsZero() {
		return o, errors.New("nats.username is set without nats.password")
	}
	if f := TLSCAFile.Get(cfg); f != "" {
		pem, err := os.ReadFile(f) //nolint:gosec // operator-configured path
		if err != nil {
			return o, fmt.Errorf("nats.tls-ca-file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return o, fmt.Errorf("nats.tls-ca-file %s holds no PEM certificate", f)
		}
		o.TLS = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}
	}
	return o, nil
}

// NATSOptions converts o to nats.go options: reconnect forever with
// jittered waits, keep publishing into the reconnect buffer while down.
func (o Options) NATSOptions() []nats.Option {
	if o.Timeout <= 0 {
		o.Timeout = 5 * time.Second
	}
	if o.ReconnectWait <= 0 {
		o.ReconnectWait = 250 * time.Millisecond
	}
	name := o.Name
	if name == "" {
		name = "scrim"
	}
	opts := []nats.Option{
		nats.Name(name),
		nats.Timeout(o.Timeout),
		nats.PingInterval(o.Timeout),
		nats.MaxPingsOutstanding(2),
		nats.MaxReconnects(-1),
		nats.RetryOnFailedConnect(true),
		nats.CustomReconnectDelay(func(attempts int) time.Duration {
			// Doubling from ReconnectWait up to 30s, jittered.
			d := min(o.ReconnectWait<<min(attempts, 10), 30*time.Second)
			return d/2 + rand.N(d/2+1) //nolint:gosec // jitter, not a secret
		}),
	}
	// The library keeps credentials as strings for reconnects; this is the
	// narrowest scope that can hand them over.
	if !o.Token.IsZero() {
		_ = o.Token.Expose(func(b []byte) error { opts = append(opts, nats.Token(string(b))); return nil })
	}
	if o.Username != "" {
		_ = o.Password.Expose(func(b []byte) error {
			opts = append(opts, nats.UserInfo(o.Username, string(b)))
			return nil
		})
	}
	if o.Creds != "" {
		opts = append(opts, nats.UserCredentials(o.Creds))
	}
	if o.TLS != nil {
		opts = append(opts, nats.Secure(o.TLS))
	}
	if o.Dialer != nil {
		opts = append(opts, nats.SetCustomDialer(o.Dialer))
	}
	return opts
}

// URL joins the servers for nats.Connect.
func (o Options) URL() string { return strings.Join(o.Servers, ",") }
