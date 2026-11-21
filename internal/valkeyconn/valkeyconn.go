// SPDX-License-Identifier: AGPL-3.0-only

// Package valkeyconn builds the Valkey client the valkey events backend and
// the valkey rate-limit backend share (specs/state-and-scaling, design D9),
// from the valkey.* settings. Valkey only ever holds wake-up hints and
// rate-limit counters keyed by a hash of the agent: no value, reference or
// placeholder reaches it.
package valkeyconn

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/valkey-io/valkey-go"

	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/secret"
)

// Settings shared by every Valkey user.
var (
	Addresses = config.Register(config.Spec[[]string]{
		Key: "valkey.addresses",
		Description: "Valkey (or Redis-compatible) servers as host:port, used by events.backend valkey and ratelimit.backend valkey. " +
			"Several addresses of one cluster are seeds; the client discovers the rest.",
		RestartRequired: true,
	})
	Username = config.Register(config.Spec[string]{
		Key:             "valkey.username",
		Description:     "Valkey ACL user; empty uses the default user.",
		RestartRequired: true,
	})
	Password = config.Register(config.Spec[config.SecretRef]{
		Key:              "valkey.password",
		Description:      "Reference to the Valkey password (env:, file:, cred: or a store reference); empty for none.",
		RequireReference: true,
		RestartRequired:  true,
	})
	DB = config.Register(config.Spec[int]{
		Key:         "valkey.db",
		Description: "Valkey logical database (standalone servers only).",
		Validate: func(n int) error {
			if n < 0 {
				return errors.New("must not be negative")
			}
			return nil
		},
		RestartRequired: true,
	})
	TLS = config.Register(config.Spec[bool]{
		Key:             "valkey.tls",
		Description:     "Connect to Valkey over TLS, verifying the server against the system roots or valkey.tls-ca-file.",
		RestartRequired: true,
	})
	TLSCAFile = config.Register(config.Spec[string]{
		Key:             "valkey.tls-ca-file",
		Description:     "PEM file of the certificate authorities that sign the Valkey server certificate; empty uses the system roots.",
		RestartRequired: true,
	})
	Timeout = config.Register(config.Spec[time.Duration]{
		Key:     "valkey.timeout",
		Default: 5 * time.Second,
		Description: "Dial timeout and the bound on one Valkey round trip; a connection that does not answer a ping within it is " +
			"considered dead and replaced.",
		Validate: func(d time.Duration) error {
			if d < 100*time.Millisecond || d > time.Minute {
				return errors.New("must be between 100ms and 1m")
			}
			return nil
		},
		RestartRequired: true,
	})
)

// Options are what a client is built from; tests set them directly.
type Options struct {
	Addresses []string
	Username  string
	Password  secret.Value
	DB        int
	TLS       *tls.Config
	Timeout   time.Duration
	// ClientName names the connections in CLIENT LIST.
	ClientName string
	// Dial, if set, replaces the network dialer (tests cut connections
	// with it).
	Dial func(ctx context.Context, addr string, d *net.Dialer, t *tls.Config) (net.Conn, error)
}

// FromConfig reads the valkey.* settings.
func FromConfig(cfg *config.Config) (Options, error) {
	o := Options{
		Addresses: Addresses.Get(cfg),
		Username:  Username.Get(cfg),
		DB:        DB.Get(cfg),
		Timeout:   Timeout.Get(cfg),
	}
	if len(o.Addresses) == 0 {
		return o, errors.New("valkey.addresses is empty")
	}
	if pw, ok := cfg.Secret(Password); ok {
		o.Password = pw
	} else if Password.Get(cfg) != "" {
		return o, errors.New("valkey.password is set but did not resolve")
	}
	if TLS.Get(cfg) {
		tc := &tls.Config{MinVersion: tls.VersionTLS12}
		if f := TLSCAFile.Get(cfg); f != "" {
			pem, err := os.ReadFile(f) //nolint:gosec // operator-configured path
			if err != nil {
				return o, fmt.Errorf("valkey.tls-ca-file: %w", err)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(pem) {
				return o, fmt.Errorf("valkey.tls-ca-file %s holds no PEM certificate", f)
			}
			tc.RootCAs = pool
		}
		o.TLS = tc
	}
	return o, nil
}

// New connects a client. Errors name the setting, never the password.
func New(o Options) (valkey.Client, error) {
	if o.Timeout <= 0 {
		o.Timeout = 5 * time.Second
	}
	co := valkey.ClientOption{
		InitAddress:      o.Addresses,
		Username:         o.Username,
		SelectDB:         o.DB,
		TLSConfig:        o.TLS,
		ClientName:       o.ClientName,
		ConnWriteTimeout: o.Timeout,
		Dialer:           net.Dialer{Timeout: o.Timeout},
		// Hints and counters are tiny; client-side caching is not used.
		DisableCache: true,
	}
	if o.Dial != nil {
		co.DialCtxFn = o.Dial
	}
	// The client keeps the password for reconnects; the library takes it
	// as a string, so this is the narrowest scope that can hold it.
	if !o.Password.IsZero() {
		_ = o.Password.Expose(func(b []byte) error { co.Password = string(b); return nil })
	}
	c, err := valkey.NewClient(co)
	if err != nil {
		return nil, fmt.Errorf("valkey %v: %w", o.Addresses, scrub(err, o.Password))
	}
	return c, nil
}

// Ping checks the server answers within the client's timeout.
func Ping(ctx context.Context, c valkey.Client) error {
	return c.Do(ctx, c.B().Ping().Build()).Error()
}

// scrub hides a password a server or library error might echo.
func scrub(err error, pw secret.Value) error {
	if err == nil || pw.IsZero() {
		return err
	}
	leak := false
	_ = pw.Expose(func(b []byte) error {
		leak = len(b) > 0 && bytes.Contains([]byte(err.Error()), b)
		return nil
	})
	if leak {
		return errors.New("connection failed (error withheld: it quoted the password)")
	}
	return err
}
