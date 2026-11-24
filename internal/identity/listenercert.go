// SPDX-License-Identifier: AGPL-3.0-only

package identity

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"slices"
	"sync/atomic"
	"time"

	"github.com/heliopsy/scrim/internal/secret"
)

// ListenerCert is the operator's certificate for the TLS listeners of
// client certificate identity, presented instead of one scrim's CA issues.
// ChainPEM is public; Key is the end entity's private key.
type ListenerCert struct {
	// ChainPEM holds the certificates, end entity first, PEM.
	ChainPEM []byte
	// Key is the end entity's private key, PEM.
	Key secret.Value
	// Leaf is the parsed end entity.
	Leaf *x509.Certificate
}

// ParseListenerCert checks an operator's listener certificate: a chain of
// at least one certificate, an end entity that is not a CA, may serve TLS
// (no extended key usage, or server authentication among them) and is
// within its validity period at now, and a key that belongs to it. Errors
// never quote the key.
func ParseListenerCert(chainPEM []byte, key secret.Value, now time.Time) (*ListenerCert, error) {
	var certs []byte
	rest := chainPEM
	n := 0
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		if b.Type != "CERTIFICATE" {
			continue
		}
		certs = append(certs, pem.EncodeToMemory(b)...)
		n++
	}
	if n == 0 {
		return nil, errors.New("no certificate in the listener certificate file")
	}
	var leaf *x509.Certificate
	err := key.Expose(func(k []byte) error {
		pair, err := tls.X509KeyPair(certs, k)
		if err != nil {
			return errors.New("the listener key does not match the certificate, or is not a PEM private key")
		}
		leaf = pair.Leaf
		if leaf == nil {
			leaf, err = x509.ParseCertificate(pair.Certificate[0])
		}
		return err
	})
	if err != nil {
		return nil, err
	}
	switch {
	case leaf.IsCA:
		return nil, fmt.Errorf("the listener certificate (%s) is a CA certificate", leaf.Subject.CommonName)
	case len(leaf.ExtKeyUsage) > 0 && !slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageServerAuth) &&
		!slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageAny):
		return nil, fmt.Errorf("the listener certificate (%s) does not allow server authentication", leaf.Subject.CommonName)
	case now.Before(leaf.NotBefore):
		return nil, fmt.Errorf("the listener certificate (%s) is not valid before %s", leaf.Subject.CommonName, leaf.NotBefore.UTC().Format(time.RFC3339))
	case now.After(leaf.NotAfter):
		return nil, fmt.Errorf("the listener certificate (%s) expired at %s", leaf.Subject.CommonName, leaf.NotAfter.UTC().Format(time.RFC3339))
	}
	return &ListenerCert{ChainPEM: certs, Key: key, Leaf: leaf}, nil
}

// ListenerCertSource holds the operator's listener certificate in force and
// reloads it from its file and key reference, so a certificate renewed in
// place (cert-manager, an ACME client) is presented without a restart.
type ListenerCertSource struct {
	// Read returns the chain (PEM) and the key. The source owns the key.
	Read func() ([]byte, secret.Value, error)
	// Now is the clock; time.Now when nil.
	Now func() time.Time
	// RetireAfter is how long a replaced certificate keeps its key, for
	// readers that loaded it just before. One minute when zero.
	RetireAfter time.Duration

	cur atomic.Pointer[ListenerCert]
}

// Current is the certificate in force, nil before the first successful
// Reload or on a nil source.
func (s *ListenerCertSource) Current() *ListenerCert {
	if s == nil {
		return nil
	}
	return s.cur.Load()
}

// Reload reads the certificate and key again and reports whether they
// changed. On an error the certificate in force is kept: a renewal that is
// half written, or a certificate that expired, never replaces a working one.
func (s *ListenerCertSource) Reload() (bool, error) {
	chain, key, err := s.Read()
	if err != nil {
		return false, err
	}
	now := time.Now()
	if s.Now != nil {
		now = s.Now()
	}
	c, err := ParseListenerCert(chain, key, now)
	if err != nil {
		key.Wipe()
		return false, err
	}
	old := s.cur.Load()
	if old != nil && bytes.Equal(old.ChainPEM, c.ChainPEM) && old.Key.Equal(c.Key) {
		key.Wipe()
		return false, nil
	}
	s.cur.Store(c)
	if old != nil {
		after := s.RetireAfter
		if after == 0 {
			after = time.Minute
		}
		time.AfterFunc(after, old.Key.Wipe)
	}
	return true, nil
}
