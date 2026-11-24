// SPDX-License-Identifier: AGPL-3.0-only

package edge

import (
	"crypto/tls"
	"errors"
	"slices"
	"sync"
	"time"

	"github.com/heliopsy/scrim/internal/ca"
	"github.com/heliopsy/scrim/internal/secret"
)

// CertTTL is how long an edge listener certificate is valid. It is issued
// again at half that, or as soon as the CA that issued it changes.
const CertTTL = 24 * time.Hour

// CASource returns a CA's current certificate and a copy of its key, which
// the caller wipes.
type CASource func() (certPEM string, key secret.Value, err error)

// Certs issues the edge listener's certificate from the edge CA.
type Certs struct {
	// CA is the edge CA.
	CA CASource
	// Legacy, when set (edge.legacy-interception-certificate), is the
	// interception CA: a client that does not offer [EdgeCAProto], a
	// forwarder from before the edge CA, gets a certificate issued by it.
	Legacy CASource
	// Names are the host names and addresses the certificate carries.
	Names []string
	Now   func() time.Time

	mu           sync.Mutex
	edge, legacy issued
}

// issued is the certificate in use from one CA.
type issued struct {
	cur     *tls.Certificate
	caPEM   string
	renewAt time.Time
}

func (c *Certs) now() time.Time {
	if c.Now == nil {
		return time.Now()
	}
	return c.Now()
}

// GetCertificate is the tls.Config hook. A nil hello means the edge CA's
// certificate.
func (c *Certs) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if c.Legacy != nil && hello != nil && !slices.Contains(hello.SupportedProtos, EdgeCAProto) {
		return c.issue(&c.legacy, c.Legacy)
	}
	if c.CA == nil {
		return nil, errors.New("edge: no edge CA to issue the listener's certificate")
	}
	return c.issue(&c.edge, c.CA)
}

// LegacyCertificate issues (or returns) the interception CA's certificate,
// so start-up can check that it can be issued.
func (c *Certs) LegacyCertificate() (*tls.Certificate, error) {
	if c.Legacy == nil {
		return nil, errors.New("edge: no interception CA for the legacy certificate")
	}
	return c.issue(&c.legacy, c.Legacy)
}

func (c *Certs) issue(is *issued, src CASource) (*tls.Certificate, error) {
	certPEM, key, err := src()
	if err != nil {
		return nil, err
	}
	defer key.Wipe()
	now := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()
	if is.cur != nil && is.caPEM == certPEM && now.Before(is.renewAt) {
		return is.cur, nil
	}
	cert, err := ca.IssueServer(certPEM, key, c.Names, now, CertTTL)
	if err != nil {
		return nil, err
	}
	is.cur, is.caPEM = &cert, certPEM
	is.renewAt = now.Add(cert.Leaf.NotAfter.Sub(now) / 2)
	return is.cur, nil
}
