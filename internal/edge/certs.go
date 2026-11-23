// SPDX-License-Identifier: AGPL-3.0-only

package edge

import (
	"crypto/tls"
	"errors"
	"sync"
	"time"

	"github.com/heliopsy/scrim/internal/ca"
	"github.com/heliopsy/scrim/internal/secret"
)

// CertTTL is how long an edge listener certificate is valid. It is issued
// again at half that, or as soon as scrim's CA changes.
const CertTTL = 24 * time.Hour

// Certs issues the edge listener's certificate from scrim's current CA.
type Certs struct {
	// CA returns the current CA certificate and a copy of its key, which
	// Certs wipes.
	CA func() (certPEM string, key secret.Value, err error)
	// Names are the host names and addresses the certificate carries.
	Names []string
	Now   func() time.Time

	mu      sync.Mutex
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

// GetCertificate is the tls.Config hook.
func (c *Certs) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	if c.CA == nil {
		return nil, errors.New("edge: no CA to issue the listener's certificate")
	}
	certPEM, key, err := c.CA()
	if err != nil {
		return nil, err
	}
	defer key.Wipe()
	now := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cur != nil && c.caPEM == certPEM && now.Before(c.renewAt) {
		return c.cur, nil
	}
	cert, err := ca.IssueServer(certPEM, key, c.Names, now, CertTTL)
	if err != nil {
		return nil, err
	}
	c.cur, c.caPEM = &cert, certPEM
	c.renewAt = now.Add(cert.Leaf.NotAfter.Sub(now) / 2)
	return c.cur, nil
}
