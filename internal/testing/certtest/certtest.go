// SPDX-License-Identifier: AGPL-3.0-only

// Package certtest issues client certificates and revocation lists for
// tests of client certificate identity. Keys are generated at runtime.
package certtest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/url"
	"sync/atomic"
	"testing"
	"time"
)

// CA is a test certificate authority.
type CA struct {
	Cert *x509.Certificate
	Key  *ecdsa.PrivateKey
	// PEM is the CA certificate, PEM.
	PEM []byte

	serial atomic.Int64
}

// NewCA returns a CA named cn, valid from an hour ago for a day.
func NewCA(t testing.TB, cn string) *CA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	ca := &CA{Cert: c, Key: key, PEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
	ca.serial.Store(100)
	return ca
}

// Leaf describes a client certificate to issue.
type Leaf struct {
	CN     string
	SPIFFE string
	DNS    []string
	// NotBefore and NotAfter default to an hour ago and an hour from now.
	NotBefore, NotAfter time.Time
	// ServerOnly issues a server-authentication certificate instead.
	ServerOnly bool
}

// Issued is a client certificate and its key.
type Issued struct {
	Cert *x509.Certificate
	// TLS is the certificate and key for a tls.Config.
	TLS tls.Certificate
	// CertPEM and KeyPEM for clients configured by file.
	CertPEM, KeyPEM []byte
}

// Issue signs a client certificate.
func (ca *CA) Issue(t testing.TB, l Leaf) Issued {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	nb, na := l.NotBefore, l.NotAfter
	if nb.IsZero() {
		nb = time.Now().Add(-time.Hour)
	}
	if na.IsZero() {
		na = time.Now().Add(time.Hour)
	}
	eku := x509.ExtKeyUsageClientAuth
	if l.ServerOnly {
		eku = x509.ExtKeyUsageServerAuth
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(ca.serial.Add(1)), Subject: pkix.Name{CommonName: l.CN},
		NotBefore: nb, NotAfter: na, DNSNames: l.DNS, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{eku}}
	if l.SPIFFE != "" {
		u, err := url.Parse(l.SPIFFE)
		if err != nil {
			t.Fatal(err)
		}
		tmpl.URIs = []*url.URL{u}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, &key.PublicKey, ca.Key)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	kd, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return Issued{Cert: c, TLS: tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: c},
		CertPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		KeyPEM:  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kd})}
}

// CRL returns a PEM revocation list that revokes certs, valid until
// nextUpdate (a day from now when zero).
func (ca *CA) CRL(t testing.TB, nextUpdate time.Time, revoked ...*x509.Certificate) []byte {
	t.Helper()
	if nextUpdate.IsZero() {
		nextUpdate = time.Now().Add(24 * time.Hour)
	}
	var entries []x509.RevocationListEntry
	for _, c := range revoked {
		entries = append(entries, x509.RevocationListEntry{SerialNumber: c.SerialNumber, RevocationTime: time.Now().Add(-time.Minute)})
	}
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number: big.NewInt(ca.serial.Add(1)), ThisUpdate: time.Now().Add(-time.Hour), NextUpdate: nextUpdate,
		RevokedCertificateEntries: entries,
	}, ca.Cert, ca.Key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der})
}
