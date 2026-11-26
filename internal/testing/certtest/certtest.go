// SPDX-License-Identifier: AGPL-3.0-only

// Package certtest issues client certificates and revocation lists for
// tests of client certificate identity. Keys are generated at runtime.
package certtest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"
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
	// OCSP lists OCSP responder URLs for the authority information access
	// extension.
	OCSP []string
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
		ExtKeyUsage: []x509.ExtKeyUsage{eku}, OCSPServer: l.OCSP}
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

// KeyPEM is the CA's private key, PKCS#8 PEM.
func (ca *CA) KeyPEM(t testing.TB) []byte {
	t.Helper()
	kd, err := x509.MarshalPKCS8PrivateKey(ca.Key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kd})
}

// Sub returns an intermediate CA named cn that ca issued, whose certificate
// names ocsp as its OCSP responders.
func (ca *CA) Sub(t testing.TB, cn string, ocsp ...string) *CA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(ca.serial.Add(1)), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, OCSPServer: ocsp}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, &key.PublicKey, ca.Key)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	sub := &CA{Cert: c, Key: key, PEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
	sub.serial.Store(1000)
	return sub
}

// Delegate issues an OCSP responder certificate, with the OCSP signing
// usage when signing is set, and its key.
func (ca *CA) Delegate(t testing.TB, signing bool) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	eku := x509.ExtKeyUsageServerAuth
	if signing {
		eku = x509.ExtKeyUsageOCSPSigning
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(ca.serial.Add(1)), Subject: pkix.Name{CommonName: "ocsp responder"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{eku}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, &key.PublicKey, ca.Key)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c, key
}

// Responder is a local OCSP responder for the certificates one CA issued.
// It answers good unless told otherwise, with a next update an hour away.
type Responder struct {
	// URL is where it listens.
	URL string

	ca     *CA
	srv    *httptest.Server
	hits   atomic.Int64
	mu     sync.Mutex
	status map[string]int
	next   time.Duration
	signer *x509.Certificate
	key    crypto.Signer
	broken bool
}

// Responder starts an OCSP responder for ca's certificates, stopped when
// the test ends.
func (ca *CA) Responder(t testing.TB) *Responder {
	t.Helper()
	r := &Responder{ca: ca, status: map[string]int{}, next: time.Hour}
	r.srv = httptest.NewServer(http.HandlerFunc(r.serve))
	r.URL = r.srv.URL
	t.Cleanup(r.srv.Close)
	return r
}

// Set makes the responder answer status (ocsp.Good, ocsp.Revoked or
// ocsp.Unknown) for c.
func (r *Responder) Set(c *x509.Certificate, status int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.status[c.SerialNumber.String()] = status
}

// NextUpdate sets how far ahead the next update of new answers is; zero
// leaves it out, negative makes answers stale.
func (r *Responder) NextUpdate(d time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.next = d
}

// SignWith makes the responder sign with a delegated certificate and key
// (embedded in the answer) instead of the CA's key; nil goes back to the CA.
func (r *Responder) SignWith(c *x509.Certificate, key crypto.Signer) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.signer, r.key = c, key
}

// Broken makes the responder answer HTTP 500.
func (r *Responder) Broken(b bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.broken = b
}

// Hits is how many requests the responder answered.
func (r *Responder) Hits() int64 { return r.hits.Load() }

// Close stops the responder: it becomes unreachable.
func (r *Responder) Close() { r.srv.Close() }

func (r *Responder) serve(w http.ResponseWriter, req *http.Request) {
	r.hits.Add(1)
	body, err := io.ReadAll(io.LimitReader(req.Body, 1<<16))
	if err != nil {
		http.Error(w, "read", http.StatusBadRequest)
		return
	}
	q, err := ocsp.ParseRequest(body)
	if err != nil {
		http.Error(w, "parse", http.StatusBadRequest)
		return
	}
	r.mu.Lock()
	st, ok := r.status[q.SerialNumber.String()]
	if !ok {
		st = ocsp.Good
	}
	next, signer, key, broken := r.next, r.signer, r.key, r.broken
	r.mu.Unlock()
	if broken {
		http.Error(w, "broken", http.StatusInternalServerError)
		return
	}
	now := time.Now()
	tmpl := ocsp.Response{Status: st, SerialNumber: q.SerialNumber, ThisUpdate: now.Add(-time.Minute)}
	switch {
	case next > 0:
		tmpl.NextUpdate = now.Add(next)
	case next < 0:
		tmpl.ThisUpdate = now.Add(2 * next)
		tmpl.NextUpdate = now.Add(next)
	}
	if st == ocsp.Revoked {
		tmpl.RevokedAt = now.Add(-time.Minute)
	}
	var der []byte
	if signer != nil {
		tmpl.Certificate = signer
		der, err = ocsp.CreateResponse(r.ca.Cert, signer, tmpl, key)
	} else {
		der, err = ocsp.CreateResponse(r.ca.Cert, r.ca.Cert, tmpl, r.ca.Key)
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/ocsp-response")
	_, _ = w.Write(der)
}
