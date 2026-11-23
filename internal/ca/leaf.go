// SPDX-License-Identifier: AGPL-3.0-only

package ca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/heliopsy/scrim/internal/secret"
)

// IssueServer signs a TLS server certificate for names (host names or IP
// addresses) with the CA whose certificate is caCertPEM and whose PKCS#8 PEM
// key is caKey, valid from now for ttl and never past the CA itself. The
// leaf's key is a fresh P-256 key held only in the returned certificate.
//
// scrim's own listeners that agents reach over the network (the edge
// listener) use it, so clients verify them against the CA they already
// trust for the tool proxy. caKey belongs to the caller; errors never
// contain key material.
func IssueServer(caCertPEM string, caKey secret.Value, names []string, now time.Time, ttl time.Duration) (tls.Certificate, error) {
	if len(names) == 0 {
		return tls.Certificate{}, errors.New("ca: a server certificate needs at least one name")
	}
	block, _ := pem.Decode([]byte(caCertPEM))
	if block == nil || block.Type != "CERTIFICATE" {
		return tls.Certificate{}, errors.New("ca: the CA certificate is not PEM")
	}
	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("ca: parse the CA certificate: %w", err)
	}
	var signer crypto.Signer
	err = caKey.Expose(func(b []byte) error {
		kb, _ := pem.Decode(b)
		if kb == nil || kb.Type != "PRIVATE KEY" {
			return errors.New("ca: the CA key is not a PKCS#8 PEM key")
		}
		k, err := x509.ParsePKCS8PrivateKey(kb.Bytes)
		secret.WipeBytes(kb.Bytes)
		if err != nil {
			return errors.New("ca: the CA key is not valid PKCS#8")
		}
		s, ok := k.(crypto.Signer)
		if !ok {
			return errors.New("ca: the CA key cannot sign")
		}
		signer = s
		return nil
	})
	if err != nil {
		return tls.Certificate{}, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("ca: generate the leaf key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return tls.Certificate{}, err
	}
	now = now.UTC().Truncate(time.Second)
	notAfter := now.Add(ttl)
	if notAfter.After(caCert.NotAfter) {
		notAfter = caCert.NotAfter
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{Organization: []string{Organization}, CommonName: names[0]},
		NotBefore:    now.Add(-clockSkew),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, n := range names {
		if ip := net.ParseIP(n); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, n)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, signer)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("ca: sign the server certificate: %w", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("ca: parse the server certificate: %w", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, nil
}
