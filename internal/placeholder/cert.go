// SPDX-License-Identifier: AGPL-3.0-only

package placeholder

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"time"
)

// Placeholder client certificates (specs/credential-injection "Client
// certificates toward upstreams"). A tool configuration that needs a client
// certificate (a kubeconfig with client-certificate-data) gets a placeholder
// one: an Ed25519 key whose seed is SHA-256("scrim-placeholder-cert-v1" ||
// 0x00 || placeholder) for one of the credential's placeholder strings, in a
// self-signed certificate. The tool proxy recognises it by its public key
// (scrim-toolproxy `clientcert`) and presents the real certificate upstream.
// The key derives from public placeholder text, so it is no secret.

const certDomain = "scrim-placeholder-cert-v1\x00"

// ClientCertificateKey returns the placeholder certificate key for
// placeholder.
func ClientCertificateKey(placeholder string) ed25519.PrivateKey {
	seed := sha256.Sum256([]byte(certDomain + placeholder))
	return ed25519.NewKeyFromSeed(seed[:])
}

// ClientCertificate returns a self-signed placeholder certificate and its
// key, PEM, for placeholder. Not secret.
func ClientCertificate(placeholder, commonName string) (certPEM, keyPEM []byte, err error) {
	key := ClientCertificateKey(placeholder)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2099, 12, 31, 0, 0, 0, 0, time.UTC),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return nil, nil, err
	}
	pk, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pk}), nil
}
