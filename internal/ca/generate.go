// SPDX-License-Identifier: AGPL-3.0-only

package ca

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/heliopsy/scrim/internal/secret"
)

// CommonName is the start of every generated CA's common name. A Unix
// timestamp and part of the serial number follow, so every generation has a
// distinct subject (the cross certificate of a rotation carries the new
// name, and chain building must not confuse it with the previous one).
const CommonName = "scrim interception CA"

// Organization is the organisation of every generated CA's subject.
const Organization = "scrim"

// clockSkew is how far before its creation a certificate becomes valid,
// matching the data plane's leaves and cross certificates.
const clockSkew = 5 * time.Minute

// generation is one CA generation in memory.
type generation struct {
	id      string
	certPEM string
	cert    *x509.Certificate
	key     secret.Value // PKCS#8 PEM
}

func (g *generation) wipe() {
	if g != nil {
		g.key.Wipe()
	}
}

// newGeneration creates a self-signed P-256 CA in the shape the data plane's
// CertificateAuthority::from_pem accepts: PKCS#8 key, CA basic constraints,
// keyCertSign, cRLSign and digitalSignature.
//
// The path length is 1, not 0: during a rotation's overlap a client that
// trusts only this CA validates leaf -> cross certificate -> this CA, and
// the cross certificate counts as one intermediate below it.
func newGeneration(now time.Time, validity time.Duration) (*generation, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ca: generate key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	pub, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("ca: encode public key: %w", err)
	}
	ski, err := subjectKeyID(pub)
	if err != nil {
		return nil, err
	}
	now = now.UTC().Truncate(time.Second)
	sn := serial.Bytes()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{Organization},
			CommonName:   fmt.Sprintf("%s %d %s", CommonName, now.Unix(), hex.EncodeToString(sn[:min(4, len(sn))])),
		},
		NotBefore:             now.Add(-clockSkew),
		NotAfter:              now.Add(validity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
		SubjectKeyId:          ski,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("ca: create certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("ca: parse generated certificate: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("ca: encode private key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	secret.WipeBytes(keyDER)
	return &generation{
		id:      generationID(cert),
		certPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		cert:    cert,
		key:     secret.Adopt(keyPEM),
	}, nil
}

// subjectKeyID is the first 160 bits of the SHA-256 of the subjectPublicKey
// bits, the method rcgen uses for the authority key identifier of the
// leaves it signs, so the two always agree.
func subjectKeyID(spkiDER []byte) ([]byte, error) {
	var spki struct {
		Algorithm        pkix.AlgorithmIdentifier
		SubjectPublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(spkiDER, &spki); err != nil {
		return nil, fmt.Errorf("ca: parse public key: %w", err)
	}
	sum := sha256.Sum256(spki.SubjectPublicKey.Bytes)
	return sum[:20], nil
}

func randomSerial() (*big.Int, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("ca: random serial: %w", err)
	}
	b[0] &= 0x7f
	b[0] |= 0x01 // keep 16 bytes, so the name fragment always has 8 digits
	return new(big.Int).SetBytes(b), nil
}

// generationID names a generation on disk: creation time and serial.
func generationID(c *x509.Certificate) string {
	sn := hex.EncodeToString(c.SerialNumber.Bytes())
	return c.NotBefore.Add(clockSkew).UTC().Format("20060102T150405Z") + "-" + sn[:min(8, len(sn))]
}

// parseCert decodes exactly one PEM certificate and checks it can act as a
// CA that signs leaves.
func parseCert(certPEM []byte) (*x509.Certificate, error) {
	block, rest := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("no PEM CERTIFICATE block")
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("more than one PEM block; give exactly one CA certificate")
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}
	if !c.BasicConstraintsValid || !c.IsCA {
		return nil, errors.New("the certificate is not a CA (basic constraints)")
	}
	if c.KeyUsage != 0 && c.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, errors.New("the certificate's key usage does not allow signing certificates")
	}
	return c, nil
}

// checkKey parses a PKCS#8 PEM key and checks it belongs to cert. Errors
// never contain key material.
func checkKey(cert *x509.Certificate, key secret.Value) error {
	return key.Expose(func(b []byte) error {
		block, _ := pem.Decode(b)
		if block == nil {
			return errors.New("the private key is not PEM")
		}
		defer secret.WipeBytes(block.Bytes)
		if block.Type != "PRIVATE KEY" {
			return fmt.Errorf("the private key is a PEM %q block; PKCS#8 (\"PRIVATE KEY\") is required", block.Type)
		}
		k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return errors.New("the private key is not valid PKCS#8")
		}
		signer, ok := k.(crypto.Signer)
		if !ok {
			return errors.New("the private key cannot sign")
		}
		type equaler interface{ Equal(crypto.PublicKey) bool }
		pub, ok := signer.Public().(equaler)
		if !ok || !pub.Equal(cert.PublicKey) {
			return errors.New("the private key does not match the certificate")
		}
		return nil
	})
}
