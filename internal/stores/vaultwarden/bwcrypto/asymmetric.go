// SPDX-License-Identifier: AGPL-3.0-only

package bwcrypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // RSA-OAEP-SHA1 is part of the Bitwarden protocol (type 4)
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"hash"

	"github.com/heliopsy/scrim/internal/secret"
)

// PrivateKey is an account's RSA private key. It prints as a redaction
// marker. Go's math/big does not allow wiping the key's integers, so hold a
// PrivateKey only while organisation keys are being unwrapped and drop it
// afterwards.
type PrivateKey struct {
	k *rsa.PrivateKey
}

// String implements fmt.Stringer and never shows key material.
func (PrivateKey) String() string { return secret.Marker }

// Format implements fmt.Formatter so every verb prints the marker.
func (PrivateKey) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte(secret.Marker)) }

// GoString implements fmt.GoStringer.
func (PrivateKey) GoString() string { return "bwcrypto.PrivateKey(" + secret.Marker + ")" }

// Public returns the public half.
func (p PrivateKey) Public() *rsa.PublicKey {
	if p.k == nil {
		return nil
	}
	return &p.k.PublicKey
}

// DecryptPrivateKey decrypts an account's encrypted PKCS#8 RSA private key
// with the user key.
func DecryptPrivateKey(userKey SymmetricKey, encrypted string) (PrivateKey, error) {
	der, err := userKey.DecryptString(encrypted)
	if err != nil {
		return PrivateKey{}, fmt.Errorf("bwcrypto: private key: %w", err)
	}
	defer der.Wipe()
	var pk PrivateKey
	err = der.Expose(func(b []byte) error {
		k, err := x509.ParsePKCS8PrivateKey(b)
		if err != nil {
			return fmt.Errorf("%w: private key is not PKCS#8", ErrKey)
		}
		rk, ok := k.(*rsa.PrivateKey)
		if !ok {
			return fmt.Errorf("%w: private key is not RSA", ErrKey)
		}
		pk = PrivateKey{k: rk}
		return nil
	})
	return pk, err
}

func oaepHash(t EncType) (func() hash.Hash, error) {
	switch t {
	case EncRSA2048OAEPSHA256B64:
		return sha256.New, nil
	case EncRSA2048OAEPSHA1B64:
		return sha1.New, nil
	default:
		return nil, fmt.Errorf("%w: type %d for asymmetric data (only types 3 and 4 are accepted)", ErrUnsupported, t)
	}
}

// Decrypt decrypts an RSA-OAEP EncString (type 3 or 4).
func (p PrivateKey) Decrypt(e EncString) (secret.Value, error) {
	if p.k == nil {
		return secret.Value{}, fmt.Errorf("%w: no private key", ErrKey)
	}
	h, err := oaepHash(e.Type)
	if err != nil {
		return secret.Value{}, err
	}
	pt, err := rsa.DecryptOAEP(h(), nil, p.k, e.Data, nil)
	if err != nil {
		// Do not wrap: the rsa error is generic, but keep the message ours.
		return secret.Value{}, fmt.Errorf("%w: RSA-OAEP decryption failed", ErrKey)
	}
	return secret.Adopt(pt), nil
}

// DecryptKey unwraps a 64-byte symmetric key, such as an organisation key.
func (p PrivateKey) DecryptKey(s string) (SymmetricKey, error) {
	e, err := ParseEncString(s)
	if err != nil {
		return SymmetricKey{}, err
	}
	v, err := p.Decrypt(e)
	if err != nil {
		return SymmetricKey{}, err
	}
	return NewSymmetricKey(v)
}

// EncryptRSA encrypts plaintext for a public key as type 4 (RSA-OAEP-SHA1),
// the form Bitwarden servers and clients exchange organisation keys in.
func EncryptRSA(pub *rsa.PublicKey, plaintext secret.Value) (EncString, error) {
	var out EncString
	err := plaintext.Expose(func(pt []byte) error {
		ct, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, pub, pt, nil) //nolint:gosec // protocol type 4
		if err != nil {
			return fmt.Errorf("bwcrypto: rsa encrypt: %w", err)
		}
		out = EncString{Type: EncRSA2048OAEPSHA1B64, Data: ct}
		return nil
	})
	return out, err
}

// ParsePublicKey parses a base64 SPKI DER public key as the server returns it.
func ParsePublicKey(b64 string) (*rsa.PublicKey, error) {
	der, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("%w: public key is not base64", ErrKey)
	}
	k, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("%w: public key is not SPKI", ErrKey)
	}
	rk, ok := k.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%w: public key is not RSA", ErrKey)
	}
	return rk, nil
}

// KeyPair is a new account key pair in the form the registration and key
// endpoints take: the SPKI public key in base64 and the PKCS#8 private key
// encrypted with the user key.
type KeyPair struct {
	PublicKey           string
	EncryptedPrivateKey EncString
}

// GenerateKeyPair creates a 2048-bit RSA key pair and encrypts the private
// half with the user key.
func GenerateKeyPair(userKey SymmetricKey) (KeyPair, error) {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return KeyPair{}, fmt.Errorf("bwcrypto: rsa: %w", err)
	}
	pub, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		return KeyPair{}, fmt.Errorf("bwcrypto: rsa: %w", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return KeyPair{}, fmt.Errorf("bwcrypto: rsa: %w", err)
	}
	priv := secret.Adopt(der)
	defer priv.Wipe()
	enc, err := userKey.Encrypt(priv)
	if err != nil {
		return KeyPair{}, err
	}
	return KeyPair{PublicKey: base64.StdEncoding.EncodeToString(pub), EncryptedPrivateKey: enc}, nil
}
