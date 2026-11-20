// SPDX-License-Identifier: AGPL-3.0-only

package bwcrypto

import (
	"fmt"

	"github.com/heliopsy/scrim/internal/secret"
)

// UnlockUserKey derives the master key from the password and KDF parameters,
// stretches it and decrypts the account's protected user key. Intermediate
// keys are wiped before it returns.
func UnlockUserKey(password secret.Value, email string, p KDFParams, protectedUserKey string) (SymmetricKey, error) {
	mk, err := MasterKey(password, email, p)
	if err != nil {
		return SymmetricKey{}, err
	}
	defer mk.Wipe()
	stretched, err := StretchMasterKey(mk)
	if err != nil {
		return SymmetricKey{}, err
	}
	defer stretched.Wipe()
	uk, err := stretched.DecryptKey(protectedUserKey)
	if err != nil {
		return SymmetricKey{}, fmt.Errorf("bwcrypto: unlock user key: %w", err)
	}
	return uk, nil
}

// Registration is the client-side material a new account is registered with.
// MasterPasswordHash is a credential; the caller wipes it after use, together
// with UserKey.
type Registration struct {
	MasterPasswordHash secret.Value
	ProtectedUserKey   EncString
	Keys               KeyPair
	UserKey            SymmetricKey
}

// Wipe clears the key material held by the registration.
func (r Registration) Wipe() {
	r.MasterPasswordHash.Wipe()
	r.UserKey.Wipe()
}

// NewRegistration creates the keys a new account needs: a random user key,
// protected by the stretched master key, an RSA key pair whose private half
// is encrypted with the user key, and the server authentication hash.
func NewRegistration(password secret.Value, email string, p KDFParams) (Registration, error) {
	mk, err := MasterKey(password, email, p)
	if err != nil {
		return Registration{}, err
	}
	defer mk.Wipe()
	hash, err := MasterPasswordHash(mk, password)
	if err != nil {
		return Registration{}, err
	}
	stretched, err := StretchMasterKey(mk)
	if err != nil {
		hash.Wipe()
		return Registration{}, err
	}
	defer stretched.Wipe()
	uk, err := GenerateSymmetricKey()
	if err != nil {
		hash.Wipe()
		return Registration{}, err
	}
	protected, err := stretched.Encrypt(uk.Value())
	if err != nil {
		hash.Wipe()
		uk.Wipe()
		return Registration{}, err
	}
	kp, err := GenerateKeyPair(uk)
	if err != nil {
		hash.Wipe()
		uk.Wipe()
		return Registration{}, err
	}
	return Registration{MasterPasswordHash: hash, ProtectedUserKey: protected, Keys: kp, UserKey: uk}, nil
}
