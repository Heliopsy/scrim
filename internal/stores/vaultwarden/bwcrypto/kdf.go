// SPDX-License-Identifier: AGPL-3.0-only

package bwcrypto

import (
	"crypto/hkdf"
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"

	"github.com/heliopsy/scrim/internal/secret"
)

// KDFType identifies the key derivation function of an account, as reported
// by the server's prelogin endpoint.
type KDFType int

const (
	// KDFPBKDF2 is PBKDF2-HMAC-SHA256.
	KDFPBKDF2 KDFType = 0
	// KDFArgon2id is Argon2id.
	KDFArgon2id KDFType = 1
)

// String returns the name used in Bitwarden's own clients.
func (t KDFType) String() string {
	switch t {
	case KDFPBKDF2:
		return "PBKDF2-SHA256"
	case KDFArgon2id:
		return "Argon2id"
	default:
		return fmt.Sprintf("unknown(%d)", int(t))
	}
}

// Bounds the official clients enforce. A server that asks for more is refused
// rather than allowed to make scrim burn CPU or memory without limit.
const (
	PBKDF2MinIterations   = 5000
	PBKDF2MaxIterations   = 2_000_000
	Argon2MinIterations   = 2
	Argon2MaxIterations   = 10
	Argon2MinMemoryMiB    = 16
	Argon2MaxMemoryMiB    = 1024
	Argon2MinParallelism  = 1
	Argon2MaxParallelism  = 16
	DefaultPBKDF2Iter     = 600_000
	DefaultArgon2Iter     = 3
	DefaultArgon2MemMiB   = 64
	DefaultArgon2Parallel = 4
)

// KDFParams are an account's key derivation parameters. Memory is in MiB, as
// in the Bitwarden API.
type KDFParams struct {
	Type        KDFType
	Iterations  int
	MemoryMiB   int
	Parallelism int
}

// DefaultPBKDF2 returns the default PBKDF2 parameters of current clients.
func DefaultPBKDF2() KDFParams {
	return KDFParams{Type: KDFPBKDF2, Iterations: DefaultPBKDF2Iter}
}

// DefaultArgon2id returns the default Argon2id parameters of current clients.
func DefaultArgon2id() KDFParams {
	return KDFParams{
		Type:        KDFArgon2id,
		Iterations:  DefaultArgon2Iter,
		MemoryMiB:   DefaultArgon2MemMiB,
		Parallelism: DefaultArgon2Parallel,
	}
}

// ErrKDFParams reports KDF parameters outside the accepted bounds.
var ErrKDFParams = errors.New("bwcrypto: KDF parameters out of bounds")

// Validate checks the parameters against the bounds of the official clients.
func (p KDFParams) Validate() error {
	switch p.Type {
	case KDFPBKDF2:
		if p.Iterations < PBKDF2MinIterations || p.Iterations > PBKDF2MaxIterations {
			return fmt.Errorf("%w: PBKDF2 iterations %d not in [%d, %d]", ErrKDFParams,
				p.Iterations, PBKDF2MinIterations, PBKDF2MaxIterations)
		}
	case KDFArgon2id:
		if p.Iterations < Argon2MinIterations || p.Iterations > Argon2MaxIterations {
			return fmt.Errorf("%w: Argon2id iterations %d not in [%d, %d]", ErrKDFParams,
				p.Iterations, Argon2MinIterations, Argon2MaxIterations)
		}
		if p.MemoryMiB < Argon2MinMemoryMiB || p.MemoryMiB > Argon2MaxMemoryMiB {
			return fmt.Errorf("%w: Argon2id memory %d MiB not in [%d, %d]", ErrKDFParams,
				p.MemoryMiB, Argon2MinMemoryMiB, Argon2MaxMemoryMiB)
		}
		if p.Parallelism < Argon2MinParallelism || p.Parallelism > Argon2MaxParallelism {
			return fmt.Errorf("%w: Argon2id parallelism %d not in [%d, %d]", ErrKDFParams,
				p.Parallelism, Argon2MinParallelism, Argon2MaxParallelism)
		}
	default:
		return fmt.Errorf("%w: unsupported KDF type %d", ErrKDFParams, int(p.Type))
	}
	return nil
}

// normalizeEmail is the salt form Bitwarden uses: trimmed and lower-cased.
func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

// MasterKey derives the 32-byte master key from the master password and the
// account email. The password is not retained.
func MasterKey(password secret.Value, email string, p KDFParams) (secret.Value, error) {
	if err := p.Validate(); err != nil {
		return secret.Value{}, err
	}
	if password.IsZero() {
		return secret.Value{}, errors.New("bwcrypto: empty master password")
	}
	salt := []byte(normalizeEmail(email))
	if len(salt) == 0 {
		return secret.Value{}, errors.New("bwcrypto: empty account email")
	}
	var key []byte
	err := password.Expose(func(pw []byte) error {
		switch p.Type {
		case KDFPBKDF2:
			// crypto/pbkdf2 takes the password as a string. That copy cannot be
			// wiped; it is short-lived and unreachable once Key returns.
			k, err := pbkdf2.Key(sha256.New, string(pw), salt, p.Iterations, 32)
			if err != nil {
				return fmt.Errorf("bwcrypto: pbkdf2: %w", err)
			}
			key = k
		case KDFArgon2id:
			// Bitwarden hashes the email to get a fixed-size Argon2 salt.
			s := sha256.Sum256(salt)
			key = argon2.IDKey(pw, s[:], uint32(p.Iterations), uint32(p.MemoryMiB)*1024, //nolint:gosec // bounds checked by Validate
				uint8(p.Parallelism), 32) //nolint:gosec // bounds checked by Validate
		}
		return nil
	})
	if err != nil {
		return secret.Value{}, err
	}
	return secret.Adopt(key), nil
}

// MasterPasswordHash returns the base64 server authentication hash:
// PBKDF2-SHA256 over the master key, salted with the password, one iteration.
// It proves knowledge of the password to the server without revealing the
// master key. The result is itself a credential and is returned as a Value.
func MasterPasswordHash(masterKey, password secret.Value) (secret.Value, error) {
	var out secret.Value
	err := masterKey.Expose(func(mk []byte) error {
		if len(mk) != 32 {
			return errors.New("bwcrypto: master key must be 32 bytes")
		}
		return password.Expose(func(pw []byte) error {
			h, err := pbkdf2.Key(sha256.New, string(mk), pw, 1, 32)
			if err != nil {
				return fmt.Errorf("bwcrypto: pbkdf2: %w", err)
			}
			enc := make([]byte, base64.StdEncoding.EncodedLen(len(h)))
			base64.StdEncoding.Encode(enc, h)
			secret.WipeBytes(h)
			out = secret.Adopt(enc)
			return nil
		})
	})
	return out, err
}

// StretchMasterKey expands the 32-byte master key with HKDF-Expand-SHA256
// into a 64-byte symmetric key: "enc" for the encryption half and "mac" for
// the MAC half.
func StretchMasterKey(masterKey secret.Value) (SymmetricKey, error) {
	var out SymmetricKey
	err := masterKey.Expose(func(mk []byte) error {
		if len(mk) != 32 {
			return errors.New("bwcrypto: master key must be 32 bytes")
		}
		enc, err := hkdf.Expand(sha256.New, mk, "enc", 32)
		if err != nil {
			return fmt.Errorf("bwcrypto: hkdf: %w", err)
		}
		mac, err := hkdf.Expand(sha256.New, mk, "mac", 32)
		if err != nil {
			secret.WipeBytes(enc)
			return fmt.Errorf("bwcrypto: hkdf: %w", err)
		}
		b := make([]byte, 0, 64)
		b = append(b, enc...)
		b = append(b, mac...)
		secret.WipeBytes(enc)
		secret.WipeBytes(mac)
		k, err := NewSymmetricKey(secret.Adopt(b))
		out = k
		return err
	})
	return out, err
}
