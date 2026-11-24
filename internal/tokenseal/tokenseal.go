// SPDX-License-Identifier: AGPL-3.0-only

// Package tokenseal seals scrim's own tokens (session, Kubernetes service
// account and issued identity tokens) for the shared state, so every replica
// can redact a token another replica minted without the state ever holding it
// in plaintext (specs/state-and-scaling "Every replica redacts scrim's own
// tokens", design S1 to S4 of the shared-session-redaction change).
//
// The keys are derived from the placeholder keys, which every replica already
// shares: for each placeholder key version, HKDF-SHA256 with no salt and the
// info strings below gives a 32-byte sealing key and a 32-byte ID key. A token
// is sealed with AES-256-GCM under a random 96-bit nonce, with the token's
// kind and row ID as associated data, so a sealed token opens only as the row
// it was written for. The sealed form is nonce followed by ciphertext and tag.
package tokenseal

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/heliopsy/scrim/internal/placeholder"
	"github.com/heliopsy/scrim/internal/secret"
)

// HKDF info strings and the associated data prefix. Changing one makes every
// stored row unreadable.
const (
	sealInfo = "scrim/redaction-token-seal/v1"
	idInfo   = "scrim/redaction-token-id/v1"
	aadTag   = "scrim-redaction-token/v1"
)

const nonceSize = 12

// Errors.
var (
	// ErrUnknownVersion: the row was sealed under a key version the ring
	// does not hold.
	ErrUnknownVersion = errors.New("tokenseal: key version not in the placeholder key ring")
	// ErrOpen: the sealed bytes do not open as this row (damaged, moved to
	// another row, or sealed under another key).
	ErrOpen = errors.New("tokenseal: sealed token does not open")
)

type keys struct {
	version int
	seal    secret.Value
	id      secret.Value
}

// Sealer holds the keys derived from one placeholder key ring. It owns
// copies of them; Wipe clears them. It is safe for concurrent use once built.
type Sealer struct {
	keys []keys // highest version (current) first, as in the ring
}

// New derives the keys for every version in ring. The ring stays the
// caller's.
func New(ring *placeholder.Ring) (*Sealer, error) {
	if ring == nil || len(ring.Keys) == 0 {
		return nil, errors.New("tokenseal: no placeholder key")
	}
	s := &Sealer{}
	for _, k := range ring.Keys {
		var ks keys
		err := k.Key.Expose(func(b []byte) error {
			seal, err := hkdf.Key(sha256.New, b, nil, sealInfo, 32)
			if err != nil {
				return err
			}
			id, err := hkdf.Key(sha256.New, b, nil, idInfo, 32)
			if err != nil {
				secret.WipeBytes(seal)
				return err
			}
			ks = keys{version: k.Version, seal: secret.Adopt(seal), id: secret.Adopt(id)}
			return nil
		})
		if err != nil {
			s.Wipe()
			return nil, fmt.Errorf("tokenseal: deriving keys for version %d: %w", k.Version, err)
		}
		s.keys = append(s.keys, ks)
	}
	return s, nil
}

// Wipe clears every derived key.
func (s *Sealer) Wipe() {
	if s == nil {
		return
	}
	for _, k := range s.keys {
		k.seal.Wipe()
		k.id.Wipe()
	}
}

// Version is the key version new tokens are sealed under.
func (s *Sealer) Version() int { return s.keys[0].version }

func (s *Sealer) key(version int) (keys, bool) {
	for _, k := range s.keys {
		if k.version == version {
			return k, true
		}
	}
	return keys{}, false
}

// ID returns the row ID of a token that has no ID of its own: the hex
// HMAC-SHA256 of the token under the current ID key.
func (s *Sealer) ID(token []byte) string {
	var out string
	_ = s.keys[0].id.Expose(func(k []byte) error {
		m := hmac.New(sha256.New, k)
		m.Write(token)
		out = hex.EncodeToString(m.Sum(nil))
		return nil
	})
	return out
}

func aad(kind, id string) []byte {
	return []byte(aadTag + "\x00" + kind + "\x00" + id)
}

func gcm(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// Seal encrypts token for the row (kind, id) under the current key and
// returns the key version and the sealed bytes.
func (s *Sealer) Seal(kind, id string, token []byte) (int, []byte, error) {
	k := s.keys[0]
	var out []byte
	err := k.seal.Expose(func(key []byte) error {
		a, err := gcm(key)
		if err != nil {
			return err
		}
		nonce := make([]byte, nonceSize, nonceSize+len(token)+a.Overhead())
		if _, err := rand.Read(nonce); err != nil {
			return err
		}
		out = a.Seal(nonce, nonce, token, aad(kind, id))
		return nil
	})
	if err != nil {
		return 0, nil, fmt.Errorf("tokenseal: seal: %w", err)
	}
	return k.version, out, nil
}

// Open decrypts the sealed bytes of the row (kind, id) written under
// version. The caller owns the returned value.
func (s *Sealer) Open(kind, id string, version int, sealed []byte) (secret.Value, error) {
	k, ok := s.key(version)
	if !ok {
		return secret.Value{}, ErrUnknownVersion
	}
	var out secret.Value
	err := k.seal.Expose(func(key []byte) error {
		a, err := gcm(key)
		if err != nil {
			return err
		}
		if len(sealed) < nonceSize+a.Overhead() {
			return ErrOpen
		}
		plain, err := a.Open(nil, sealed[:nonceSize], sealed[nonceSize:], aad(kind, id))
		if err != nil {
			return ErrOpen
		}
		out = secret.Adopt(plain)
		return nil
	})
	if err != nil {
		if errors.Is(err, ErrOpen) {
			return secret.Value{}, ErrOpen
		}
		return secret.Value{}, fmt.Errorf("tokenseal: open: %w", err)
	}
	return out, nil
}
