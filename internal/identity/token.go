// SPDX-License-Identifier: AGPL-3.0-only

package identity

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"fmt"
	"io"

	"github.com/heliopsy/scrim/internal/secret"
)

// TokenPrefix starts every session token, so scanners and the redactor can
// recognise one.
const TokenPrefix = "scrim_st_"

const (
	idBytes     = 10 // 16 base32 characters
	secretBytes = 32 // 43 base64url characters, 256 bits
	idLen       = 16
	secretLen   = 43
	tokenLen    = len(TokenPrefix) + idLen + 1 + secretLen
)

var idEncoding = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

// hashDomain separates session token hashes from any other SHA-256 use.
const hashDomain = "scrim session token v1\x00"

// mintToken returns a new token and its public ID. The token is
// TokenPrefix + id + "_" + secret; only the hash of the secret part is kept.
func mintToken(r io.Reader) (id string, tok secret.Value, hash []byte, err error) {
	raw := make([]byte, idBytes+secretBytes)
	defer secret.WipeBytes(raw)
	if _, err := io.ReadFull(r, raw); err != nil {
		return "", secret.Value{}, nil, fmt.Errorf("identity: reading randomness: %w", err)
	}
	id = idEncoding.EncodeToString(raw[:idBytes])
	buf := make([]byte, 0, tokenLen)
	buf = append(buf, TokenPrefix...)
	buf = append(buf, id...)
	buf = append(buf, '_')
	buf = base64.RawURLEncoding.AppendEncode(buf, raw[idBytes:])
	h := hashSecret(buf[len(TokenPrefix)+idLen+1:])
	return id, secret.Adopt(buf), h, nil
}

// parseToken splits a presented token into its ID and the hash of its
// secret part. It reports false for anything not shaped like a token.
func parseToken(tok []byte) (id string, hash []byte, ok bool) {
	tok = bytes.TrimSpace(tok)
	if len(tok) != tokenLen || !bytes.HasPrefix(tok, []byte(TokenPrefix)) {
		return "", nil, false
	}
	rest := tok[len(TokenPrefix):]
	if rest[idLen] != '_' {
		return "", nil, false
	}
	idPart, secPart := rest[:idLen], rest[idLen+1:]
	if _, err := idEncoding.DecodeString(string(idPart)); err != nil {
		return "", nil, false
	}
	if n, err := base64.RawURLEncoding.Decode(make([]byte, secretBytes), secPart); err != nil || n != secretBytes {
		return "", nil, false
	}
	return string(idPart), hashSecret(secPart), true
}

// hashSecret hashes the secret part of a token. The part carries 256 bits of
// randomness, so a fast hash is enough: there is nothing to brute-force.
func hashSecret(s []byte) []byte {
	h := sha256.New()
	h.Write([]byte(hashDomain))
	h.Write(s)
	return h.Sum(nil)
}

// LooksLikeToken reports whether s has the shape of a session token. It is
// for scanners and tests, not for authentication.
func LooksLikeToken(s []byte) bool { _, _, ok := parseToken(s); return ok }

var defaultRand io.Reader = rand.Reader
