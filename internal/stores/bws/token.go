// SPDX-License-Identifier: AGPL-3.0-only

package bws

import (
	"bytes"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores/internal/wire"
	"github.com/heliopsy/scrim/internal/stores/vaultwarden/bwcrypto"
)

// accessToken is a parsed Secrets Manager machine account access token:
//
//	0.<access token id>.<client secret>:<base64 of a 16-byte key>
//
// as bitwarden-core's AccessToken::from_str reads it. The client secret and
// the derived key are secret; the access token ID is a UUID and is not.
type accessToken struct {
	id           string
	clientSecret secret.Value
	// key decrypts the encrypted_payload the identity server returns at
	// login, which holds the organisation key.
	key bwcrypto.SymmetricKey
	// keyText is the base64 key part as written in the token, kept so
	// scrim can redact it on its own.
	keyText secret.Value
}

func (t *accessToken) wipe() {
	if t == nil {
		return
	}
	t.clientSecret.Wipe()
	t.key.Wipe()
	t.keyText.Wipe()
}

var uuidPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// errToken explains a malformed access token without quoting any of it.
var errToken = errors.New("access token is malformed")

// parseAccessToken parses tok without converting its secret parts to Go
// strings. The caller keeps ownership of tok. Errors say which part is wrong,
// never what it holds.
func parseAccessToken(tok secret.Value) (*accessToken, error) {
	var out *accessToken
	err := tok.Expose(func(b []byte) error {
		b = bytes.TrimSpace(b)
		head, keyPart, ok := bytes.Cut(b, []byte{':'})
		if !ok {
			return fmt.Errorf("%w: no encryption key after ':'", errToken)
		}
		parts := bytes.Split(head, []byte{'.'})
		if len(parts) != 3 {
			return fmt.Errorf("%w: want 3 dot-separated parts before ':', got %d", errToken, len(parts))
		}
		if string(parts[0]) != "0" {
			return fmt.Errorf("%w: unsupported version (only 0 is known)", errToken)
		}
		if !uuidPattern.Match(parts[1]) {
			return fmt.Errorf("%w: access token ID is not a UUID", errToken)
		}
		if len(parts[2]) == 0 {
			return fmt.Errorf("%w: empty client secret", errToken)
		}
		raw, err := decodeB64(keyPart)
		if err != nil {
			return fmt.Errorf("%w: encryption key is not base64", errToken)
		}
		if len(raw) != 16 {
			n := len(raw)
			secret.WipeBytes(raw)
			return fmt.Errorf("%w: encryption key must be 16 bytes, got %d", errToken, n)
		}
		key, err := deriveShareableKey(raw, "accesstoken", "sm-access-token")
		secret.WipeBytes(raw)
		if err != nil {
			return err
		}
		out = &accessToken{
			id:           strings.ToLower(string(parts[1])),
			clientSecret: secret.New(parts[2]),
			key:          key,
			keyText:      secret.New(keyPart),
		}
		return nil
	})
	return out, err
}

// decodeB64 decodes standard base64 with or without padding, as the SDK's
// B64 type accepts both.
func decodeB64(s []byte) ([]byte, error) {
	enc := base64.StdEncoding
	if len(s)%4 != 0 {
		enc = base64.RawStdEncoding
	}
	out := make([]byte, enc.DecodedLen(len(s)))
	n, err := enc.Decode(out, s)
	if err != nil {
		secret.WipeBytes(out)
		return nil, err
	}
	return out[:n], nil
}

// deriveShareableKey is bitwarden-crypto's derive_shareable_key: a PRK of
// HMAC-SHA256 keyed with "bitwarden-<name>" over the 16-byte secret, expanded
// with HKDF-SHA256 (no extract step) and info to the 64 bytes of an
// AES-256-CBC-HMAC-SHA256 key, encryption key first.
func deriveShareableKey(secret16 []byte, name, info string) (bwcrypto.SymmetricKey, error) {
	m := hmac.New(sha256.New, []byte("bitwarden-"+name))
	m.Write(secret16)
	prk := m.Sum(nil)
	defer secret.WipeBytes(prk)
	k, err := hkdf.Expand(sha256.New, prk, info, bwcrypto.SymmetricKeySize)
	if err != nil {
		return bwcrypto.SymmetricKey{}, fmt.Errorf("bws: hkdf: %w", err)
	}
	return bwcrypto.NewSymmetricKey(secret.Adopt(k))
}

// orgKeyFromPayload decrypts the identity server's encrypted_payload with
// the access token key and returns the organisation key it carries as
// {"encryptionKey": "<base64>"}. Only a 64-byte AES-256-CBC-HMAC-SHA256 key
// is accepted: a 32-byte key would mean unauthenticated encryption.
func orgKeyFromPayload(tokenKey bwcrypto.SymmetricKey, payload string) (bwcrypto.SymmetricKey, error) {
	pt, err := tokenKey.DecryptString(payload)
	if err != nil {
		return bwcrypto.SymmetricKey{}, fmt.Errorf("cannot decrypt the login payload with the access token key: %w", err)
	}
	defer pt.Wipe()
	var key bwcrypto.SymmetricKey
	err = pt.Expose(func(b []byte) error {
		var p struct {
			EncryptionKey wire.Raw `json:"encryptionKey"`
		}
		if err := json.Unmarshal(b, &p); err != nil {
			return errors.New("login payload is not the expected JSON")
		}
		defer p.EncryptionKey.Wipe()
		q := bytes.TrimSpace(p.EncryptionKey)
		if len(q) == 0 || q[0] != '"' {
			return errors.New("login payload has no encryptionKey")
		}
		s, err := wire.Unquote(q)
		if err != nil {
			return errors.New("login payload has a malformed encryptionKey")
		}
		raw, err := decodeB64(s)
		secret.WipeBytes(s)
		if err != nil {
			return errors.New("login payload encryptionKey is not base64")
		}
		if len(raw) != bwcrypto.SymmetricKeySize {
			n := len(raw)
			secret.WipeBytes(raw)
			return fmt.Errorf("organisation key is %d bytes; only 64-byte AES-256-CBC-HMAC-SHA256 keys are supported", n)
		}
		key, err = bwcrypto.NewSymmetricKey(secret.Adopt(raw))
		return err
	})
	return key, err
}

// jwtOrganization returns the organization claim of a bearer token, read
// without verifying the signature, as the SDK does: the token came from the
// identity server over TLS and the claim only addresses API calls the server
// authorises anyway.
func jwtOrganization(tok secret.Value) (string, error) {
	var org string
	err := tok.Expose(func(b []byte) error {
		parts := bytes.Split(b, []byte{'.'})
		if len(parts) != 3 {
			return errors.New("access token from the identity server is not a JWT")
		}
		body := make([]byte, base64.RawURLEncoding.DecodedLen(len(parts[1])))
		n, err := base64.RawURLEncoding.Decode(body, bytes.TrimRight(parts[1], "="))
		if err != nil {
			return errors.New("access token from the identity server has a malformed payload")
		}
		var claims struct {
			Organization string `json:"organization"`
		}
		if err := json.Unmarshal(body[:n], &claims); err != nil {
			return errors.New("access token from the identity server has a malformed payload")
		}
		if !uuidPattern.MatchString(claims.Organization) {
			return errors.New("access token from the identity server names no organization; is this a machine account access token?")
		}
		org = strings.ToLower(claims.Organization)
		return nil
	})
	return org, err
}
