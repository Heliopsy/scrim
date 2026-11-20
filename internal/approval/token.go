// SPDX-License-Identifier: AGPL-3.0-only

package approval

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/heliopsy/scrim/internal/secret"
)

// Decision links carry a token that binds one action (approve or deny) to one
// approval until an expiry:
//
//	v1.<kid>.<base64url(payload)>.<base64url(HMAC-SHA256(key, "scrim-approval-v1." + kid + "." + payload))>
//
// payload is JSON: {"a": approval ID, "d": "approve"|"deny", "exp": unix
// seconds, "n": random nonce, "via": notifier name}. A token is single-use
// because an approval leaves pending exactly once: after the first decision
// every token for it, approve or deny, is refused. The key is
// approvals.signing-key, shared by every replica; key IDs allow rotation.

// Token errors. They say what is wrong with the token, never anything about
// the key.
var (
	ErrTokenInvalid  = errors.New("approval: decision token is malformed or its signature does not verify")
	ErrTokenExpired  = errors.New("approval: decision token has expired")
	ErrTokenMismatch = errors.New("approval: decision token was issued for another approval")
)

// Action is what a decision token does.
type Action string

// Token actions.
const (
	ActionApprove Action = "approve"
	ActionDeny    Action = "deny"
)

// MinKeyLen is the shortest accepted signing key.
const MinKeyLen = 32

const tokenContext = "scrim-approval-v1."

var kidPattern = regexp.MustCompile(`^[a-z0-9-]{1,32}$`)

// Signer mints and verifies decision tokens.
type Signer struct {
	current string
	keys    map[string]secret.Value
}

// NewSigner uses keys by key ID and signs with current. Older keys keep
// verifying tokens they signed until they are removed.
func NewSigner(current string, keys map[string]secret.Value) (*Signer, error) {
	if _, ok := keys[current]; !ok {
		return nil, fmt.Errorf("approval: signing key %q is not configured", current)
	}
	for kid, k := range keys {
		if !kidPattern.MatchString(kid) {
			return nil, fmt.Errorf("approval: key ID %q must be 1-32 lower-case letters, digits or dashes", kid)
		}
		if k.Len() < MinKeyLen {
			return nil, fmt.Errorf("approval: signing key %q is shorter than %d bytes", kid, MinKeyLen)
		}
	}
	return &Signer{current: current, keys: keys}, nil
}

// RandomSigner returns a signer with a fresh random key. Its tokens stop
// verifying when the process exits and are not valid on other replicas, so
// it is only suitable for a single process with the memory backend.
func RandomSigner() *Signer {
	b := make([]byte, MinKeyLen)
	_, _ = rand.Read(b)
	return &Signer{current: "ephemeral", keys: map[string]secret.Value{"ephemeral": secret.Adopt(b)}}
}

type payload struct {
	A   string `json:"a"`
	D   Action `json:"d"`
	Exp int64  `json:"exp"`
	N   string `json:"n"`
	Via string `json:"via,omitempty"`
}

// Mint returns a token for action on approval id, valid until exp.
func (s *Signer) Mint(id string, action Action, exp time.Time, via string) (string, error) {
	nonce := make([]byte, 12)
	_, _ = rand.Read(nonce)
	body, err := json.Marshal(payload{A: id, D: action, Exp: exp.Unix(), N: hex.EncodeToString(nonce), Via: via})
	if err != nil {
		return "", err
	}
	p := base64.RawURLEncoding.EncodeToString(body)
	mac, err := s.mac(s.current, p)
	if err != nil {
		return "", err
	}
	return "v1." + s.current + "." + p + "." + base64.RawURLEncoding.EncodeToString(mac), nil
}

func (s *Signer) mac(kid, p string) ([]byte, error) {
	k, ok := s.keys[kid]
	if !ok {
		return nil, ErrTokenInvalid
	}
	var sum []byte
	err := k.Expose(func(key []byte) error {
		h := hmac.New(sha256.New, key)
		h.Write([]byte(tokenContext + kid + "." + p))
		sum = h.Sum(nil)
		return nil
	})
	return sum, err
}

// Claims are a verified token's contents.
type Claims struct {
	Approval string
	Action   Action
	Expires  time.Time
	Via      string
}

// Verify checks token for approval id at now.
func (s *Signer) Verify(token, id string, now time.Time) (Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 4 || parts[0] != "v1" {
		return Claims{}, ErrTokenInvalid
	}
	kid, p, sig := parts[1], parts[2], parts[3]
	want, err := s.mac(kid, p)
	if err != nil {
		return Claims{}, ErrTokenInvalid
	}
	got, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil || !hmac.Equal(got, want) {
		return Claims{}, ErrTokenInvalid
	}
	raw, err := base64.RawURLEncoding.DecodeString(p)
	if err != nil {
		return Claims{}, ErrTokenInvalid
	}
	var pl payload
	if err := json.Unmarshal(raw, &pl); err != nil || (pl.D != ActionApprove && pl.D != ActionDeny) || pl.A == "" {
		return Claims{}, ErrTokenInvalid
	}
	if pl.A != id {
		return Claims{}, ErrTokenMismatch
	}
	exp := time.Unix(pl.Exp, 0)
	if !now.Before(exp) {
		return Claims{}, ErrTokenExpired
	}
	return Claims{Approval: pl.A, Action: pl.D, Expires: exp, Via: pl.Via}, nil
}
