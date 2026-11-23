// SPDX-License-Identifier: AGPL-3.0-only

package issuer

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Alg is the only signature algorithm scrim issues and publishes.
const Alg = "RS256"

// Claims are what an identity token says. Times are seconds since the
// epoch, as RFC 7519 has them.
type Claims struct {
	Issuer    string `json:"iss"`
	Subject   string `json:"sub"`
	Audience  string `json:"aud"`
	IssuedAt  int64  `json:"iat"`
	NotBefore int64  `json:"nbf"`
	Expiry    int64  `json:"exp"`
	ID        string `json:"jti"`

	// Agent is the agent name; AgentKind how scrim identified it (peer,
	// session or k8s).
	Agent     string `json:"agent"`
	AgentKind string `json:"agent_kind"`
	// Session and SessionName are set for a `scrim run` session.
	Session     string `json:"session,omitempty"`
	SessionName string `json:"session_name,omitempty"`
	// Host is the machine scrim runs on, for local agents.
	Host string `json:"host,omitempty"`
	// Namespace, ServiceAccount and Pod are set for Kubernetes agents.
	Namespace      string `json:"namespace,omitempty"`
	ServiceAccount string `json:"service_account,omitempty"`
	Pod            string `json:"pod,omitempty"`
	// Profile is scrim's configuration profile.
	Profile string `json:"profile,omitempty"`
}

type header struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Typ string `json:"typ"`
}

// sign returns the compact JWS of c, signed by k.
func sign(k signingKey, c Claims) ([]byte, error) {
	h, err := json.Marshal(header{Alg: Alg, Kid: k.kid, Typ: "JWT"})
	if err != nil {
		return nil, err
	}
	p, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	enc := base64.RawURLEncoding
	n := enc.EncodedLen(len(h)) + 1 + enc.EncodedLen(len(p))
	out := make([]byte, n, n+1+enc.EncodedLen(k.bits()/8))
	enc.Encode(out, h)
	out[enc.EncodedLen(len(h))] = '.'
	enc.Encode(out[enc.EncodedLen(len(h))+1:], p)
	sum := sha256.Sum256(out)
	sig, err := k.sign(sum[:])
	if err != nil {
		return nil, err
	}
	out = append(out, '.')
	return enc.AppendEncode(out, sig), nil
}

func signPKCS1(priv *rsa.PrivateKey, digest []byte) ([]byte, error) {
	return rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, digest)
}

// Verify checks a compact RS256 token against keys (by key ID), its expiry
// and not-before at now with leeway, its issuer and its audience, and
// returns its claims. scrim never verifies its own tokens on a request
// path: this is for tests and `scrim doctor`, mirroring what a store does.
func Verify(token, issuer, audience string, keys map[string]*rsa.PublicKey, now time.Time, leeway time.Duration) (Claims, error) {
	var c Claims
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return c, errors.New("not a compact JWS")
	}
	enc := base64.RawURLEncoding
	hb, err := enc.DecodeString(parts[0])
	if err != nil {
		return c, errors.New("header is not base64url")
	}
	var h header
	if err := json.Unmarshal(hb, &h); err != nil {
		return c, errors.New("header is not JSON")
	}
	if h.Alg != Alg {
		return c, fmt.Errorf("algorithm %q, want %s", h.Alg, Alg)
	}
	pub, ok := keys[h.Kid]
	if !ok {
		return c, fmt.Errorf("unknown key id %q", h.Kid)
	}
	sig, err := enc.DecodeString(parts[2])
	if err != nil {
		return c, errors.New("signature is not base64url")
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, sum[:], sig); err != nil {
		return c, errors.New("bad signature")
	}
	pb, err := enc.DecodeString(parts[1])
	if err != nil {
		return c, errors.New("payload is not base64url")
	}
	if err := json.Unmarshal(pb, &c); err != nil {
		return c, errors.New("payload is not JSON")
	}
	switch {
	case c.Issuer != issuer:
		return c, fmt.Errorf("issuer %q, want %q", c.Issuer, issuer)
	case c.Audience != audience:
		return c, fmt.Errorf("audience %q, want %q", c.Audience, audience)
	case now.After(time.Unix(c.Expiry, 0).Add(leeway)):
		return c, errors.New("expired")
	case now.Add(leeway).Before(time.Unix(c.NotBefore, 0)):
		return c, errors.New("not yet valid")
	}
	return c, nil
}
