// SPDX-License-Identifier: AGPL-3.0-only

// Package leak is scrim's leak checker and the shared vocabulary of the leak
// suite: generated fake secrets ("seeds"), findings and reports.
//
// The checker is deliberately independent of the redactor and the guard. It
// shares no code with them and decodes far more than they match, so anything
// they miss shows up here. It runs on captures of what a fake model provider
// received, never on live traffic.
//
// Seeds are fake values generated at run time. They never come from a store,
// and reports identify them by name, kind, length and a short hash, never by
// value, so a report can be pasted into an issue as is.
package leak

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"
)

// Kind names the shape of a generated secret.
type Kind string

// Kinds the generator knows. Each mimics the shape of a real credential
// family closely enough to exercise pattern detectors, with a random body.
const (
	KindAWSAccessKey Kind = "aws-access-key-id"
	KindAWSSecret    Kind = "aws-secret-access-key"
	KindGitHubToken  Kind = "github-token"
	KindAPIKey       Kind = "api-key"
	KindPassword     Kind = "password"
	KindJWT          Kind = "jwt"
	KindDBPassword   Kind = "db-password"
	KindPrivateKey   Kind = "private-key"
	KindShort        Kind = "short-password"
)

// Seed is one generated fake secret.
//
// The value is unexported and only reachable through [Seed.Value], so a Seed
// printed with fmt, slog or encoding/json never shows it. Seeds are fake, but
// the suite is written as if they were real so that the same habits hold when
// a user points it at their own setup.
type Seed struct {
	// Name is the reference alias the seed is registered under, for example
	// "leak/github-token". It is not secret.
	Name string
	// Kind is the shape of the value.
	Kind Kind
	// Public lists substrings of the value that are fixed by its format
	// (prefixes, PEM armour). Partial matches made only of public parts are
	// not leaks.
	Public []string

	value string
}

// NewSeed builds a seed from an existing fake value, for example one a user
// loaded into their own store. The caller must never pass a real secret.
func NewSeed(name string, kind Kind, value string, public ...string) Seed {
	return Seed{Name: name, Kind: kind, Public: public, value: value}
}

// Value returns the secret value. Callers must not log or print it.
func (s Seed) Value() string { return s.value }

// Len is the value length in bytes. Length is metadata and safe to print.
func (s Seed) Len() int { return len(s.value) }

// Hash is the first 12 hex digits of the SHA-256 of the value. It is safe to
// print and lets a reader match a finding to a seed without the value.
func (s Seed) Hash() string {
	sum := sha256.Sum256([]byte(s.value))
	return hex.EncodeToString(sum[:])[:12]
}

// String describes the seed without its value.
func (s Seed) String() string {
	return fmt.Sprintf("%s(%s, len=%d, sha256=%s)", s.Name, s.Kind, s.Len(), s.Hash())
}

// GoString keeps %#v from printing the value.
func (s Seed) GoString() string { return s.String() }

// MarshalJSON keeps encoding/json from printing the value.
func (s Seed) MarshalJSON() ([]byte, error) {
	return json.Marshal(SeedRef{Name: s.Name, Kind: s.Kind, Len: s.Len(), SHA256: s.Hash()})
}

// SeedRef is the printable identity of a seed.
type SeedRef struct {
	Name   string `json:"name"`
	Kind   Kind   `json:"kind"`
	Len    int    `json:"len"`
	SHA256 string `json:"sha256"`
}

// Ref returns the printable identity of the seed.
func (s Seed) Ref() SeedRef {
	return SeedRef{Name: s.Name, Kind: s.Kind, Len: s.Len(), SHA256: s.Hash()}
}

const (
	upper     = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	lower     = "abcdefghijklmnopqrstuvwxyz"
	digits    = "0123456789"
	alnum     = upper + lower + digits
	b32chars  = upper + "234567"
	b64chars  = alnum + "+/"
	urlsafe   = alnum + "-_"
	pwSymbols = `!#%&*+-./:<=>?@^_~"\$` + "'"
)

func randString(alphabet string, n int) string {
	var b strings.Builder
	max := big.NewInt(int64(len(alphabet)))
	for range n {
		i, err := rand.Int(rand.Reader, max)
		if err != nil {
			panic("leak: crypto/rand failed: " + err.Error())
		}
		b.WriteByte(alphabet[i.Int64()])
	}
	return b.String()
}

// password returns a random password of length n that contains at least one
// upper, lower, digit and two symbols, including a quote and a backslash, so
// every JSON, shell and URL escaping path is exercised.
func password(n int) string {
	if n < 8 {
		n = 8
	}
	body := []byte(randString(alnum+pwSymbols, n-6))
	body = append(body, randString(upper, 1)[0], randString(lower, 1)[0], randString(digits, 1)[0], '"', '\\', randString("%&+/<=", 1)[0])
	// Shuffle so the forced characters are not always at the end.
	for i := len(body) - 1; i > 0; i-- {
		j, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			panic("leak: crypto/rand failed: " + err.Error())
		}
		body[i], body[j.Int64()] = body[j.Int64()], body[i]
	}
	return string(body)
}

// Generate returns a fresh fake secret of the given kind.
func Generate(kind Kind) Seed {
	name := "leak/" + string(kind)
	switch kind {
	case KindAWSAccessKey:
		return NewSeed(name, kind, "AKIA"+randString(b32chars, 16), "AKIA")
	case KindAWSSecret:
		return NewSeed(name, kind, randString(b64chars, 40))
	case KindGitHubToken:
		return NewSeed(name, kind, "ghp_"+randString(alnum, 36), "ghp_")
	case KindAPIKey:
		return NewSeed(name, kind, "sk-test-"+randString(urlsafe, 40), "sk-test-")
	case KindPassword:
		return NewSeed(name, kind, password(20))
	case KindJWT:
		enc := base64.RawURLEncoding
		header := enc.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
		payload := enc.EncodeToString([]byte(`{"sub":"` + randString(alnum, 12) + `","iat":1700000000}`))
		sig := randString(urlsafe, 43)
		return NewSeed(name, kind, header+"."+payload+"."+sig, header+".", header+"."+enc.EncodeToString([]byte(`{"sub":"`))[:10])
	case KindDBPassword:
		return NewSeed(name, kind, randString(alnum, 24))
	case KindPrivateKey:
		var b strings.Builder
		b.WriteString("-----BEGIN PRIVATE KEY-----\n")
		body := randString(b64chars, 320)
		for i := 0; i < len(body); i += 64 {
			b.WriteString(body[i:min(i+64, len(body))])
			b.WriteByte('\n')
		}
		b.WriteString("-----END PRIVATE KEY-----")
		return NewSeed(name, kind, b.String(), "-----BEGIN PRIVATE KEY-----\n", "\n-----END PRIVATE KEY-----")
	case KindShort:
		// A digit at both ends: the matrix truncates a value to six of its
		// eight bytes inside a frame of letters (API_TOKEN=... LOG_LEVEL),
		// and a short value whose dropped end the frame happens to spell
		// (one in about a thousand ends in "lo") would read as a leak.
		return NewSeed(name, kind, randString(digits, 1)+randString(alnum, 6)+randString(digits, 1))
	default:
		panic("leak: unknown seed kind " + string(kind))
	}
}

// DefaultKinds is the seed set the suite runs with unless told otherwise.
var DefaultKinds = []Kind{
	KindAWSAccessKey, KindAWSSecret, KindGitHubToken, KindAPIKey, KindPassword,
	KindJWT, KindDBPassword, KindPrivateKey, KindShort,
}

// GenerateSet returns one fresh seed per kind.
func GenerateSet(kinds ...Kind) []Seed {
	if len(kinds) == 0 {
		kinds = DefaultKinds
	}
	out := make([]Seed, 0, len(kinds))
	for _, k := range kinds {
		out = append(out, Generate(k))
	}
	return out
}

// seedFile is the on-disk form of a seed set. It contains fake values only.
type seedFile struct {
	Comment string          `json:"comment"`
	Seeds   []seedFileEntry `json:"seeds"`
}

type seedFileEntry struct {
	Name   string   `json:"name"`
	Kind   Kind     `json:"kind"`
	Value  string   `json:"value"`
	Public []string `json:"public,omitempty"`
}

// WriteSeedFile writes seeds, values included, to path with mode 0600 so the
// system under test can load them into its store. Seeds are fake values; the
// file is still treated like a secret file.
func WriteSeedFile(path string, seeds []Seed) error {
	f := seedFile{Comment: "scrim leak suite: generated fake secrets, not real credentials"}
	for _, s := range seeds {
		f.Seeds = append(f.Seeds, seedFileEntry{Name: s.Name, Kind: s.Kind, Value: s.value, Public: s.Public})
	}
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o600)
}

// ReadSeedFile reads a seed set written by [WriteSeedFile] or by hand.
func ReadSeedFile(path string) ([]Seed, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f seedFile
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("seed file %s: %w", path, err)
	}
	if len(f.Seeds) == 0 {
		return nil, errors.New("seed file " + path + " holds no seeds")
	}
	out := make([]Seed, 0, len(f.Seeds))
	for _, e := range f.Seeds {
		if e.Name == "" || e.Value == "" {
			return nil, fmt.Errorf("seed file %s: every seed needs a name and a value", path)
		}
		out = append(out, NewSeed(e.Name, e.Kind, e.Value, e.Public...))
	}
	return out, nil
}
