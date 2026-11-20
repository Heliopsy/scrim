// SPDX-License-Identifier: AGPL-3.0-only

// Package placeholder derives the placeholders the model sees in place of
// secret values (specs/redaction "Placeholder format", "Placeholder fields",
// design D3), and holds the versioned placeholder keys.
//
// A placeholder is `⟦scrim:<slug>:<vv><tag>⟧`: the slug names the reference,
// vv is the key version in two hex digits and tag is the first 8 bytes of
// HMAC-SHA256(key, "scrim-placeholder-v1" || 0x00 || value) in hex. The data
// plane computes the same function (scrim-redact `placeholder_for`); the
// control plane needs it for the placeholders it hands out itself (a captured
// token, a written secret) before the next snapshot reaches the data plane.
package placeholder

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/heliopsy/scrim/internal/secret"
)

// Placeholder delimiters.
const (
	Open  = "⟦scrim:"
	Close = "⟧"
)

// MaxSlugLen is the longest slug.
const MaxSlugLen = 48

// MinKeyLen is the shortest accepted key, as in the data plane.
const MinKeyLen = 16

const domain = "scrim-placeholder-v1\x00"

const tagBytes = 8

// Errors.
var (
	ErrKeyVersion = errors.New("placeholder: key version must be 1 to 255")
	ErrKeyShort   = fmt.Errorf("placeholder: key shorter than %d bytes", MinKeyLen)
	ErrSlug       = errors.New("placeholder: invalid slug")
)

// Key is one version of the placeholder key.
type Key struct {
	Version int
	Key     secret.Value
}

// Validate checks the version and length, never the bytes.
func (k Key) Validate() error {
	if k.Version < 1 || k.Version > 255 {
		return ErrKeyVersion
	}
	if k.Key.Len() < MinKeyLen {
		return ErrKeyShort
	}
	return nil
}

// ValidSlug reports whether s is a slug: [a-z0-9-], 1 to 48 bytes, not
// starting or ending with '-'.
func ValidSlug(s string) bool {
	if s == "" || len(s) > MaxSlugLen || s[0] == '-' || s[len(s)-1] == '-' {
		return false
	}
	for i := range len(s) {
		if !isSlugByte(s[i]) {
			return false
		}
	}
	return true
}

func isSlugByte(c byte) bool { return c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' }

// Slug derives a slug from any alias exactly like the data plane
// (scrim-redact `RefSlug::from_alias`): ASCII letters are lower-cased, every
// run of other characters becomes one '-', the result is trimmed and cut to
// 48 bytes, and an alias with no usable character becomes "ref".
func Slug(alias string) string {
	var b strings.Builder
	dash := false
	for i := range len(alias) {
		c := alias[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		if c >= 'a' && c <= 'z' || c >= '0' && c <= '9' {
			if dash && b.Len() > 0 {
				b.WriteByte('-')
			}
			dash = false
			b.WriteByte(c)
		} else {
			dash = true
		}
		if b.Len() >= MaxSlugLen {
			break
		}
	}
	out := b.String()
	if len(out) > MaxSlugLen {
		out = out[:MaxSlugLen]
	}
	out = strings.TrimRight(out, "-")
	if out == "" {
		return "ref"
	}
	return out
}

// Derive returns the placeholder for value under slug with k.
func Derive(k Key, slug string, value secret.Value) (string, error) {
	if err := k.Validate(); err != nil {
		return "", err
	}
	if !ValidSlug(slug) {
		return "", ErrSlug
	}
	var tag []byte
	err := k.Key.Expose(func(key []byte) error {
		m := hmac.New(sha256.New, key)
		m.Write([]byte(domain))
		return value.Expose(func(v []byte) error {
			m.Write(v)
			tag = m.Sum(nil)[:tagBytes]
			return nil
		})
	})
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s%s:%02x%s%s", Open, slug, k.Version, hex.EncodeToString(tag), Close), nil
}
