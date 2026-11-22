// SPDX-License-Identifier: AGPL-3.0-only

package placeholder

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"math/bits"
	"slices"
	"strings"

	"github.com/heliopsy/scrim/internal/secret"
)

// Format-preserving placeholders (specs/redaction "Format-preserving
// placeholders"): for a client that checks a token's shape, the placeholder
// keeps the value's known prefix, length and alphabet. The data plane computes
// the same function (scrim-redact `shaped_placeholder_for`, whose module
// documentation is the reference); testdata/shaped.json holds the vectors
// both sides check.

// FormatShape is the ValueEntry.placeholder_format that asks for a
// format-preserving placeholder.
const FormatShape = "shape"

// Shape limits: values outside them have no shape and keep the bracket form.
const (
	MinShapedLen = 16
	MaxShapedLen = 1024
)

// ErrNoShape reports a value without a shape.
var ErrNoShape = errors.New("placeholder: the value has no shape")

const (
	shapeDomain = "scrim-placeholder-shape-v1\x00"
	jwtHeader   = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0"
	b64urlChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	base32Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
)

// Prefixes are the known token prefixes a shaped placeholder keeps, longest
// match first, as in the data plane.
var Prefixes = []string{
	"github_pat_", "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "glpat-", "glrt-", "gldt-",
	"xoxb-", "xoxp-", "xoxa-", "xoxr-", "xoxs-", "xoxe-", "xapp-",
	"sk-ant-api03-", "sk-ant-admin01-", "sk-proj-", "sk-svcacct-", "sk-",
	"AKIA", "ASIA", "hf_", "npm_", "pypi-", "dop_v1_", "doo_v1_", "shpat_", "shpss_",
	"sq0atp-", "SG.", "AIza", "hvs.", "hvb.", "glsa_", "lin_api_",
	"rk_live_", "sk_live_", "sk_test_", "pk_live_", "pk_test_",
}

var (
	keepSeparators    = []string{"github_pat_", "xoxb-", "xoxp-", "xoxa-", "xoxr-", "xoxs-", "xoxe-", "xapp-"}
	githubChecksummed = []string{"ghp_", "gho_", "ghu_", "ghs_", "ghr_"}
)

type shapeStream struct {
	key, slug, value []byte
	block            []byte
	counter          uint32
}

func (s *shapeStream) byte() byte {
	if len(s.block) == 0 {
		m := hmac.New(sha256.New, s.key)
		m.Write([]byte(shapeDomain))
		var c [4]byte
		binary.BigEndian.PutUint32(c[:], s.counter)
		m.Write(c[:])
		m.Write(s.slug)
		m.Write([]byte{0})
		m.Write(s.value)
		s.block = m.Sum(nil)
		s.counter++
	}
	b := s.block[0]
	s.block = s.block[1:]
	return b
}

func (s *shapeStream) pick(alphabet string) byte {
	n := len(alphabet)
	limit := 256 - 256%n
	for {
		if b := int(s.byte()); b < limit {
			return alphabet[b%n]
		}
	}
}

func isB64URL(s string) bool {
	if s == "" {
		return false
	}
	for i := range len(s) {
		c := s[i]
		if !isAlnum(c) && c != '-' && c != '_' {
			return false
		}
	}
	return true
}

func isAlnum(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z'
}

func base62(v uint32, alphabet string) string {
	out := make([]byte, 6)
	for i := 5; i >= 0; i-- {
		out[i] = alphabet[v%62]
		v /= 62
	}
	return string(out)
}

func githubChecksumValid(prefix string, body []byte) bool {
	const a1 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	const a2 = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	tail := string(body[30:36])
	for _, data := range [][]byte{body[:30], append([]byte(prefix), body[:30]...)} {
		crc := crc32.ChecksumIEEE(data)
		if tail == base62(crc, a1) || tail == base62(crc, a2) {
			return true
		}
	}
	return false
}

// Shaped returns the format-preserving placeholder for value under slug with
// k, or ErrNoShape.
func Shaped(k Key, slug string, value secret.Value) (string, error) {
	if err := k.Validate(); err != nil {
		return "", err
	}
	if !ValidSlug(slug) {
		return "", ErrSlug
	}
	var out string
	err := k.Key.Expose(func(key []byte) error {
		return value.Expose(func(v []byte) error {
			var err error
			out, err = shaped(key, slug, v)
			return err
		})
	})
	return out, err
}

func shaped(key []byte, slug string, value []byte) (string, error) {
	if len(value) < MinShapedLen || len(value) > MaxShapedLen {
		return "", ErrNoShape
	}
	for _, c := range value {
		if c < 0x21 || c > 0x7e {
			return "", ErrNoShape
		}
	}
	st := &shapeStream{key: key, slug: []byte(slug), value: value}
	v := string(value)

	if segs := strings.Split(v, "."); len(segs) == 3 && strings.HasPrefix(v, "eyJ") &&
		isB64URL(segs[0]) && isB64URL(segs[1]) && isB64URL(segs[2]) {
		n := max(len(segs[2]), 22)
		var b strings.Builder
		b.WriteString(jwtHeader)
		b.WriteByte('.')
		b.WriteString(base64.RawURLEncoding.EncodeToString([]byte(`{"scrim":"` + slug + `"}`)))
		b.WriteByte('.')
		for range n {
			b.WriteByte(st.pick(b64urlChars))
		}
		if b.String() == v {
			return "", ErrNoShape
		}
		return b.String(), nil
	}

	prefix := ""
	for _, p := range Prefixes {
		if strings.HasPrefix(v, p) && len(p) > len(prefix) {
			prefix = p
		}
	}
	rest := v[len(prefix):]
	pad := len(rest) - len(strings.TrimRight(rest, "="))
	body := rest[:len(rest)-pad]
	keepSep := slices.Contains(keepSeparators, prefix)
	kept := func(c byte) bool { return keepSep && (c == '-' || c == '_') }

	var alphabet string
	if prefix == "AKIA" || prefix == "ASIA" {
		alphabet = base32Chars
	} else {
		var digit, upper, lower bool
		var other []byte
		for i := range len(body) {
			c := body[i]
			switch {
			case kept(c):
			case c >= '0' && c <= '9':
				digit = true
			case c >= 'A' && c <= 'Z':
				upper = true
			case c >= 'a' && c <= 'z':
				lower = true
			default:
				other = append(other, c)
			}
		}
		var a strings.Builder
		if digit {
			a.WriteString("0123456789")
		}
		if upper {
			a.WriteString("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
		}
		if lower {
			a.WriteString("abcdefghijklmnopqrstuvwxyz")
		}
		slices.Sort(other)
		a.Write(slices.Compact(other))
		alphabet = a.String()
	}
	count := 0
	for i := range len(body) {
		if !kept(body[i]) {
			count++
		}
	}
	if len(alphabet) < 2 || count*(bits.Len(uint(len(alphabet)))-1) < 64 {
		return "", ErrNoShape
	}
	outBody := make([]byte, len(body))
	for i := range len(body) {
		if kept(body[i]) {
			outBody[i] = body[i]
		} else {
			outBody[i] = st.pick(alphabet)
		}
	}
	if slices.Contains(githubChecksummed, prefix) && len(outBody) == 36 {
		for githubChecksumValid(prefix, outBody) {
			outBody[35] = st.pick(alphabet)
		}
	}
	out := prefix + string(outBody) + strings.Repeat("=", pad)
	if out == v {
		return "", ErrNoShape
	}
	return out, nil
}
