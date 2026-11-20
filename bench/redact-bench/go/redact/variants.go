package redact

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"unicode/utf8"
)

// MinVariantLen: variants shorter than this are not used as patterns.
const MinVariantLen = 8

// PlaceholderLen is the byte length of ⟦kss:<12 hex>⟧.
const PlaceholderLen = 3 + 4 + 12 + 3

var (
	phOpen  = []byte("⟦kss:")
	phClose = []byte("⟧")
)

// Placeholder returns ⟦kss:<first 12 hex of HMAC-SHA256(key, v)>⟧.
func Placeholder(key []byte, v []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(v)
	var sum [32]byte
	h := m.Sum(sum[:0])
	out := make([]byte, 0, PlaceholderLen)
	out = append(out, phOpen...)
	out = hex.AppendEncode(out, h[:6])
	return append(out, phClose...)
}

const lhex = "0123456789abcdef"

// AppendJSONEscaped appends s escaped as JSON string content (no quotes).
// slash: escape '/' as \/ ; uni: escape non-ASCII as \uXXXX (UTF-16).
func AppendJSONEscaped(out []byte, s []byte, slash, uni bool) []byte {
	start := 0
	for i := 0; i < len(s); {
		c := s[i]
		if c >= 0x20 && c != '"' && c != '\\' && c < 0x80 && !(slash && c == '/') {
			i++
			continue
		}
		if c >= 0x80 && !uni {
			i++
			continue
		}
		out = append(out, s[start:i]...)
		if c >= 0x80 {
			r, n := utf8.DecodeRune(s[i:])
			u4 := func(x rune) {
				out = append(out, '\\', 'u', lhex[(x>>12)&15], lhex[(x>>8)&15], lhex[(x>>4)&15], lhex[x&15])
			}
			if r >= 0x10000 {
				r -= 0x10000
				u4(0xD800 + (r >> 10))
				u4(0xDC00 + (r & 0x3FF))
			} else {
				u4(r)
			}
			i += n
			start = i
			continue
		}
		switch c {
		case '"', '\\', '/':
			out = append(out, '\\', c)
		case '\n':
			out = append(out, '\\', 'n')
		case '\r':
			out = append(out, '\\', 'r')
		case '\t':
			out = append(out, '\\', 't')
		case '\b':
			out = append(out, '\\', 'b')
		case '\f':
			out = append(out, '\\', 'f')
		default:
			out = append(out, '\\', 'u', '0', '0', lhex[c>>4], lhex[c&15])
		}
		i++
		start = i
	}
	return append(out, s[start:]...)
}

func b64Stable(enc *base64.Encoding, v []byte, k int) []byte {
	buf := make([]byte, k+len(v))
	copy(buf[k:], v)
	full := enc.EncodeToString(buf)
	js, je := (8*k+5)/6, (8*(k+len(v)))/6
	if je <= js {
		return nil
	}
	return []byte(full[js:je])
}

func urlEncode(s []byte) []byte {
	const hx = "0123456789ABCDEF"
	out := make([]byte, 0, len(s)*3)
	for _, c := range s {
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '.' || c == '_' || c == '~' {
			out = append(out, c)
		} else {
			out = append(out, '%', hx[c>>4], hx[c&15])
		}
	}
	return out
}

// Variants returns the encoded forms of v in canonical order.
func Variants(v []byte) [][]byte {
	std, url := base64.RawStdEncoding, base64.RawURLEncoding
	return [][]byte{
		v,
		AppendJSONEscaped(nil, v, false, false),
		AppendJSONEscaped(nil, v, true, false),
		AppendJSONEscaped(nil, v, false, true),
		AppendJSONEscaped(nil, v, true, true),
		b64Stable(std, v, 0), b64Stable(std, v, 1), b64Stable(std, v, 2),
		b64Stable(url, v, 0), b64Stable(url, v, 1), b64Stable(url, v, 2),
		[]byte(hex.EncodeToString(v)),
		urlEncode(v),
	}
}

// Patterns returns deduplicated patterns (first occurrence wins) and their secret index.
func Patterns(secrets [][]byte) ([][]byte, []int32) {
	seen := make(map[string]struct{}, len(secrets)*6)
	var pats [][]byte
	var owner []int32
	for i, s := range secrets {
		for _, v := range Variants(s) {
			if len(v) < MinVariantLen {
				continue
			}
			if _, ok := seen[string(v)]; ok {
				continue
			}
			seen[string(v)] = struct{}{}
			pats = append(pats, v)
			owner = append(owner, int32(i))
		}
	}
	return pats, owner
}
