// Reference ("oracle") implementation of the shared algorithm spec.
// The Go and Rust implementations under test are written independently;
// this file only produces fixtures and the expected variant list.
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"unicode/utf8"
)

const minVariantLen = 8

func placeholder(key []byte, v string) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(v))
	return "⟦kss:" + hex.EncodeToString(m.Sum(nil))[:12] + "⟧"
}

// jsonEscape: canonical escaping. slash: escape '/' as "\/". uni: non-ASCII as \uXXXX.
func jsonEscape(s string, slash, uni bool) string {
	const hx = "0123456789abcdef"
	out := make([]byte, 0, len(s)+8)
	for i := 0; i < len(s); {
		c := s[i]
		if c >= 0x80 {
			r, n := utf8.DecodeRuneInString(s[i:])
			if !uni {
				out = append(out, s[i:i+n]...)
			} else {
				u4 := func(x rune) {
					out = append(out, '\\', 'u', hx[(x>>12)&15], hx[(x>>8)&15], hx[(x>>4)&15], hx[x&15])
				}
				if r >= 0x10000 {
					r -= 0x10000
					u4(0xD800 + (r >> 10))
					u4(0xDC00 + (r & 0x3FF))
				} else {
					u4(r)
				}
			}
			i += n
			continue
		}
		switch c {
		case '"':
			out = append(out, '\\', '"')
		case '\\':
			out = append(out, '\\', '\\')
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
		case '/':
			if slash {
				out = append(out, '\\', '/')
			} else {
				out = append(out, '/')
			}
		default:
			if c < 0x20 {
				out = append(out, '\\', 'u', '0', '0', hx[c>>4], hx[c&15])
			} else {
				out = append(out, c)
			}
		}
		i++
	}
	return string(out)
}

// b64Stable returns the base64 characters fully determined by v when v is
// preceded by k bytes (k = 0,1,2) of arbitrary data and followed by arbitrary data.
func b64Stable(enc *base64.Encoding, v string, k int) string {
	buf := make([]byte, k+len(v))
	copy(buf[k:], v)
	full := enc.EncodeToString(buf)
	n := len(v)
	js := (8*k + 5) / 6
	je := (8 * (k + n)) / 6
	if je <= js {
		return ""
	}
	return full[js:je]
}

func urlEncode(s string) string {
	const hx = "0123456789ABCDEF"
	out := make([]byte, 0, len(s)*3)
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '.' || c == '_' || c == '~' {
			out = append(out, c)
		} else {
			out = append(out, '%', hx[c>>4], hx[c&15])
		}
	}
	return string(out)
}

// variants in canonical order: raw, J(-,-), J(/,-), J(-,u), J(/,u), b64std k0..2, b64url k0..2, hex, url.
func variants(v string) []string {
	std := base64.RawStdEncoding
	url := base64.RawURLEncoding
	return []string{
		v,
		jsonEscape(v, false, false),
		jsonEscape(v, true, false),
		jsonEscape(v, false, true),
		jsonEscape(v, true, true),
		b64Stable(std, v, 0), b64Stable(std, v, 1), b64Stable(std, v, 2),
		b64Stable(url, v, 0), b64Stable(url, v, 1), b64Stable(url, v, 2),
		hex.EncodeToString([]byte(v)),
		urlEncode(v),
	}
}

type pattern struct {
	bytes  string
	secret int
}

// patternList: dedupe globally, first occurrence wins, drop < minVariantLen.
func patternList(secrets []string) []pattern {
	seen := map[string]bool{}
	var out []pattern
	for i, s := range secrets {
		for _, v := range variants(s) {
			if len(v) < minVariantLen || seen[v] {
				continue
			}
			seen[v] = true
			out = append(out, pattern{v, i})
		}
	}
	return out
}
