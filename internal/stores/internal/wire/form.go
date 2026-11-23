// SPDX-License-Identifier: AGPL-3.0-only

package wire

import "github.com/heliopsy/scrim/internal/secret"

// AppendForm appends key=value to an application/x-www-form-urlencoded
// body, with & before it unless dst is empty. key and value are
// percent-encoded byte by byte, so a secret never passes through a string.
func AppendForm(dst []byte, key string, value []byte) []byte {
	if len(dst) > 0 {
		dst = append(dst, '&')
	}
	dst = appendFormEscaped(dst, []byte(key))
	dst = append(dst, '=')
	return appendFormEscaped(dst, value)
}

// AppendFormValue is [AppendForm] for a secret value.
func AppendFormValue(dst []byte, key string, v secret.Value) []byte {
	_ = v.Expose(func(b []byte) error { dst = AppendForm(dst, key, b); return nil })
	return dst
}

func appendFormEscaped(dst, b []byte) []byte {
	const hexUpper = "0123456789ABCDEF"
	for _, c := range b {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '.', c == '_', c == '~':
			dst = append(dst, c)
		case c == ' ':
			dst = append(dst, '+')
		default:
			dst = append(dst, '%', hexUpper[c>>4], hexUpper[c&0xf])
		}
	}
	return dst
}
