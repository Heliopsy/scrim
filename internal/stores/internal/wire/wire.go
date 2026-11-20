// SPDX-License-Identifier: AGPL-3.0-only

// Package wire moves secret values between store HTTP APIs and
// [secret.Value] without passing them through Go strings.
//
// Go strings are immutable and cannot be wiped, so decoding a JSON response
// with encoding/json into a string field leaves a copy of the value on the
// heap until the garbage collector reuses that memory. The helpers here decode
// JSON string literals straight into byte slices that end up in a
// [secret.Value], and encode values into request bodies that are wiped once
// the request is sent.
package wire

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/heliopsy/scrim/internal/secret"
)

// MaxBody caps how much of a store response is read into memory.
const MaxBody = 8 << 20

// ErrBodyTooLarge is returned when a response exceeds [MaxBody].
var ErrBodyTooLarge = errors.New("store response exceeds size limit")

// ReadBody reads r up to [MaxBody]. The caller owns the returned slice and
// should wipe it with [secret.WipeBytes] once the values it holds have been
// copied out.
func ReadBody(r io.Reader) ([]byte, error) {
	var buf bytes.Buffer
	n, err := io.Copy(&buf, io.LimitReader(r, MaxBody+1))
	if err != nil {
		b := buf.Bytes()
		secret.WipeBytes(b[:cap(b)])
		return nil, err
	}
	if n > MaxBody {
		b := buf.Bytes()
		secret.WipeBytes(b[:cap(b)])
		return nil, ErrBodyTooLarge
	}
	return buf.Bytes(), nil
}

// Raw is a JSON value kept as raw bytes. Unlike [json.RawMessage] it is
// never printed: its String and Format methods show a marker, so an
// accidental log of a decoded struct holding one shows no value.
type Raw []byte

// UnmarshalJSON copies the raw JSON into r.
func (r *Raw) UnmarshalJSON(b []byte) error {
	*r = append((*r)[:0], b...)
	return nil
}

// String implements fmt.Stringer.
func (Raw) String() string { return secret.Marker }

// Format implements fmt.Formatter.
func (Raw) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte(secret.Marker)) }

// Wipe zeroes r.
func (r Raw) Wipe() { secret.WipeBytes(r) }

// Value converts a raw JSON value into a [secret.Value]. A JSON string is
// unquoted; any other JSON value (number, boolean, object, array) keeps its
// JSON text. JSON null yields an error, because a null is not a value that
// can be redacted or injected.
func (r Raw) Value() (secret.Value, error) {
	b := bytes.TrimSpace(r)
	if len(b) == 0 {
		return secret.Value{}, errors.New("empty JSON value")
	}
	switch b[0] {
	case '"':
		out, err := Unquote(b)
		if err != nil {
			return secret.Value{}, err
		}
		return secret.Adopt(out), nil
	case 'n':
		return secret.Value{}, errors.New("JSON null is not a secret value")
	default:
		if !json.Valid(b) {
			return secret.Value{}, errors.New("invalid JSON value")
		}
		return secret.New(b), nil
	}
}

// Unquote decodes the JSON string literal q (including its quotes) into a
// new byte slice. It never allocates a Go string.
func Unquote(q []byte) ([]byte, error) {
	if len(q) < 2 || q[0] != '"' || q[len(q)-1] != '"' {
		return nil, errors.New("not a JSON string")
	}
	q = q[1 : len(q)-1]
	out := make([]byte, 0, len(q))
	for i := 0; i < len(q); {
		c := q[i]
		switch {
		case c == '\\':
			if i+1 >= len(q) {
				secret.WipeBytes(out)
				return nil, errors.New("truncated escape in JSON string")
			}
			e := q[i+1]
			i += 2
			switch e {
			case '"', '\\', '/':
				out = append(out, e)
			case 'b':
				out = append(out, '\b')
			case 'f':
				out = append(out, '\f')
			case 'n':
				out = append(out, '\n')
			case 'r':
				out = append(out, '\r')
			case 't':
				out = append(out, '\t')
			case 'u':
				r, ok := hex4(q, i)
				if !ok {
					secret.WipeBytes(out)
					return nil, errors.New("invalid \\u escape in JSON string")
				}
				i += 4
				if utf16.IsSurrogate(r) {
					r2, ok2 := rune(0), false
					if i+6 <= len(q) && q[i] == '\\' && q[i+1] == 'u' {
						r2, ok2 = hex4(q, i+2)
					}
					if dec := utf16.DecodeRune(r, r2); ok2 && dec != utf8.RuneError {
						r = dec
						i += 6
					} else {
						r = utf8.RuneError
					}
				}
				out = utf8.AppendRune(out, r)
			default:
				secret.WipeBytes(out)
				return nil, errors.New("invalid escape in JSON string")
			}
		case c < 0x20:
			secret.WipeBytes(out)
			return nil, errors.New("control character in JSON string")
		default:
			out = append(out, c)
			i++
		}
	}
	return out, nil
}

func hex4(q []byte, i int) (rune, bool) {
	if i+4 > len(q) {
		return 0, false
	}
	var r rune
	for _, c := range q[i : i+4] {
		r <<= 4
		switch {
		case c >= '0' && c <= '9':
			r |= rune(c - '0')
		case c >= 'a' && c <= 'f':
			r |= rune(c - 'a' + 10)
		case c >= 'A' && c <= 'F':
			r |= rune(c - 'A' + 10)
		default:
			return 0, false
		}
	}
	return r, true
}

const hexDigits = "0123456789abcdef"

// AppendQuoted appends b to dst as a JSON string literal, quotes included.
// Invalid UTF-8 is rejected rather than replaced, so a value is never
// silently changed on its way into a store.
func AppendQuoted(dst, b []byte) ([]byte, error) {
	if !utf8.Valid(b) {
		return dst, errors.New("value is not valid UTF-8")
	}
	dst = append(dst, '"')
	for _, c := range b {
		switch {
		case c == '"' || c == '\\':
			dst = append(dst, '\\', c)
		case c == '\n':
			dst = append(dst, '\\', 'n')
		case c == '\r':
			dst = append(dst, '\\', 'r')
		case c == '\t':
			dst = append(dst, '\\', 't')
		case c < 0x20:
			dst = append(dst, '\\', 'u', '0', '0', hexDigits[c>>4], hexDigits[c&0xf])
		default:
			dst = append(dst, c)
		}
	}
	return append(dst, '"'), nil
}

// AppendValue appends v as a JSON string literal.
func AppendValue(dst []byte, v secret.Value) ([]byte, error) {
	err := v.Expose(func(b []byte) error {
		var err error
		dst, err = AppendQuoted(dst, b)
		return err
	})
	return dst, err
}

// AppendJSON appends the JSON encoding of a non-secret value.
func AppendJSON(dst []byte, v any) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return dst, err
	}
	return append(dst, b...), nil
}

// Body is a request body holding secret material. It is wiped by Wipe, which
// the caller defers right after building it.
type Body struct {
	b []byte
}

// NewBody wraps b. Ownership of b passes to the Body.
func NewBody(b []byte) *Body { return &Body{b: b} }

// Reader returns a fresh reader over the body, for one request attempt.
func (b *Body) Reader() io.Reader { return bytes.NewReader(b.b) }

// Len reports the body length.
func (b *Body) Len() int { return len(b.b) }

// Wipe zeroes the body.
func (b *Body) Wipe() {
	if b != nil {
		secret.WipeBytes(b.b[:cap(b.b)])
	}
}

// maxDetail caps how much of a store's own error message is kept.
const maxDetail = 200

// SafeDetail returns msg, a store's own error message, fit to put in
// stores.Error.Detail: control characters removed, length capped, and
// replaced entirely by "(store message withheld)" if it contains any of the
// values involved in the request, since some stores echo request data back.
func SafeDetail(msg string, involved ...secret.Value) string {
	msg = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, msg)
	msg = strings.TrimSpace(msg)
	for _, v := range involved {
		leak := false
		_ = v.Expose(func(b []byte) error {
			leak = len(b) > 0 && strings.Contains(msg, string(b))
			return nil
		})
		if leak {
			return "(store message withheld)"
		}
	}
	if len(msg) > maxDetail {
		cut := maxDetail
		for cut > 0 && !utf8.RuneStart(msg[cut]) {
			cut--
		}
		msg = msg[:cut] + "..."
	}
	return msg
}
