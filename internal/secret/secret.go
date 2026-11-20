// SPDX-License-Identifier: AGPL-3.0-only

// Package secret holds secret values in a type that cannot be printed,
// logged or serialised by accident.
//
// Every formatting and encoding path (fmt verbs, slog, encoding/json,
// encoding/text, gob) renders a [Value] as [Marker]. The only way to read the
// bytes is [Value.Expose], which is easy to grep for in review. A Value is
// wiped with [Value.Wipe] when it is no longer needed.
//
// A Value is a small handle: copies share the same backing buffer, so wiping
// any copy wipes them all. Keep one owner and pass the Value, not the bytes.
package secret

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"log/slog"
	"sync"
)

// Marker is what every printing or encoding path shows instead of a value.
const Marker = "[scrim:redacted]"

// ErrWiped is returned by accessors once a value has been wiped.
var ErrWiped = errors.New("secret: value has been wiped")

// Value is a secret byte string. The zero Value is empty and valid.
type Value struct {
	b *buf
}

type buf struct {
	mu    sync.RWMutex
	data  []byte
	wiped bool
}

// New copies b into a new Value. The caller should wipe its own copy of b
// (for example with [WipeBytes]) once New returns.
func New(b []byte) Value {
	data := make([]byte, len(b))
	copy(data, b)
	return Value{b: &buf{data: data}}
}

// Adopt takes ownership of b without copying. The caller must not use b
// afterwards; it is wiped together with the Value.
func Adopt(b []byte) Value {
	return Value{b: &buf{data: b}}
}

// FromString copies s into a new Value. Go strings are immutable and cannot
// be wiped, so prefer [New] or [Adopt] for values that arrive as bytes.
func FromString(s string) Value {
	return New([]byte(s))
}

// Expose calls fn with the secret bytes. fn must not retain, log or return
// the slice; it is only valid during the call. Expose returns [ErrWiped] if
// the value was wiped, and otherwise whatever fn returns.
func (v Value) Expose(fn func([]byte) error) error {
	if v.b == nil {
		return fn(nil)
	}
	v.b.mu.RLock()
	defer v.b.mu.RUnlock()
	if v.b.wiped {
		return ErrWiped
	}
	return fn(v.b.data)
}

// Len reports the length of the value in bytes. Length is metadata, not the
// value, and is safe to log.
func (v Value) Len() int {
	if v.b == nil {
		return 0
	}
	v.b.mu.RLock()
	defer v.b.mu.RUnlock()
	return len(v.b.data)
}

// IsZero reports whether the value is empty or wiped.
func (v Value) IsZero() bool { return v.Len() == 0 }

// Wiped reports whether [Value.Wipe] has been called on this value or a copy.
func (v Value) Wiped() bool {
	if v.b == nil {
		return false
	}
	v.b.mu.RLock()
	defer v.b.mu.RUnlock()
	return v.b.wiped
}

// Equal compares two values in constant time with respect to their content.
func (v Value) Equal(o Value) bool {
	if v.b != nil && v.b == o.b {
		// Same buffer: avoid taking its read lock twice.
		return !v.Wiped()
	}
	eq := false
	_ = v.Expose(func(a []byte) error {
		return o.Expose(func(b []byte) error {
			eq = subtle.ConstantTimeCompare(a, b) == 1
			return nil
		})
	})
	return eq
}

// Wipe overwrites the backing bytes with zeros and marks the value wiped.
// It is safe to call more than once and on the zero Value.
func (v Value) Wipe() {
	if v.b == nil {
		return
	}
	v.b.mu.Lock()
	defer v.b.mu.Unlock()
	WipeBytes(v.b.data)
	v.b.data = nil
	v.b.wiped = true
}

// WipeBytes overwrites b with zeros.
func WipeBytes(b []byte) {
	clear(b)
}

// String implements fmt.Stringer.
func (Value) String() string { return Marker }

// GoString implements fmt.GoStringer, used by %#v.
func (Value) GoString() string { return "secret.Value(" + Marker + ")" }

// Format implements fmt.Formatter so every verb, including %x, %q and %s,
// prints the marker.
func (Value) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte(Marker)) }

// LogValue implements slog.LogValuer.
func (Value) LogValue() slog.Value { return slog.StringValue(Marker) }

// MarshalJSON implements json.Marshaler.
func (Value) MarshalJSON() ([]byte, error) { return []byte(`"` + Marker + `"`), nil }

// MarshalText implements encoding.TextMarshaler, used by YAML and text
// encoders as well as map keys in JSON.
func (Value) MarshalText() ([]byte, error) { return []byte(Marker), nil }

// MarshalBinary implements encoding.BinaryMarshaler, used by gob.
func (Value) MarshalBinary() ([]byte, error) { return []byte(Marker), nil }

// UnmarshalJSON refuses to decode: values never come from serialised input
// through this type, so a decode attempt is a programming error.
func (*Value) UnmarshalJSON([]byte) error {
	return errors.New("secret: Value cannot be decoded from JSON")
}

// UnmarshalText refuses to decode, as [Value.UnmarshalJSON].
func (*Value) UnmarshalText([]byte) error {
	return errors.New("secret: Value cannot be decoded from text")
}
