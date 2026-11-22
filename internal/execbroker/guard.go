// SPDX-License-Identifier: AGPL-3.0-only

package execbroker

import (
	"bytes"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"slices"

	"github.com/heliopsy/scrim/internal/secret"
)

// guardMinLen is the shortest value the guard looks for; shorter ones would
// match ordinary output.
const guardMinLen = 6

// leaks is the broker's own check over redacted output, independent of the
// data plane's redactor (design D4): it looks for each injected value
// verbatim and in the encodings a command is most likely to print it in.
// Output in which it finds one is withheld, never repaired.
func leaks(out []byte, values []secret.Value) bool {
	found := false
	for _, v := range values {
		_ = v.Expose(func(b []byte) error {
			if len(b) < guardMinLen {
				return nil
			}
			for _, form := range forms(b) {
				if !found && bytes.Contains(out, form) {
					found = true
				}
				secret.WipeBytes(form)
			}
			return nil
		})
	}
	return found
}

func forms(v []byte) [][]byte {
	rev := slices.Clone(v)
	slices.Reverse(rev)
	lower := make([]byte, hex.EncodedLen(len(v)))
	hex.Encode(lower, v)
	out := [][]byte{slices.Clone(v), rev, lower, bytes.ToUpper(lower), percent(v)}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.URLEncoding} {
		// The value at each of the three alignments inside a longer base64
		// stream: the groups that hold value bytes only encode the same
		// whatever surrounds them.
		for pad := range 3 {
			buf := append(make([]byte, pad), v...)
			e := make([]byte, enc.EncodedLen(len(buf)))
			enc.Encode(e, buf)
			secret.WipeBytes(buf)
			lo, hi := (pad+2)/3*4, (pad+len(v))/3*4
			if hi-lo >= guardMinLen {
				out = append(out, slices.Clone(e[lo:hi]))
			}
			secret.WipeBytes(e)
		}
	}
	b32 := make([]byte, base32.StdEncoding.EncodedLen(len(v)))
	base32.StdEncoding.Encode(b32, v)
	return append(out, b32)
}

// percent is v percent-encoded wherever it is not an unreserved character.
func percent(v []byte) []byte {
	const digits = "0123456789ABCDEF"
	out := make([]byte, 0, len(v)*3)
	for _, c := range v {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.' || c == '~' {
			out = append(out, c)
			continue
		}
		out = append(out, '%', digits[c>>4], digits[c&15])
	}
	return out
}
