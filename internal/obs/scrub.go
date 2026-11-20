// SPDX-License-Identifier: AGPL-3.0-only

package obs

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"strings"

	"github.com/heliopsy/scrim/internal/secret"
)

// MinScrubLength is the shortest encoded form [ValueScrubber] replaces.
// Shorter fragments would match ordinary text; the redaction engine applies
// its own minimum-length rule to the values it loads.
const MinScrubLength = 4

// ValueScrubber is a [Scrubber] over a fixed set of secret values. It
// matches each in raw, JSON-escaped, URL-escaped, hex and base64 (standard and URL alphabets, padded and raw, at
// each of the three byte alignments) forms. Every form is held as a
// [secret.Value] and exposed only while scrubbing.
type ValueScrubber struct {
	forms []secret.Value
}

// NewValueScrubber builds a scrubber over vals. The caller keeps ownership of
// vals; the scrubber holds its own copies of every form and wipes them in
// [ValueScrubber.Wipe].
func NewValueScrubber(vals ...secret.Value) *ValueScrubber {
	seen := map[string]bool{}
	vs := &ValueScrubber{}
	for _, v := range vals {
		_ = v.Expose(func(raw []byte) error {
			for _, f := range encodedForms(raw) {
				if len(f) < MinScrubLength || seen[string(f)] {
					continue
				}
				seen[string(f)] = true
				vs.forms = append(vs.forms, secret.Adopt(f))
			}
			return nil
		})
	}
	// Longest first, so a form that contains another is replaced whole.
	for i := 1; i < len(vs.forms); i++ {
		for j := i; j > 0 && vs.forms[j].Len() > vs.forms[j-1].Len(); j-- {
			vs.forms[j], vs.forms[j-1] = vs.forms[j-1], vs.forms[j]
		}
	}
	return vs
}

// Scrub implements [Scrubber].
// It compares bytes, so no form is ever copied into an unwipeable string.
func (vs *ValueScrubber) Scrub(s string) string {
	b := []byte(s)
	changed := false
	marker := []byte(secret.Marker)
	for _, f := range vs.forms {
		_ = f.Expose(func(form []byte) error {
			if bytes.Contains(b, form) {
				b = bytes.ReplaceAll(b, form, marker)
				changed = true
			}
			return nil
		})
	}
	if !changed {
		return s
	}
	return string(b)
}

// Wipe wipes every held form.
func (vs *ValueScrubber) Wipe() {
	for _, f := range vs.forms {
		f.Wipe()
	}
	vs.forms = nil
}

// encodedForms returns raw and every encoding of it the scrubber matches.
func encodedForms(raw []byte) [][]byte {
	out := [][]byte{append([]byte(nil), raw...)}
	// JSON string escaping, with and without HTML escaping of <, > and &.
	if j, err := json.Marshal(string(raw)); err == nil && len(j) >= 2 {
		out = append(out, j[1:len(j)-1])
	}
	var jb bytes.Buffer
	je := json.NewEncoder(&jb)
	je.SetEscapeHTML(false)
	if err := je.Encode(string(raw)); err == nil {
		if j := bytes.TrimSpace(jb.Bytes()); len(j) >= 2 {
			out = append(out, j[1:len(j)-1])
		}
	}
	out = append(out,
		[]byte(url.QueryEscape(string(raw))),
		[]byte(url.PathEscape(string(raw))),
		[]byte(hex.EncodeToString(raw)),
		[]byte(strings.ToUpper(hex.EncodeToString(raw))),
	)
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.URLEncoding} {
		out = append(out, []byte(enc.EncodeToString(raw)))
		for k := 0; k < 3; k++ {
			out = append(out, base64Aligned(enc, raw, k))
		}
	}
	return out
}

// base64Aligned returns the base64 characters determined only by raw when
// raw starts k bytes into a larger encoded buffer: the encoding of a value
// embedded in a longer blob, whatever surrounds it.
func base64Aligned(enc *base64.Encoding, raw []byte, k int) []byte {
	buf := make([]byte, k+len(raw))
	copy(buf[k:], raw)
	s := enc.WithPadding(base64.NoPadding).EncodeToString(buf)
	start := (k*8 + 5) / 6
	end := (k + len(raw)) * 8 / 6
	if end <= start || end > len(s) {
		return nil
	}
	return []byte(s[start:end])
}
