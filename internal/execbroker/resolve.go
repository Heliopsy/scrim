// SPDX-License-Identifier: AGPL-3.0-only

package execbroker

import (
	"context"
	"slices"
	"strings"

	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores"
)

// Match is a credential one of whose placeholders occurs in a request. Value
// is a copy the broker owns and wipes.
type Match struct {
	// Form is the placeholder text that occurred.
	Form  string
	Ref   stores.Ref
	Name  string
	Class string
	Value secret.Value
}

// Values finds the credentials a request names. The control plane implements
// it over its redaction set: every current value with a store reference, under
// every placeholder that names it (the bracket placeholder under each key
// version, a format-preserving one where the catalog asks for it, a declared
// placeholder such as SCRIM_GITHUB_TOKEN, and {{scrim:<ref>}}).
type Values interface {
	// Find calls occurs with each placeholder form and returns a Match for
	// every form it reports true for.
	Find(ctx context.Context, occurs func(form string) bool) ([]Match, error)
}

// Markers that mean "this is meant to be a placeholder". One left after
// substitution names no credential with a value, and the request is refused
// rather than run with the placeholder as text.
var markers = []string{"⟦scrim:", "{{scrim:"}

// span is one placeholder occurrence in a text.
type span struct {
	start, end int
	match      int
}

// substitute replaces every placeholder in text with its value. It returns
// the new bytes (which the caller wipes), the indexes of the matches it used
// and whether the text outside them still holds a placeholder marker. A form
// is only taken at word boundaries, so SCRIM_KEY does not match inside
// SCRIM_KEY_2.
func substitute(text string, matches []Match) ([]byte, []int, bool) {
	var spans []span
	for i, m := range matches {
		for off := 0; off < len(text); {
			j := strings.Index(text[off:], m.Form)
			if j < 0 {
				break
			}
			s, e := off+j, off+j+len(m.Form)
			if boundary(text, s, e) {
				spans = append(spans, span{s, e, i})
			}
			off = s + 1
		}
	}
	if len(spans) == 0 {
		return []byte(text), nil, hasMarker(text)
	}
	// Leftmost first, longest first at one position; overlapping spans are
	// dropped.
	slices.SortFunc(spans, func(a, b span) int {
		if a.start != b.start {
			return a.start - b.start
		}
		return b.end - a.end
	})
	out := make([]byte, 0, len(text)+64)
	var used []int
	pos, leftover := 0, false
	for _, sp := range spans {
		if sp.start < pos {
			continue
		}
		leftover = leftover || hasMarker(text[pos:sp.start])
		out = appendWiping(out, []byte(text[pos:sp.start]))
		_ = matches[sp.match].Value.Expose(func(v []byte) error {
			out = appendWiping(out, v)
			return nil
		})
		if !slices.Contains(used, sp.match) {
			used = append(used, sp.match)
		}
		pos = sp.end
	}
	leftover = leftover || hasMarker(text[pos:])
	out = appendWiping(out, []byte(text[pos:]))
	return out, used, leftover
}

// appendWiping appends v to out; when out has to grow, the old backing
// array is wiped so no stray copy of a value stays behind.
func appendWiping(out, v []byte) []byte {
	if len(out)+len(v) <= cap(out) {
		return append(out, v...)
	}
	grown := make([]byte, len(out), 2*(len(out)+len(v)))
	copy(grown, out)
	secret.WipeBytes(out[:cap(out)])
	return append(grown, v...)
}

func boundary(text string, s, e int) bool {
	word := func(c byte) bool {
		return c == '_' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
	}
	if s > 0 && word(text[s-1]) && word(text[s]) {
		return false
	}
	if e < len(text) && word(text[e]) && word(text[e-1]) {
		return false
	}
	return true
}

// hasMarker reports whether text holds something meant as a placeholder.
func hasMarker(text string) bool {
	return slices.ContainsFunc(markers, func(m string) bool { return strings.Contains(text, m) })
}
