// SPDX-License-Identifier: AGPL-3.0-only

package aws

import (
	"maps"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/heliopsy/scrim/internal/stores"
)

// Store-native policy labels (docs/stores/aws.md, "Policy labels").
//
// AWS's own attributes of a secret or parameter go into Metadata.Labels
// under "awssm.<attr>" or "ssm.<attr>". Resource tags are user-editable, so
// they go under "<kind>.meta.<key>" through stores.UserMeta, after the
// native keys, and never replace one. Tags whose key starts with "scrim."
// are scrim's own catalog bindings (scrim.hosts, scrim.placeholder) and are
// also reported under their own key, as every store reports them; no other
// tag gets a key outside the meta namespace, so a tag cannot shadow a
// derived label. Labels hold metadata only, never a value.

// setTime sets a timestamp attribute in RFC 3339, UTC, when it is known.
func setTime(labels map[string]string, kind, attr string, t time.Time) {
	if !t.IsZero() {
		stores.SetNative(labels, kind, attr, t.UTC().Format(time.RFC3339Nano))
	}
}

func setBool(labels map[string]string, kind, attr string, v bool) {
	stores.SetNative(labels, kind, attr, strconv.FormatBool(v))
}

// tagLabels adds the scrim.* tags under their own key (decoded, see
// encodeTagValue) and every tag as user metadata. Call it after the native
// attributes are set.
func tagLabels(labels map[string]string, kind string, tags []tag) {
	for _, t := range tags {
		if strings.HasPrefix(t.Key, stores.ScrimLabelPrefix) {
			if _, taken := labels[t.Key]; !taken {
				labels[t.Key] = decodeTagValue(t.Value)
			}
		}
	}
	for _, t := range tags {
		stores.UserMeta(labels, kind, t.Key, t.Value)
	}
}

// tagChar reports whether AWS accepts r in a tag key or value: letters,
// numbers, separators (spaces) and _ . : / = + - @ (\p{L}\p{Z}\p{N}_.:/=+\-@).
func tagChar(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsNumber(r) || unicode.In(r, unicode.Z) || strings.ContainsRune("_.:/=+-@", r)
}

// encodeTagValue fits a label value into AWS's tag character set: '=' and
// every character AWS refuses (the ',' of a scrim.hosts list, for one)
// become =XX per UTF-8 byte, in upper-case hex. decodeTagValue reverses it
// for scrim.* tags.
func encodeTagValue(v string) string {
	if !strings.ContainsFunc(v, func(r rune) bool { return r == '=' || !tagChar(r) }) {
		return v
	}
	var b strings.Builder
	for _, r := range v {
		if r != '=' && tagChar(r) {
			b.WriteRune(r)
			continue
		}
		for _, c := range []byte(string(r)) {
			b.WriteByte('=')
			b.WriteByte(upperHex[c>>4])
			b.WriteByte(upperHex[c&0xf])
		}
	}
	return b.String()
}

const upperHex = "0123456789ABCDEF"

// decodeTagValue undoes encodeTagValue. An '=' not followed by two hex
// digits is kept as it is, so a tag written by hand still reads sensibly.
func decodeTagValue(v string) string {
	if !strings.Contains(v, "=") {
		return v
	}
	out := make([]byte, 0, len(v))
	for i := 0; i < len(v); i++ {
		if v[i] == '=' && i+2 < len(v) {
			if n, err := strconv.ParseUint(v[i+1:i+3], 16, 8); err == nil {
				out = append(out, byte(n))
				i += 2
				continue
			}
		}
		out = append(out, v[i])
	}
	return string(out)
}

// writeTags turns WriteOptions.Labels into resource tags, sorted by key.
// Keys in the adapter's or scrim's reserved namespaces are not stored (a
// write must not plant what would read as a native label), nor are keys AWS
// reserves (aws:). It reports the first key AWS could not take.
func writeTags(kind string, labels map[string]string) ([]tag, string) {
	var out []tag
	for _, k := range slices.Sorted(maps.Keys(labels)) {
		lk := strings.ToLower(strings.TrimSpace(k))
		if strings.HasPrefix(lk, kind+".") || strings.HasPrefix(lk, stores.StoreLabelPrefix) || strings.HasPrefix(lk, "aws:") {
			continue
		}
		if k == "" || len(k) > 128 || strings.ContainsFunc(k, func(r rune) bool { return !tagChar(r) }) {
			return nil, k
		}
		v := encodeTagValue(labels[k])
		if len(v) > 256 {
			return nil, k
		}
		out = append(out, tag{Key: k, Value: v})
	}
	return out, ""
}
