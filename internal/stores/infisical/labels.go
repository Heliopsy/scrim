// SPDX-License-Identifier: AGPL-3.0-only

package infisical

import (
	"slices"
	"strconv"
	"strings"
	"time"
)

// Store-native policy labels (docs/stores/infisical.md, "Policy labels").
//
// Infisical's own attributes of a secret go into stores.Metadata.Labels
// under "infisical.<attr>", so policy rules can match on project,
// environment, folder, tags and the rest. User-editable secret metadata goes
// under "infisical.meta.<key>". Every user-supplied key in the "infisical."
// namespace is dropped and native keys are set before user metadata, which
// never overwrites a key, so metadata cannot forge a native attribute.
// Labels hold metadata only, never a value.
//
// The helpers below have the semantics of stores.SetNative, stores.UserMeta
// and stores.LabelKey (feat/store-labels-core), with this adapter's kind and
// multi-valued attributes fixed; they can be replaced by those once that
// lands.

// labelPrefix is the namespace of every label this adapter derives.
const labelPrefix = Kind + "."

// metaPrefix is the namespace of user-editable secret metadata.
const metaPrefix = labelPrefix + "meta."

// multiAttrs are the multi-valued attributes: they get presence keys even
// for a single value.
var multiAttrs = []string{"tag", "encrypted-meta"}

// setNative sets the native attribute attr, replacing whatever is there.
// One value of a single-valued attribute is infisical.<attr> = value.
// Several values, or any values of a multi-valued attribute, are the values
// joined by "," (duplicates dropped) plus infisical.<attr>.<value> = "true"
// per value, the value verbatim. Empty values are skipped; with none left
// nothing is set.
func setNative(labels map[string]string, attr string, values ...string) {
	key := labelPrefix + labelKey(attr)
	vals := make([]string, 0, len(values))
	for _, v := range values {
		if v != "" && !slices.Contains(vals, v) {
			vals = append(vals, v)
		}
	}
	if len(vals) == 0 {
		return
	}
	labels[key] = strings.Join(vals, ",")
	if len(vals) > 1 || slices.Contains(multiAttrs, attr) {
		for _, v := range vals {
			labels[key+"."+v] = "true"
		}
	}
}

// setBool sets a boolean native attribute to "true" or "false".
func setBool(labels map[string]string, attr string, v bool) {
	setNative(labels, attr, strconv.FormatBool(v))
}

// setTime sets a timestamp attribute in RFC 3339, UTC, when it is known.
func setTime(labels map[string]string, attr string, t time.Time) {
	if !t.IsZero() {
		setNative(labels, attr, t.UTC().Format(time.RFC3339Nano))
	}
}

// userMeta records one user-editable metadata entry as
// infisical.meta.<labelKey(key)>, the value as Infisical returns it. It
// never overwrites a key already set, so of two keys that fold to the same
// name the first wins.
func userMeta(labels map[string]string, key, value string) {
	k := labelKey(key)
	if k == "" {
		return
	}
	if _, taken := labels[metaPrefix+k]; !taken {
		labels[metaPrefix+k] = value
	}
}

// isReserved reports whether a user-supplied label key falls in the
// adapter's namespace and must not be taken as given. The check ignores case
// and surrounding space, so "Infisical.Environment" cannot pose as a native
// key to a reader that folds case.
func isReserved(key string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(key)), labelPrefix)
}

// labelKey folds s into a label key: lower-case ASCII letters, digits, '-'
// and '_' in dot-separated segments. Other characters (space, '/', ',',
// non-ASCII) become '_', empty segments are dropped.
func labelKey(s string) string {
	var b strings.Builder
	for seg := range strings.SplitSeq(strings.ToLower(s), ".") {
		if seg == "" {
			continue
		}
		if b.Len() > 0 {
			b.WriteByte('.')
		}
		for _, c := range seg {
			switch {
			case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_':
				b.WriteRune(c)
			default:
				b.WriteByte('_')
			}
		}
	}
	return b.String()
}

// folderKeys sets infisical.folder to the folder path as Infisical spells it
// ("/" or "/db/Primary") and one presence key per folder on the way down,
// with the folder names verbatim joined by dots: infisical.folder.db and
// infisical.folder.db.Primary. Infisical folder names are ASCII letters,
// digits, '-' and '_', so the dotted form is unambiguous.
func folderKeys(labels map[string]string, folder string) {
	folder = "/" + strings.Trim(folder, "/")
	setNative(labels, "folder", folder)
	acc := ""
	for _, seg := range strings.Split(strings.Trim(folder, "/"), "/") {
		if seg == "" {
			continue
		}
		if acc != "" {
			acc += "."
		}
		acc += seg
		labels[labelPrefix+"folder."+acc] = "true"
	}
}
