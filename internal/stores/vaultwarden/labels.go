// SPDX-License-Identifier: AGPL-3.0-only

package vaultwarden

import (
	"net/url"
	"slices"
	"strconv"
	"strings"
)

// Store-native labels. The adapter describes where an item lives and what it
// is under the reserved prefix "vaultwarden.", so policy rules can match the
// real location of an item rather than the spelling of its reference. The
// shape follows the shared convention of stores.SetNative and
// stores.UserMeta (feat/store-labels-core), which this file mirrors until
// the adapter can call them:
//
//	vaultwarden.collection          = "Prod,Shared/Team A"  (names, verbatim)
//	vaultwarden.collection.Prod     = "true"                (one presence key per value)
//	vaultwarden.collection.Shared   = "true"                (and per ancestor)
//	vaultwarden.collection.Shared/Team A = "true"
//
// Presence keys carry the value verbatim, so matching is exact and
// case-sensitive. A nested folder or collection also gets a presence key for
// each ancestor, so "Agents/CI" matches a rule on "Agents". Text custom
// fields that are not scrim.* labels become vaultwarden.meta.<key>, with the
// key folded by labelKey. Native keys are computed last and replace anything
// else under the prefix, so whoever can edit an item cannot forge them.
const (
	nativePrefix = Kind + "."
	metaPrefix   = nativePrefix + "meta."
	// metaMaxLen bounds a text custom field value copied into a label.
	metaMaxLen = 256
)

// labelKey folds s into a label key exactly as stores.LabelKey does:
// lower-case ASCII letters, digits, '-' and '_' in dot-separated segments;
// every other character becomes '_' and empty segments are dropped.
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

// ancestors returns a "/"-separated name and each of its ancestors,
// verbatim, shortest first: "Agents/CI" gives "Agents" and "Agents/CI".
func ancestors(name string) []string {
	var out []string
	for i := 0; i < len(name); i++ {
		if name[i] == '/' && i > 0 {
			out = append(out, name[:i])
		}
	}
	return append(out, name)
}

// nativeLabels collects the native labels of one item.
type nativeLabels map[string]string

// set records a single-valued attribute: vaultwarden.<attr> = value.
func (n nativeLabels) set(attr, value string) {
	n[nativePrefix+attr] = value
}

// setBool records a boolean attribute as "true" or "false".
func (n nativeLabels) setBool(attr string, v bool) {
	n.set(attr, strconv.FormatBool(v))
}

// setMulti records a multi-valued attribute: the values verbatim, sorted and
// comma-joined under vaultwarden.<attr>, and vaultwarden.<attr>.<value> =
// "true" for each value (as stores.SetNative does for an attribute declared
// multi). With nested, each "/"-ancestor of a value gets a presence key as
// well. No values records nothing.
func (n nativeLabels) setMulti(attr string, nested bool, values ...string) {
	var vs []string
	for _, v := range values {
		if v != "" && !slices.Contains(vs, v) {
			vs = append(vs, v)
		}
	}
	if len(vs) == 0 {
		return
	}
	slices.Sort(vs)
	n.set(attr, strings.Join(vs, ","))
	for _, v := range vs {
		keys := []string{v}
		if nested {
			keys = ancestors(v)
		}
		for _, k := range keys {
			n[nativePrefix+attr+"."+k] = "true"
		}
	}
}

// addMeta records a text custom field as vaultwarden.meta.<key>, as
// stores.UserMeta does: the first field of a key wins, as for values. Long
// values are skipped.
func addMeta(labels map[string]string, name, value string) {
	if len(value) > metaMaxLen {
		return
	}
	key := labelKey(name)
	if key == "" {
		return
	}
	k := metaPrefix + key
	if _, dup := labels[k]; !dup {
		labels[k] = value
	}
}

// mergeNative returns user labels (scrim.* and vaultwarden.meta.*) with the
// native labels on top. Any other key under the native prefix is dropped
// first, so a user-supplied label can never stand in for a native one.
func mergeNative(user map[string]string, native nativeLabels) map[string]string {
	out := make(map[string]string, len(user)+len(native))
	for k, v := range user {
		if strings.HasPrefix(k, nativePrefix) && !strings.HasPrefix(k, metaPrefix) {
			continue
		}
		out[k] = v
	}
	for k, v := range native {
		out[k] = v
	}
	return out
}

// uriHosts returns the host names of login URIs, without ports, paths,
// queries or user info. URIs matched as regular expressions are skipped.
func uriHosts(uris []string) []string {
	var out []string
	for _, u := range uris {
		u = strings.TrimSpace(u)
		if u == "" {
			continue
		}
		if !strings.Contains(u, "://") {
			u = "https://" + u
		}
		p, err := url.Parse(u)
		if err != nil {
			continue
		}
		h := strings.ToLower(strings.TrimSuffix(p.Hostname(), "."))
		if h != "" && !slices.Contains(out, h) {
			out = append(out, h)
		}
	}
	return out
}

// Type names used in vaultwarden.type.
func typeName(t int) string {
	switch t {
	case cipherLogin:
		return "login"
	case cipherSecureNote:
		return "note"
	case cipherCard:
		return "card"
	case cipherIdentity:
		return "identity"
	case cipherSSHKey:
		return "ssh-key"
	}
	return "unknown"
}

// orgRole names the organisation user types.
func orgRole(t int) string {
	switch t {
	case 0:
		return "owner"
	case 1:
		return "admin"
	case 2:
		return "user"
	case 3:
		return "manager"
	case 4:
		return "custom"
	}
	return "unknown"
}
