// SPDX-License-Identifier: AGPL-3.0-only

package sops

import (
	"errors"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// defaultUnencryptedSuffix is what sops applies when a file names no
// encryption rule.
const defaultUnencryptedSuffix = "_unencrypted"

// ageKey is one age recipient of a file's data key.
type ageKey struct {
	recipient string
	enc       string // armored age file holding the 32-byte data key
}

// metadata is the part of a file's `sops` metadata this source uses. All of
// it is plaintext in the file: none of it is a secret value.
type metadata struct {
	age          []ageKey
	pgp          []string // fingerprints
	keyTypes     []string // label spelling: age, pgp, kms, gcp-kms, ...
	groups       int
	shamir       int
	lastModified time.Time
	lastModRaw   string
	mac          string
	version      string
	macOnly      bool

	unencSuffix, encSuffix, unencRegex, encRegex string
	commentRules                                 bool

	unencRe, encRe *regexp.Regexp
}

// keySources are the master key lists of a key group, with their label
// spelling.
var keySources = []struct{ key, label string }{
	{"age", "age"}, {"pgp", "pgp"}, {"kms", "kms"}, {"gcp_kms", "gcp-kms"},
	{"azure_kv", "azure-kv"}, {"hc_vault", "hc-vault"}, {"hckms", "hckms"},
}

func str(m *node, key string) string {
	s, _ := m.get(key).scalar()
	return s
}

// boolOpt reads a boolean option written as YAML/JSON boolean or, in the
// flattened formats, as a string.
func boolOpt(m *node, key string) bool {
	n := m.get(key)
	s, ok := n.scalar()
	if !ok {
		return false
	}
	if !n.str {
		return s == "True"
	}
	b, _ := strconv.ParseBool(s)
	return b
}

func parseMetadata(m *node) (metadata, error) {
	md := metadata{
		lastModRaw:  str(m, "lastmodified"),
		mac:         str(m, "mac"),
		version:     str(m, "version"),
		macOnly:     boolOpt(m, "mac_only_encrypted"),
		unencSuffix: str(m, "unencrypted_suffix"),
		encSuffix:   str(m, "encrypted_suffix"),
		unencRegex:  str(m, "unencrypted_regex"),
		encRegex:    str(m, "encrypted_regex"),
	}
	if s, ok := m.get("shamir_threshold").scalar(); ok {
		md.shamir, _ = strconv.Atoi(s)
	}
	t, err := time.Parse(time.RFC3339, md.lastModRaw)
	if err != nil {
		return metadata{}, errors.New("sops metadata has no valid lastmodified")
	}
	md.lastModified = t

	groups := []*node{m}
	if kg := m.get("key_groups"); kg != nil && kg.kind == kindList && len(kg.items) > 0 {
		groups = kg.items
	}
	md.groups = len(groups)
	for _, g := range groups {
		for _, src := range keySources {
			l := g.get(src.key)
			if l == nil || l.kind != kindList || len(l.items) == 0 {
				continue
			}
			md.keyTypes = appendUnique(md.keyTypes, src.label)
			for _, it := range l.items {
				switch src.key {
				case "age":
					md.age = append(md.age, ageKey{recipient: str(it, "recipient"), enc: str(it, "enc")})
				case "pgp":
					if fp := str(it, "fp"); fp != "" {
						md.pgp = append(md.pgp, fp)
					}
				}
			}
		}
	}

	rules := 0
	for _, r := range []string{md.unencSuffix, md.encSuffix, md.unencRegex, md.encRegex,
		str(m, "unencrypted_comment_regex"), str(m, "encrypted_comment_regex")} {
		if r != "" {
			rules++
		}
	}
	if rules > 1 {
		return metadata{}, errors.New("sops metadata names more than one encryption rule")
	}
	md.commentRules = str(m, "unencrypted_comment_regex") != "" || str(m, "encrypted_comment_regex") != ""
	if rules == 0 {
		md.unencSuffix = defaultUnencryptedSuffix
	}
	// sops ignores a regular expression that does not compile (it never
	// matches); so does this.
	if md.unencRegex != "" {
		md.unencRe, _ = regexp.Compile(md.unencRegex)
	}
	if md.encRegex != "" {
		md.encRe, _ = regexp.Compile(md.encRegex)
	}
	return md, nil
}

func appendUnique(s []string, v string) []string {
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}

// encrypted reports whether sops encrypts the leaf at path (the map keys
// from the root), following sops' Tree.shouldBeEncrypted. At most one rule
// is set.
func (md *metadata) encrypted(path []string) bool {
	match := func(fn func(string) bool) bool {
		for _, p := range path {
			if fn(p) {
				return true
			}
		}
		return false
	}
	switch {
	case md.unencSuffix != "":
		return !match(func(p string) bool { return strings.HasSuffix(p, md.unencSuffix) })
	case md.encSuffix != "":
		return match(func(p string) bool { return strings.HasSuffix(p, md.encSuffix) })
	case md.unencRegex != "":
		return md.unencRe == nil || !match(md.unencRe.MatchString)
	case md.encRegex != "":
		return md.encRe != nil && match(md.encRe.MatchString)
	}
	return true
}
