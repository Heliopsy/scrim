// SPDX-License-Identifier: AGPL-3.0-only

package sops

import (
	"slices"
	"strconv"
	"strings"
)

// Format is the document format of a SOPS file.
type Format string

// Formats.
const (
	FormatAuto   Format = "auto"
	FormatYAML   Format = "yaml"
	FormatJSON   Format = "json"
	FormatDotenv Format = "dotenv"
	FormatINI    Format = "ini"
)

// detect picks the format for a file name under FormatAuto, the way sops
// does: by extension, with anything unknown read as JSON (sops writes
// binary files as a JSON document with one `data` key).
func detect(name string) Format {
	base := name[strings.LastIndexByte(name, '/')+1:]
	switch {
	case strings.HasSuffix(base, ".yaml"), strings.HasSuffix(base, ".yml"):
		return FormatYAML
	case strings.HasSuffix(base, ".json"):
		return FormatJSON
	case strings.HasSuffix(base, ".env"), strings.HasPrefix(base, ".env"):
		return FormatDotenv
	case strings.HasSuffix(base, ".ini"):
		return FormatINI
	}
	return FormatJSON
}

type nodeKind uint8

const (
	kindNull nodeKind = iota
	kindMap
	kindList
	kindLeaf
)

// node is one value of a parsed SOPS document. Keys are plaintext in SOPS
// files, and so are encrypted leaves (they hold ciphertext); the only
// plaintext values a node holds are leaves the file stores unencrypted
// (unencrypted_suffix and friends), which the operator chose to keep in
// clear on disk and which are never returned as fields.
type node struct {
	kind  nodeKind
	keys  []string // kindMap, in document order
	vals  []*node  // kindMap values, parallel to keys
	items []*node  // kindList
	// str is set for a string leaf: text is the string itself. For any
	// other leaf, text is the canonical form sops hashes into the MAC
	// (sops.ToBytes: "True"/"False", strconv.Itoa, FormatFloat 'f' -1).
	str  bool
	text string
	line int // 1-based source line, 0 when unknown
}

func newMap() *node { return &node{kind: kindMap} }

// get returns the value of key in a map node, or nil.
func (n *node) get(key string) *node {
	if n == nil || n.kind != kindMap {
		return nil
	}
	for i, k := range n.keys {
		if k == key {
			return n.vals[i]
		}
	}
	return nil
}

// set appends key to a map node and reports false when it is a duplicate.
func (n *node) set(key string, v *node) bool {
	for _, k := range n.keys {
		if k == key {
			return false
		}
	}
	n.keys = append(n.keys, key)
	n.vals = append(n.vals, v)
	return true
}

// remove drops key from a map node and returns its value.
func (n *node) remove(key string) *node {
	for i, k := range n.keys {
		if k == key {
			v := n.vals[i]
			n.keys = append(n.keys[:i], n.keys[i+1:]...)
			n.vals = append(n.vals[:i], n.vals[i+1:]...)
			return v
		}
	}
	return nil
}

// scalar returns the text of a leaf (string or not) and whether n is one.
func (n *node) scalar() (string, bool) {
	if n == nil || n.kind != kindLeaf {
		return "", false
	}
	return n.text, true
}

// Field names: a leaf's key path, segments joined by '/', each segment
// escaped as in RFC 6901 JSON Pointer ('~' as "~0", '/' as "~1"), list
// items numbered from 0. `db/password`, `servers/0/token`,
// `hosts/api.example.com`, `a~1b` for the key "a/b".

func escapeSegment(s string) string {
	if !strings.ContainsAny(s, "~/") {
		return s
	}
	return strings.NewReplacer("~", "~0", "/", "~1").Replace(s)
}

func joinField(parent, seg string) string {
	if parent == "" {
		return seg
	}
	return parent + "/" + seg
}

// leafVisit is called for every leaf in document order: sopsPath is the map
// keys from the root (sops' additional data and the input of its encryption
// rules; list items add nothing), field the escaped field name.
type leafVisit func(n *node, sopsPath []string, field string) error

// isComment reports whether a list item is a comment sops encrypted in
// place (a YAML comment inside a sequence becomes an item of type comment).
// Comments are not hashed into the MAC and are not fields, so they are
// skipped and list items are numbered as the decrypted document shows
// them.
func isComment(n *node) bool {
	if n.kind != kindLeaf || !n.str || !strings.HasSuffix(n.text, ",type:comment]") {
		return false
	}
	ev, ok := parseEnc(n.text)
	return ok && ev.typ == "comment"
}

// walk visits every leaf under n in document order. Nulls and encrypted
// comments in lists are skipped, as sops skips them for the MAC.
func walk(n *node, sopsPath []string, field string, visit leafVisit) error {
	switch n.kind {
	case kindMap:
		for i, k := range n.keys {
			p := slices.Concat(sopsPath, []string{k})
			if err := walk(n.vals[i], p, joinField(field, escapeSegment(k)), visit); err != nil {
				return err
			}
		}
	case kindList:
		i := 0
		for _, it := range n.items {
			if isComment(it) {
				continue
			}
			if err := walk(it, sopsPath, joinField(field, strconv.Itoa(i)), visit); err != nil {
				return err
			}
			i++
		}
	case kindLeaf:
		return visit(n, sopsPath, field)
	}
	return nil
}
