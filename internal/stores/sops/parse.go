// SPDX-License-Identifier: AGPL-3.0-only

package sops

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"

	"go.yaml.in/yaml/v4"
)

// maxDepth bounds nesting, so a hostile file cannot exhaust the stack.
const maxDepth = 64

// metadataKey is where sops keeps its metadata: the top-level `sops` key
// (YAML, JSON), the `sops_` prefix (dotenv) or the `[sops]` section (ini).
const metadataKey = "sops"

// errNoMetadata marks a well-formed document without SOPS metadata: not a
// SOPS file.
var errNoMetadata = errors.New("not a SOPS-encrypted file (no sops metadata)")

// errUnsupported marks a valid SOPS file this source cannot read.
type errUnsupported struct{ what string }

func (e errUnsupported) Error() string { return e.what }

// parseError names where a document failed to parse, never its content.
func parseError(format string, line int, what string) error {
	if line > 0 {
		return fmt.Errorf("invalid %s at line %d: %s", format, line, what)
	}
	return fmt.Errorf("invalid %s: %s", format, what)
}

// parseDoc splits a SOPS file into its data tree and its metadata tree.
func parseDoc(f Format, b []byte) (data, meta *node, err error) {
	switch f {
	case FormatYAML:
		data, err = parseYAML(b)
	case FormatJSON:
		data, err = parseJSON(b)
	case FormatDotenv:
		return parseDotenv(b)
	case FormatINI:
		return parseINI(b)
	default:
		return nil, nil, fmt.Errorf("unknown format %q", f)
	}
	if err != nil {
		return nil, nil, err
	}
	meta = data.remove(metadataKey)
	if meta == nil {
		return nil, nil, errNoMetadata
	}
	if meta.kind != kindMap {
		return nil, nil, errors.New("sops metadata is not a mapping")
	}
	return data, meta, nil
}

var yamlLine = regexp.MustCompile(`line (\d+)`)

// yamlError keeps only the line number of a YAML error: its message can
// quote the input.
func yamlError(err error) error {
	line := 0
	if m := yamlLine.FindStringSubmatch(err.Error()); m != nil {
		line, _ = strconv.Atoi(m[1])
	}
	return parseError("YAML", line, "syntax error")
}

func parseYAML(b []byte) (*node, error) {
	dec := yaml.NewDecoder(bytes.NewReader(b))
	var doc yaml.Node
	if err := dec.Decode(&doc); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errNoMetadata
		}
		return nil, yamlError(err)
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); err == nil {
		return nil, errUnsupported{"multi-document YAML files are not supported"}
	} else if !errors.Is(err, io.EOF) {
		return nil, yamlError(err)
	}
	root := &doc
	if root.Kind == yaml.DocumentNode {
		if len(root.Content) == 0 {
			return nil, errNoMetadata
		}
		root = root.Content[0]
	}
	switch {
	case root.Kind == yaml.ScalarNode && root.ShortTag() == "!!null":
		return nil, errNoMetadata
	case root.Kind != yaml.MappingNode:
		return nil, parseError("YAML", root.Line, "the document is not a mapping")
	}
	return fromYAML(root, 0)
}

func fromYAML(y *yaml.Node, depth int) (*node, error) {
	if depth > maxDepth {
		return nil, parseError("YAML", y.Line, "nested too deeply")
	}
	switch y.Kind {
	case yaml.AliasNode:
		if y.Alias == nil {
			return nil, parseError("YAML", y.Line, "dangling alias")
		}
		return fromYAML(y.Alias, depth+1)
	case yaml.MappingNode:
		n := &node{kind: kindMap, line: y.Line}
		for i := 0; i+1 < len(y.Content); i += 2 {
			k := y.Content[i]
			if k.Kind == yaml.AliasNode && k.Alias != nil {
				k = k.Alias
			}
			if k.Kind != yaml.ScalarNode || k.ShortTag() != "!!str" {
				return nil, parseError("YAML", k.Line, "a mapping key is not a string")
			}
			v, err := fromYAML(y.Content[i+1], depth+1)
			if err != nil {
				return nil, err
			}
			if !n.set(k.Value, v) {
				return nil, parseError("YAML", k.Line, "duplicate key")
			}
		}
		return n, nil
	case yaml.SequenceNode:
		n := &node{kind: kindList, line: y.Line}
		for _, it := range y.Content {
			v, err := fromYAML(it, depth+1)
			if err != nil {
				return nil, err
			}
			n.items = append(n.items, v)
		}
		return n, nil
	case yaml.ScalarNode:
		switch y.ShortTag() {
		case "!!null":
			return &node{kind: kindNull, line: y.Line}, nil
		case "!!str":
			return &node{kind: kindLeaf, str: true, text: y.Value, line: y.Line}, nil
		}
		// A typed scalar is decoded the way sops decodes it (into an
		// interface{}) and kept in the form sops hashes into the MAC.
		var v any
		if err := y.Decode(&v); err != nil {
			return nil, parseError("YAML", y.Line, "a scalar does not decode")
		}
		n := &node{kind: kindLeaf, line: y.Line}
		switch x := v.(type) {
		case nil:
			n.kind = kindNull
		case string:
			n.str, n.text = true, x
		case int:
			n.text = strconv.Itoa(x)
		case float64:
			n.text = strconv.FormatFloat(x, 'f', -1, 64)
		case bool:
			n.text = boolText(x)
		case time.Time:
			t, _ := x.MarshalText()
			n.text = string(t)
		default:
			return nil, parseError("YAML", y.Line, "a scalar has a type sops cannot hash")
		}
		return n, nil
	}
	return nil, parseError("YAML", y.Line, "unexpected node")
}

// boolText is how sops hashes a boolean (Python's spelling, kept for
// compatibility with the original implementation).
func boolText(b bool) string {
	if b {
		return "True"
	}
	return "False"
}

func parseJSON(b []byte) (*node, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	fail := func() (*node, error) {
		return nil, parseError("JSON", 0, fmt.Sprintf("at byte %d", dec.InputOffset()))
	}
	tok, err := dec.Token()
	if err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errNoMetadata
		}
		return fail()
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return nil, parseError("JSON", 0, "the document is not an object")
	}
	root, err := jsonObject(dec, 0)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return fail()
	}
	return root, nil
}

func jsonValue(dec *json.Decoder, tok json.Token, depth int) (*node, error) {
	if depth > maxDepth {
		return nil, parseError("JSON", 0, fmt.Sprintf("nested too deeply at byte %d", dec.InputOffset()))
	}
	switch x := tok.(type) {
	case json.Delim:
		switch x {
		case '{':
			return jsonObject(dec, depth+1)
		case '[':
			n := &node{kind: kindList}
			for {
				t, err := dec.Token()
				if err != nil {
					return nil, parseError("JSON", 0, fmt.Sprintf("at byte %d", dec.InputOffset()))
				}
				if d, ok := t.(json.Delim); ok && d == ']' {
					return n, nil
				}
				v, err := jsonValue(dec, t, depth+1)
				if err != nil {
					return nil, err
				}
				n.items = append(n.items, v)
			}
		}
	case string:
		return &node{kind: kindLeaf, str: true, text: x}, nil
	case json.Number:
		// As sops: an integer in int64 range is an int, anything else a
		// float64.
		if i, err := x.Int64(); err == nil {
			return &node{kind: kindLeaf, text: strconv.FormatInt(i, 10)}, nil
		}
		f, err := x.Float64()
		if err != nil {
			return nil, parseError("JSON", 0, fmt.Sprintf("number out of range at byte %d", dec.InputOffset()))
		}
		return &node{kind: kindLeaf, text: strconv.FormatFloat(f, 'f', -1, 64)}, nil
	case bool:
		return &node{kind: kindLeaf, text: boolText(x)}, nil
	case nil:
		return &node{kind: kindNull}, nil
	}
	return nil, parseError("JSON", 0, fmt.Sprintf("unexpected token at byte %d", dec.InputOffset()))
}

// jsonObject reads the members of an object whose '{' was consumed.
func jsonObject(dec *json.Decoder, depth int) (*node, error) {
	n := newMap()
	for {
		t, err := dec.Token()
		if err != nil {
			return nil, parseError("JSON", 0, fmt.Sprintf("at byte %d", dec.InputOffset()))
		}
		if d, ok := t.(json.Delim); ok && d == '}' {
			return n, nil
		}
		k, ok := t.(string)
		if !ok {
			return nil, parseError("JSON", 0, fmt.Sprintf("at byte %d", dec.InputOffset()))
		}
		vt, err := dec.Token()
		if err != nil {
			return nil, parseError("JSON", 0, fmt.Sprintf("at byte %d", dec.InputOffset()))
		}
		v, err := jsonValue(dec, vt, depth)
		if err != nil {
			return nil, err
		}
		if !n.set(k, v) {
			return nil, parseError("JSON", 0, fmt.Sprintf("duplicate key at byte %d", dec.InputOffset()))
		}
	}
}

// parseDotenv reads a dotenv file the way sops does: lines split on "\n",
// blank lines skipped, lines starting with '#' are comments, every other
// line is KEY=VALUE split at the first '=', with no trimming, no quoting
// and `\n` in the value turned into a newline. Keys starting with `sops_`
// are the flattened metadata.
func parseDotenv(b []byte) (data, meta *node, err error) {
	data = newMap()
	var flat [][2]string
	for i, line := range bytes.Split(b, []byte("\n")) {
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		pos := bytes.IndexByte(line, '=')
		if pos < 0 {
			return nil, nil, parseError("dotenv", i+1, "expected KEY=VALUE")
		}
		key := string(line[:pos])
		val := strings.ReplaceAll(string(line[pos+1:]), `\n`, "\n")
		if rest, ok := strings.CutPrefix(key, metadataKey+"_"); ok {
			flat = append(flat, [2]string{rest, val})
			continue
		}
		if !data.set(key, &node{kind: kindLeaf, str: true, text: val, line: i + 1}) {
			return nil, nil, parseError("dotenv", i+1, "duplicate key")
		}
	}
	if len(flat) == 0 {
		return nil, nil, errNoMetadata
	}
	meta, err = unflatten(flat)
	return data, meta, err
}

// parseINI reads the INI files sops writes (gopkg.in/ini.v1 with its
// defaults): `[section]` headers, `key = value` or `key: value` pairs,
// whole-line comments starting with '#' or ';', values trimmed and cut at
// their first '#' or ';', then matching surrounding quotes removed. Keys
// before the first header belong to the DEFAULT section.
// Triple-quoted and backquoted values are refused. The `[sops]` section is
// the flattened metadata, with `\n` escapes in its values.
func parseINI(b []byte) (data, meta *node, err error) {
	const defaultSection = "DEFAULT"
	data = newMap()
	cur := newMap()
	data.set(defaultSection, cur)
	var flat [][2]string
	inMeta := false
	for i, raw := range bytes.Split(b, []byte("\n")) {
		line := strings.TrimSpace(string(raw))
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		if line[0] == '[' {
			end := strings.IndexByte(line, ']')
			if end < 0 {
				return nil, nil, parseError("INI", i+1, "unterminated section header")
			}
			name := strings.TrimSpace(line[1:end])
			if name == "" {
				return nil, nil, parseError("INI", i+1, "empty section name")
			}
			inMeta = name == metadataKey
			if inMeta {
				continue
			}
			if name == defaultSection {
				cur = data.get(defaultSection)
				continue
			}
			cur = newMap()
			if !data.set(name, cur) {
				return nil, nil, parseError("INI", i+1, "duplicate section")
			}
			continue
		}
		pos := strings.IndexAny(line, "=:")
		if pos <= 0 {
			return nil, nil, parseError("INI", i+1, "expected key = value")
		}
		key := strings.TrimSpace(line[:pos])
		val := strings.TrimSpace(line[pos+1:])
		if strings.HasPrefix(val, `"""`) || strings.HasPrefix(val, "`") {
			return nil, nil, errUnsupported{fmt.Sprintf("INI line %d: multi-line values are not supported", i+1)}
		}
		if c := strings.IndexAny(val, "#;"); c >= 0 {
			val = strings.TrimSpace(val[:c])
		}
		if surrounded(val, '"') || surrounded(val, '\'') {
			val = val[1 : len(val)-1]
		}
		if inMeta {
			flat = append(flat, [2]string{key, strings.ReplaceAll(val, `\n`, "\n")})
			continue
		}
		if !cur.set(key, &node{kind: kindLeaf, str: true, text: val, line: i + 1}) {
			return nil, nil, parseError("INI", i+1, "duplicate key")
		}
	}
	if len(flat) == 0 {
		return nil, nil, errNoMetadata
	}
	meta, err = unflatten(flat)
	return data, meta, err
}

// surrounded reports whether s is quoted with q at both ends and nowhere
// else, as ini.v1 decides it.
func surrounded(s string, q byte) bool {
	return len(s) >= 2 && s[0] == q && s[len(s)-1] == q && strings.IndexByte(s[1:], q) == len(s)-2
}

// Flattened metadata (dotenv, ini): `age__list_0__map_recipient` is the
// key `recipient` of item 0 of the list `age`.
const (
	flatMap  = "__map_"
	flatList = "__list_"
	maxItems = 1024
)

type flatToken struct {
	key   string
	index int
	list  bool
}

func tokenize(path string) ([]flatToken, error) {
	var out []flatToken
	cur, list := "", false
	emit := func() error {
		if list {
			i, err := strconv.Atoi(cur)
			if err != nil || i < 0 || i >= maxItems {
				return errors.New("bad list index in flattened sops metadata")
			}
			out = append(out, flatToken{index: i, list: true})
		} else {
			out = append(out, flatToken{key: cur})
		}
		return nil
	}
	for i := 0; i < len(path); {
		switch {
		case strings.HasPrefix(path[i:], flatMap):
			if err := emit(); err != nil {
				return nil, err
			}
			cur, list = "", false
			i += len(flatMap)
		case strings.HasPrefix(path[i:], flatList):
			if err := emit(); err != nil {
				return nil, err
			}
			cur, list = "", true
			i += len(flatList)
		default:
			cur += path[i : i+1]
			i++
		}
	}
	if err := emit(); err != nil {
		return nil, err
	}
	return out, nil
}

func unflatten(flat [][2]string) (*node, error) {
	root := newMap()
	for _, e := range flat {
		toks, err := tokenize(e[0])
		if err != nil {
			return nil, err
		}
		if err := place(root, toks, &node{kind: kindLeaf, str: true, text: e[1]}); err != nil {
			return nil, err
		}
	}
	if err := checkGaps(root); err != nil {
		return nil, err
	}
	return root, nil
}

func place(cur *node, toks []flatToken, leaf *node) error {
	bad := errors.New("inconsistent flattened sops metadata")
	for i, t := range toks {
		last := i == len(toks)-1
		next := leaf
		if !last {
			next = newMap()
			if toks[i+1].list {
				next = &node{kind: kindList}
			}
		}
		if t.list {
			if cur.kind != kindList {
				return bad
			}
			for len(cur.items) <= t.index {
				cur.items = append(cur.items, nil)
			}
			if ex := cur.items[t.index]; ex != nil {
				if last || ex.kind != next.kind {
					return bad
				}
				next = ex
			} else {
				cur.items[t.index] = next
			}
		} else {
			if cur.kind != kindMap {
				return bad
			}
			if ex := cur.get(t.key); ex != nil {
				if last || ex.kind != next.kind {
					return bad
				}
				next = ex
			} else {
				cur.set(t.key, next)
			}
		}
		cur = next
	}
	return nil
}

func checkGaps(n *node) error {
	switch n.kind {
	case kindMap:
		for _, v := range n.vals {
			if err := checkGaps(v); err != nil {
				return err
			}
		}
	case kindList:
		for _, v := range n.items {
			if v == nil {
				return errors.New("flattened sops metadata skips a list index")
			}
			if err := checkGaps(v); err != nil {
				return err
			}
		}
	}
	return nil
}
