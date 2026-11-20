// SPDX-License-Identifier: AGPL-3.0-only

package agenttools

import (
	"bytes"
	"encoding/json"
	"regexp"
	"strconv"
	"strings"

	"github.com/heliopsy/scrim/internal/secret"
)

// Extraction selects the value inside captured output. With neither field
// set, the whole output is the value, with surrounding whitespace trimmed.
type Extraction struct {
	JSONPath string
	Pattern  string
}

// pathStep is one step of a JSON path: an object key or an array index.
type pathStep struct {
	key   string
	index int
	isIdx bool
}

// Check validates the extraction before anything runs.
func (x Extraction) Check() error {
	if x.JSONPath != "" && x.Pattern != "" {
		return Errorf(CodeInvalid, "json_path and pattern cannot both be set")
	}
	if x.JSONPath != "" {
		if _, err := parsePath(x.JSONPath); err != nil {
			return err
		}
	}
	if x.Pattern != "" {
		if len(x.Pattern) > 1024 {
			return Errorf(CodeInvalid, "pattern is longer than 1024 bytes")
		}
		if _, err := regexp.Compile(x.Pattern); err != nil {
			return Errorf(CodeInvalid, "pattern is not a valid regular expression")
		}
	}
	return nil
}

// Extract returns the selected value from out. Errors never contain any part
// of out: they say only what was not found.
func (x Extraction) Extract(out []byte) (secret.Value, error) {
	if err := x.Check(); err != nil {
		return secret.Value{}, err
	}
	var v []byte
	switch {
	case x.JSONPath != "":
		got, err := extractJSON(out, x.JSONPath)
		if err != nil {
			return secret.Value{}, err
		}
		v = got
	case x.Pattern != "":
		re := regexp.MustCompile(x.Pattern)
		m := re.FindSubmatchIndex(out)
		if m == nil {
			return secret.Value{}, Errorf(CodeInvalid, "pattern matched nothing in the output")
		}
		start, end := m[0], m[1]
		if len(m) >= 4 && m[2] >= 0 {
			start, end = m[2], m[3]
		}
		v = bytes.Clone(out[start:end])
	default:
		v = bytes.Clone(bytes.TrimSpace(out))
	}
	if len(v) == 0 {
		secret.WipeBytes(v)
		return secret.Value{}, Errorf(CodeInvalid, "the extracted value is empty")
	}
	return secret.Adopt(v), nil
}

func extractJSON(out []byte, path string) ([]byte, error) {
	steps, err := parsePath(path)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(out))
	dec.UseNumber()
	var doc any
	if err := dec.Decode(&doc); err != nil {
		return nil, Errorf(CodeInvalid, "the output is not JSON")
	}
	cur := doc
	for _, s := range steps {
		switch c := cur.(type) {
		case map[string]any:
			if s.isIdx {
				return nil, Errorf(CodeInvalid, "json_path %s matched no value", path)
			}
			next, ok := c[s.key]
			if !ok {
				return nil, Errorf(CodeInvalid, "json_path %s matched no value", path)
			}
			cur = next
		case []any:
			if !s.isIdx || s.index >= len(c) {
				return nil, Errorf(CodeInvalid, "json_path %s matched no value", path)
			}
			cur = c[s.index]
		default:
			return nil, Errorf(CodeInvalid, "json_path %s matched no value", path)
		}
	}
	switch v := cur.(type) {
	case string:
		return []byte(v), nil
	case json.Number:
		return []byte(v.String()), nil
	default:
		return nil, Errorf(CodeInvalid, "json_path %s selects an object, array, boolean or null, not a value", path)
	}
}

// dotKey is a key written after a dot; other keys use ["..."].
var dotKey = regexp.MustCompile(`^[A-Za-z0-9_$@-]+$`)

// parsePath parses .a.b[0]["c d"]. A lone "." is the whole document.
func parsePath(p string) ([]pathStep, error) {
	bad := func() ([]pathStep, error) {
		return nil, Errorf(CodeInvalid, "json_path must look like .token or .data[0].key")
	}
	if len(p) > 256 || p == "" {
		return bad()
	}
	if p == "." {
		return nil, nil
	}
	if p[0] != '.' && p[0] != '[' {
		p = "." + p
	}
	var steps []pathStep
	for i := 0; i < len(p); {
		switch p[i] {
		case '.':
			j := i + 1
			for j < len(p) && p[j] != '.' && p[j] != '[' {
				j++
			}
			if j == i+1 || !dotKey.MatchString(p[i+1:j]) {
				return bad()
			}
			steps = append(steps, pathStep{key: p[i+1 : j]})
			i = j
		case '[':
			end := strings.IndexByte(p[i:], ']')
			if end < 0 {
				return bad()
			}
			inner := p[i+1 : i+end]
			if strings.HasPrefix(inner, `"`) {
				key, err := strconv.Unquote(inner)
				if err != nil {
					return bad()
				}
				steps = append(steps, pathStep{key: key})
			} else {
				n, err := strconv.Atoi(inner)
				if err != nil || n < 0 {
					return bad()
				}
				steps = append(steps, pathStep{index: n, isIdx: true})
			}
			i += end + 1
		default:
			return bad()
		}
	}
	return steps, nil
}
