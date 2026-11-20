// SPDX-License-Identifier: AGPL-3.0-only

package file

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores/internal/wire"
)

// Format is how a file's bytes map to fields.
type Format string

// Formats.
const (
	FormatAuto   Format = "auto"
	FormatRaw    Format = "raw"
	FormatDotenv Format = "dotenv"
	FormatJSON   Format = "json"
)

// RawField is the field name of a raw file's single value.
const RawField = "value"

// detect picks the format for a file name under FormatAuto.
func detect(name string) Format {
	base := name[strings.LastIndexByte(name, '/')+1:]
	switch {
	case strings.HasSuffix(base, ".env") || strings.HasPrefix(base, ".env"):
		return FormatDotenv
	case strings.HasSuffix(base, ".json"):
		return FormatJSON
	}
	return FormatRaw
}

// parse turns file content into fields. Parse errors name a line or byte
// offset, never content. The caller wipes b afterwards; every returned value
// owns its own copy.
func parse(f Format, b []byte, trimNewline bool) (map[string]secret.Value, error) {
	switch f {
	case FormatRaw:
		v := b
		if trimNewline {
			v = bytes.TrimSuffix(v, []byte("\n"))
			if len(v) < len(b) {
				v = bytes.TrimSuffix(v, []byte("\r"))
			}
		}
		return map[string]secret.Value{RawField: secret.New(v)}, nil
	case FormatDotenv:
		return parseDotenv(b)
	case FormatJSON:
		return parseJSON(b)
	}
	return nil, fmt.Errorf("unknown format %q", f)
}

func wipeAll(m map[string]secret.Value) {
	for _, v := range m {
		v.Wipe()
	}
}

func parseJSON(b []byte) (map[string]secret.Value, error) {
	var raw map[string]wire.Raw
	if err := json.Unmarshal(b, &raw); err != nil {
		// encoding/json errors can quote a character of the input; report
		// only where it failed.
		var se *json.SyntaxError
		if errors.As(err, &se) {
			return nil, fmt.Errorf("invalid JSON at byte %d", se.Offset)
		}
		return nil, errors.New("JSON content is not an object of fields")
	}
	out := make(map[string]secret.Value, len(raw))
	defer func() {
		for _, r := range raw {
			r.Wipe()
		}
	}()
	for k, r := range raw {
		if bytes.Equal(bytes.TrimSpace(r), []byte("null")) {
			continue
		}
		v, err := r.Value()
		if err != nil {
			wipeAll(out)
			return nil, fmt.Errorf("field %s: invalid value", k)
		}
		out[k] = v
	}
	return out, nil
}

func validKey(k []byte) bool {
	if len(k) == 0 {
		return false
	}
	for i, c := range k {
		switch {
		case c == '_' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z':
		case i > 0 && (c >= '0' && c <= '9' || c == '.' || c == '-'):
		default:
			return false
		}
	}
	return true
}

// parseDotenv reads KEY=VALUE lines: blank lines and lines starting with #
// are skipped, `export ` before a key is allowed, values may be unquoted
// (trailing ` #comment` and surrounding spaces removed), single-quoted
// (literal, may span lines) or double-quoted (may span lines; escapes \n \r
// \t \" \\ \$ and \` are decoded). Variables are not expanded. A later
// duplicate key wins.
func parseDotenv(b []byte) (map[string]secret.Value, error) {
	out := map[string]secret.Value{}
	fail := func(line int, what string) (map[string]secret.Value, error) {
		wipeAll(out)
		return nil, fmt.Errorf("dotenv line %d: %s", line, what)
	}
	line := 1
	i := 0
	skipSpace := func() {
		for i < len(b) && (b[i] == ' ' || b[i] == '\t') {
			i++
		}
	}
	for i < len(b) {
		start := line
		skipSpace()
		if i >= len(b) {
			break
		}
		if b[i] == '\n' || b[i] == '\r' {
			if b[i] == '\n' {
				line++
			}
			i++
			continue
		}
		if b[i] == '#' {
			for i < len(b) && b[i] != '\n' {
				i++
			}
			continue
		}
		if bytes.HasPrefix(b[i:], []byte("export ")) || bytes.HasPrefix(b[i:], []byte("export\t")) {
			i += len("export ")
			skipSpace()
		}
		ks := i
		for i < len(b) && b[i] != '=' && b[i] != '\n' && b[i] != ' ' && b[i] != '\t' {
			i++
		}
		key := b[ks:i]
		skipSpace()
		if i >= len(b) || b[i] != '=' {
			return fail(start, "expected KEY=VALUE")
		}
		if !validKey(key) {
			return fail(start, "invalid key")
		}
		i++ // '='
		skipSpace()
		var val []byte
		switch {
		case i < len(b) && b[i] == '\'':
			i++
			end := bytes.IndexByte(b[i:], '\'')
			if end < 0 {
				return fail(start, "unterminated single quote")
			}
			val = append([]byte(nil), b[i:i+end]...)
			line += bytes.Count(b[i:i+end], []byte("\n"))
			i += end + 1
		case i < len(b) && b[i] == '"':
			i++
			closed := false
			for i < len(b) {
				c := b[i]
				if c == '"' {
					closed = true
					i++
					break
				}
				if c == '\\' && i+1 < len(b) {
					e := b[i+1]
					switch e {
					case 'n':
						val = append(val, '\n')
					case 'r':
						val = append(val, '\r')
					case 't':
						val = append(val, '\t')
					case '"', '\\', '$', '`':
						val = append(val, e)
					default:
						val = append(val, '\\', e)
					}
					if e == '\n' {
						line++
					}
					i += 2
					continue
				}
				if c == '\n' {
					line++
				}
				val = append(val, c)
				i++
			}
			if !closed {
				secret.WipeBytes(val)
				return fail(start, "unterminated double quote")
			}
		default:
			vs := i
			for i < len(b) && b[i] != '\n' {
				if b[i] == '#' && i > vs && (b[i-1] == ' ' || b[i-1] == '\t') {
					break
				}
				i++
			}
			val = append([]byte(nil), bytes.TrimRight(b[vs:i], " \t\r")...)
		}
		// Rest of the line may hold only spaces and a comment.
		skipSpace()
		if i < len(b) && b[i] == '#' {
			for i < len(b) && b[i] != '\n' {
				i++
			}
		}
		if i < len(b) && b[i] == '\r' {
			i++
		}
		if i < len(b) && b[i] != '\n' {
			secret.WipeBytes(val)
			return fail(start, "unexpected text after the value")
		}
		if old, ok := out[string(key)]; ok {
			old.Wipe()
		}
		out[string(key)] = secret.Adopt(val)
	}
	return out, nil
}
