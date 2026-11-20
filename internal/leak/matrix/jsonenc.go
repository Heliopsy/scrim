// SPDX-License-Identifier: AGPL-3.0-only

package matrix

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Escape selects how string contents are written in a request body. All
// modes produce the same JSON value; a provider decodes each to the same
// text, so each must be redacted the same way.
type Escape string

// Escape modes.
const (
	// EscapeMinimal escapes only what JSON requires, like JavaScript's
	// JSON.stringify and most agent CLIs.
	EscapeMinimal Escape = ""
	// EscapeHTML also escapes <, > and & as <, > and &, like
	// Go's encoding/json by default.
	EscapeHTML Escape = "html"
	// EscapeASCII escapes every non-ASCII character, like Python's
	// json.dumps by default.
	EscapeASCII Escape = "ascii"
	// EscapeAll escapes every character of every string as \uXXXX.
	EscapeAll Escape = "all"
)

// orderedMap keeps key order so request bodies look like real clients'.
type orderedMap []kv

type kv struct {
	k string
	v any
}

func obj(pairs ...any) orderedMap {
	m := make(orderedMap, 0, len(pairs)/2)
	for i := 0; i+1 < len(pairs); i += 2 {
		m = append(m, kv{pairs[i].(string), pairs[i+1]})
	}
	return m
}

func encode(v any, mode Escape) []byte {
	var b strings.Builder
	writeValue(&b, v, mode)
	return []byte(b.String())
}

func writeValue(b *strings.Builder, v any, mode Escape) {
	switch t := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		b.WriteString(strconv.FormatBool(t))
	case int:
		b.WriteString(strconv.Itoa(t))
	case float64:
		b.WriteString(strconv.FormatFloat(t, 'f', -1, 64))
	case string:
		writeString(b, t, mode)
	case json.RawMessage:
		b.Write(t)
	case orderedMap:
		b.WriteByte('{')
		for i, p := range t {
			if i > 0 {
				b.WriteByte(',')
			}
			writeString(b, p.k, mode)
			b.WriteByte(':')
			writeValue(b, p.v, mode)
		}
		b.WriteByte('}')
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		m := make(orderedMap, 0, len(t))
		for _, k := range keys {
			m = append(m, kv{k, t[k]})
		}
		writeValue(b, m, mode)
	case []any:
		b.WriteByte('[')
		for i, e := range t {
			if i > 0 {
				b.WriteByte(',')
			}
			writeValue(b, e, mode)
		}
		b.WriteByte(']')
	default:
		panic(fmt.Sprintf("matrix: cannot encode %T", v))
	}
}

func writeString(b *strings.Builder, s string, mode Escape) {
	b.WriteByte('"')
	for _, r := range s {
		switch {
		case mode == EscapeAll:
			writeU(b, r)
		case r == '"':
			b.WriteString(`\"`)
		case r == '\\':
			b.WriteString(`\\`)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\t':
			b.WriteString(`\t`)
		case r < 0x20:
			writeU(b, r)
		case mode == EscapeHTML && (r == '<' || r == '>' || r == '&'):
			writeU(b, r)
		case (mode == EscapeASCII || mode == EscapeHTML) && (r == 0x2028 || r == 0x2029):
			writeU(b, r)
		case mode == EscapeASCII && r >= utf8.RuneSelf:
			writeU(b, r)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
}

func writeU(b *strings.Builder, r rune) {
	if r > 0xffff {
		r -= 0x10000
		fmt.Fprintf(b, `\u%04x\u%04x`, 0xd800+(r>>10), 0xdc00+(r&0x3ff))
		return
	}
	fmt.Fprintf(b, `\u%04x`, r)
}
