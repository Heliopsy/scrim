// SPDX-License-Identifier: AGPL-3.0-only

package leak

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"encoding/ascii85"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"html"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"
)

// decoded is one interpretation of a piece of text.
type decoded struct {
	enc  string
	text string
}

// A decoder finds encoded runs in text and returns their decodings. Decoders
// are lenient: they decode at every alignment and keep partial output,
// because a leak only needs a long enough fragment to count.
type decoder struct {
	name string
	fn   func(string) []decoded
}

// minDecoded is the shortest decoded output worth searching.
const minDecoded = 6

// maxDecodedPerView bounds the work one view can cause.
const maxDecodedPerView = 4096

var decoders = []decoder{
	{"hexdump", decodeHexDump},
	{"base64", decodeBase64Runs},
	{"base32", decodeBase32Runs},
	{"hex", decodeHexRuns},
	{"decimal-bytes", decodeDecimalRuns},
	{"escapes", decodeEscapes},
	{"url", decodeURL},
	{"html-entities", decodeHTML},
	{"ascii85", decodeASCII85Runs},
	{"base85", decodeBase85Runs},
	{"spelled", decodeSpelled},
}

// hasTextRun reports whether b holds a run of at least n printable ASCII
// bytes. Decoding text at the wrong alignment or in the wrong alphabet yields
// binary noise; only output with a text run can hold a seed or another
// encoding layer, so noise is dropped early.
func hasTextRun(b []byte, n int) bool {
	run := 0
	for _, c := range b {
		if c >= 0x20 && c <= 0x7e || c == '\n' || c == '\r' || c == '\t' {
			run++
			if run >= n {
				return true
			}
		} else {
			run = 0
		}
	}
	return false
}

func keep(out []decoded, enc string, b []byte) []decoded {
	if len(b) < minDecoded {
		return out
	}
	if hasTextRun(b, minDecoded) {
		out = append(out, decoded{enc: enc, text: string(b)})
	}
	// Compressed payloads are decompressed in place, so gzip+base64 and
	// zlib+base64 are one decoding step for the caller. The header is looked
	// for near the start, because a run decoded with a few bytes of
	// surrounding text in front starts with noise.
	for off := 0; ; {
		i := bytes.Index(b[off:], []byte{0x1f, 0x8b, 0x08})
		if i < 0 {
			break
		}
		if zr, err := gzip.NewReader(bytes.NewReader(b[off+i:])); err == nil {
			if u, _ := io.ReadAll(io.LimitReader(zr, 1<<20)); len(u) >= minDecoded {
				out = append(out, decoded{enc: enc + ">gzip", text: string(u)})
				break
			}
		}
		off += i + 1
	}
	head := b[:min(len(b), 64)]
	for i := 0; i+1 < len(head); i++ {
		if b[i] == 0x78 && (b[i+1] == 0x01 || b[i+1] == 0x5e || b[i+1] == 0x9c || b[i+1] == 0xda) {
			if zr, err := zlib.NewReader(bytes.NewReader(b[i:])); err == nil {
				if u, _ := io.ReadAll(io.LimitReader(zr, 1<<20)); len(u) >= minDecoded {
					out = append(out, decoded{enc: enc + ">zlib", text: string(u)})
				}
			}
		}
	}
	return out
}

// runs returns maximal runs of bytes for which in is true, allowing bytes for
// which skip is true inside a run (line wrapping), with at least minLen
// counted bytes. Skipped bytes are dropped from the returned runs.
func runs(s string, minLen int, in, skip func(byte) bool) []string {
	var out []string
	var cur []byte
	flush := func() {
		if len(cur) >= minLen {
			out = append(out, string(cur))
		}
		cur = cur[:0]
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case in(c):
			cur = append(cur, c)
		case skip != nil && skip(c) && len(cur) > 0:
		default:
			flush()
		}
	}
	flush()
	return out
}

func isB64(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '+' || c == '/' || c == '-' || c == '_' || c == '='
}

func isSpace(c byte) bool { return c == ' ' || c == '\n' || c == '\r' || c == '\t' }

func decodeBase64Runs(s string) []decoded {
	var out []decoded
	for _, r := range runs(s, 12, isB64, isSpace) {
		r = strings.Map(func(c rune) rune {
			switch c {
			case '-':
				return '+'
			case '_':
				return '/'
			case '=':
				return -1
			}
			return c
		}, r)
		for off := range 4 {
			if off >= len(r) {
				break
			}
			body := r[off:]
			if len(body)%4 == 1 {
				body = body[:len(body)-1]
			}
			b, err := base64.RawStdEncoding.DecodeString(body)
			if err != nil && len(b) == 0 {
				continue
			}
			out = keep(out, "base64@"+strconv.Itoa(off), b)
		}
	}
	return out
}

func isB32(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '='
}

var b32hex = base32.HexEncoding.WithPadding(base32.NoPadding)
var b32std = base32.StdEncoding.WithPadding(base32.NoPadding)

func decodeBase32Runs(s string) []decoded {
	var out []decoded
	var pieces []string
	for _, r := range runs(s, 16, isB32, isSpace) {
		// Padding ends a base32 string; whatever follows is another one.
		pieces = append(pieces, strings.FieldsFunc(r, func(c rune) bool { return c == '=' })...)
	}
	for _, r := range pieces {
		r = strings.ToUpper(r)
		for off := range 8 {
			if off >= len(r) {
				break
			}
			body := r[off:]
			// Trim to a length base32 accepts without padding.
			for len(body) > 0 {
				switch len(body) % 8 {
				case 0, 2, 4, 5, 7:
				default:
					body = body[:len(body)-1]
					continue
				}
				break
			}
			for _, e := range []struct {
				name string
				enc  *base32.Encoding
			}{{"base32", b32std}, {"base32hex", b32hex}} {
				if b, err := e.enc.DecodeString(body); err == nil || len(b) > 0 {
					out = keep(out, e.name+"@"+strconv.Itoa(off), b)
				}
			}
		}
	}
	return out
}

func isHexRunByte(c byte) bool {
	return isHex(c) || c == ' ' || c == '\t' || c == '\n' || c == ':' || c == ',' || c == '.' || c == '-' || c == '\'' || c == 'x' || c == 'X' || c == '\\' || c == '%' || c == 'u'
}

// decodeHexDump reads the canonical dump formats of xxd, hexdump -C and od
// -A x -t x1z: an offset column, hex bytes, and an optional printable column.
// It returns the bytes from the hex columns and, separately, the printable
// columns joined, since either alone recovers the value.
func decodeHexDump(s string) []decoded {
	var hexBytes, ascii strings.Builder
	lines := 0
	for _, line := range strings.Split(s, "\n") {
		off, rest, ok := strings.Cut(line, " ")
		off = strings.TrimSuffix(off, ":")
		if !ok || len(off) < 6 || !allHex(off) {
			continue
		}
		rest = strings.TrimLeft(rest, " ")
		cols := rest
		text := ""
		if i := strings.Index(rest, "|"); i >= 0 {
			cols, text = rest[:i], strings.TrimSuffix(rest[i+1:], "|")
		} else if i := strings.Index(rest, "  "); i >= 0 {
			// xxd: hex groups, two spaces, then the printable column.
			cols, text = rest[:i], strings.TrimLeft(rest[i:], " ")
		}
		var digits strings.Builder
		for _, f := range strings.Fields(cols) {
			if !allHex(f) || len(f)%2 != 0 {
				break
			}
			digits.WriteString(f)
		}
		b, err := hex.DecodeString(digits.String())
		if err != nil || len(b) == 0 {
			continue
		}
		lines++
		hexBytes.Write(b)
		// The printable column shows exactly the line's bytes; keep it only
		// when it has that length, so trailing text is not mistaken for it.
		if len(text) >= len(b) {
			ascii.WriteString(text[:len(b)])
		}
	}
	if lines == 0 {
		return nil
	}
	out := keep(nil, "hexdump", []byte(hexBytes.String()))
	return keep(out, "hexdump-text", []byte(ascii.String()))
}

func decodeHexRuns(s string) []decoded {
	var out []decoded
	for _, m := range runs(s, 8, isHexRunByte, nil) {
		m = strings.NewReplacer(`\x`, "", `\X`, "", "0x", "", "0X", "", `\u00`, "", "x'", "", "X'", "").Replace(m)
		digits := strings.Map(func(c rune) rune {
			if c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F' {
				return c
			}
			return -1
		}, m)
		for off := range 2 {
			d := digits[min(off, len(digits)):]
			d = d[:len(d)/2*2]
			if b, err := hex.DecodeString(d); err == nil {
				out = keep(out, "hex@"+strconv.Itoa(off), b)
			}
		}
	}
	return out
}

func isDecimalRunByte(c byte) bool {
	return c >= '0' && c <= '9' || c == ' ' || c == ',' || c == ';' || c == '\t' || c == '\n' || c == '\r'
}

func decodeDecimalRuns(s string) []decoded {
	var out []decoded
	for _, m := range runs(s, 11, isDecimalRunByte, nil) {
		var b []byte
		for _, f := range strings.FieldsFunc(m, func(r rune) bool { return r < '0' || r > '9' }) {
			n, err := strconv.Atoi(f)
			if err != nil || n > 255 {
				b = nil
				break
			}
			b = append(b, byte(n))
		}
		out = keep(out, "decimal", b)
	}
	return out
}

// decodeEscapes interprets C, shell, Python and JSON style backslash escapes
// (\xHH, \NNN octal, \uHHHH, \UHHHHHHHH and the single-letter ones) anywhere
// in the text, leaving everything else as is.
func decodeEscapes(s string) []decoded {
	if !strings.Contains(s, `\`) {
		return nil
	}
	var b strings.Builder
	changed := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '\\' || i+1 >= len(s) {
			b.WriteByte(c)
			continue
		}
		n := s[i+1]
		switch {
		case n == 'x' && i+3 < len(s) && isHex(s[i+2]) && isHex(s[i+3]):
			v, _ := strconv.ParseUint(s[i+2:i+4], 16, 8)
			b.WriteByte(byte(v))
			i += 3
		case (n == 'u' || n == 'U') && i+5 < len(s) && allHex(s[i+2:i+6]):
			w := 4
			if n == 'U' && i+9 < len(s) && allHex(s[i+2:i+10]) {
				w = 8
			}
			v, _ := strconv.ParseUint(s[i+2:i+2+w], 16, 32)
			r := rune(v)
			// Join JSON surrogate pairs.
			if r >= 0xd800 && r < 0xdc00 && i+11 < len(s) && s[i+6] == '\\' && s[i+7] == 'u' && allHex(s[i+8:i+12]) {
				lo, _ := strconv.ParseUint(s[i+8:i+12], 16, 32)
				r = (r-0xd800)<<10 + (rune(lo) - 0xdc00) + 0x10000
				i += 6
			}
			b.WriteRune(r)
			i += 1 + w
		case n >= '0' && n <= '7':
			j := i + 1
			for j < len(s) && j < i+4 && s[j] >= '0' && s[j] <= '7' {
				j++
			}
			v, _ := strconv.ParseUint(s[i+1:j], 8, 16)
			b.WriteByte(byte(v))
			i = j - 1
		default:
			if r, ok := map[byte]byte{'n': '\n', 't': '\t', 'r': '\r', '"': '"', '\\': '\\', '/': '/', '\'': '\'', 'b': '\b', 'f': '\f', ' ': ' ', '$': '$', '`': '`'}[n]; ok {
				b.WriteByte(r)
				i++
			} else {
				b.WriteByte(c)
				continue
			}
		}
		changed = true
	}
	if !changed {
		return nil
	}
	return keep(nil, "escapes", []byte(b.String()))
}

func isHex(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

func allHex(s string) bool {
	for i := 0; i < len(s); i++ {
		if !isHex(s[i]) {
			return false
		}
	}
	return true
}

// decodeURL decodes every valid %XX and leaves the rest, so text that mixes
// encoded and plain parts still decodes. Recursion handles double encoding.
func decodeURL(s string) []decoded {
	if !strings.Contains(s, "%") {
		return nil
	}
	var b strings.Builder
	changed := false
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) && isHex(s[i+1]) && isHex(s[i+2]) {
			v, _ := strconv.ParseUint(s[i+1:i+3], 16, 8)
			b.WriteByte(byte(v))
			i += 2
			changed = true
			continue
		}
		b.WriteByte(s[i])
	}
	if !changed {
		return nil
	}
	out := keep(nil, "url", []byte(b.String()))
	// Form encoding writes spaces as '+'.
	if strings.Contains(s, "+") {
		out = keep(out, "url+form", []byte(strings.ReplaceAll(b.String(), "+", " ")))
	}
	return out
}

func decodeHTML(s string) []decoded {
	if !strings.Contains(s, "&") {
		return nil
	}
	u := html.UnescapeString(s)
	if u == s {
		return nil
	}
	return keep(nil, "html-entities", []byte(u))
}

func isA85(c byte) bool { return c >= '!' && c <= 'u' || c == 'z' }

func decodeASCII85Runs(s string) []decoded {
	var out []decoded
	for _, r := range runs(s, 10, isA85, isSpace) {
		r = strings.TrimSuffix(strings.TrimPrefix(r, "<~"), "~>")
		for off := range 5 {
			if off >= len(r) {
				break
			}
			dst := make([]byte, 4*len(r))
			n, _, _ := ascii85.Decode(dst, []byte(r[off:]), true)
			out = keep(out, "ascii85@"+strconv.Itoa(off), dst[:n])
		}
	}
	return out
}

// RFC 1924 alphabet, as used by Python's base64.b85encode and git.
const b85alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~"

var b85index = func() [256]int {
	var t [256]int
	for i := range t {
		t[i] = -1
	}
	for i := 0; i < len(b85alphabet); i++ {
		t[b85alphabet[i]] = i
	}
	return t
}()

func isB85(c byte) bool { return b85index[c] >= 0 }

func decodeBase85Runs(s string) []decoded {
	var out []decoded
	for _, r := range runs(s, 10, isB85, isSpace) {
		for off := range 5 {
			if off >= len(r) {
				break
			}
			out = keep(out, "base85@"+strconv.Itoa(off), b85decode(r[off:]))
		}
	}
	return out
}

func b85decode(s string) []byte {
	var out []byte
	for i := 0; i < len(s); i += 5 {
		chunk := s[i:min(i+5, len(s))]
		pad := 5 - len(chunk)
		var v uint64
		for j := range 5 {
			d := 84
			if j < len(chunk) {
				d = b85index[chunk[j]]
			}
			v = v*85 + uint64(d)
		}
		if v > 0xffffffff {
			break
		}
		b := []byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}
		out = append(out, b[:4-pad]...)
	}
	return out
}

// spelledWords maps the spelling alphabets an agent might use (NATO, digit
// names, symbol names) to the character they stand for.
var spelledWords = func() map[string]string {
	m := map[string]string{
		"zero": "0", "one": "1", "two": "2", "three": "3", "four": "4", "five": "5",
		"six": "6", "seven": "7", "eight": "8", "nine": "9", "niner": "9",
		"dash": "-", "hyphen": "-", "minus": "-", "underscore": "_", "dot": ".", "period": ".",
		"slash": "/", "plus": "+", "equals": "=", "colon": ":", "at": "@",
	}
	for _, w := range []string{"alfa", "bravo", "charlie", "delta", "echo", "foxtrot", "golf", "hotel", "india", "juliett", "kilo", "lima", "mike", "november", "oscar", "papa", "quebec", "romeo", "sierra", "tango", "uniform", "victor", "whiskey", "xray", "yankee", "zulu"} {
		m[w] = w[:1]
	}
	m["alpha"], m["juliet"], m["x-ray"] = "a", "j", "x"
	return m
}()

// decodeSpelled turns runs of spelling-alphabet words, optionally preceded by
// "capital" or "uppercase", back into characters.
func decodeSpelled(s string) []decoded {
	words := strings.FieldsFunc(strings.ToLower(s), func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r == '-')
	})
	var out []decoded
	var cur strings.Builder
	n := 0
	upperNext := false
	flush := func() {
		if n >= minDecoded {
			out = keep(out, "spelled", []byte(cur.String()))
		}
		cur.Reset()
		n = 0
	}
	for _, w := range words {
		if w == "capital" || w == "uppercase" || w == "upper" {
			upperNext = true
			continue
		}
		if w == "lowercase" || w == "lower" || w == "small" {
			continue
		}
		c, ok := spelledWords[w]
		if !ok {
			if len(w) == 1 {
				c, ok = w, true
			}
		}
		if !ok {
			flush()
			upperNext = false
			continue
		}
		if upperNext {
			c = strings.ToUpper(c)
			upperNext = false
		}
		cur.WriteString(c)
		n++
	}
	flush()
	return out
}

// fold maps text onto a plain ASCII skeleton: confusable letters become their
// Latin look-alikes, fullwidth forms become ASCII and invisible format
// characters are dropped.
func fold(s string) string {
	if isASCII(s) {
		return s
	}
	b := make([]byte, 0, len(s))
	for i := 0; i < len(s); {
		c := s[i]
		if c < utf8.RuneSelf {
			b = append(b, c)
			i++
			continue
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			b = append(b, c) // keep invalid bytes as they are
			i++
			continue
		}
		i += size
		switch {
		case r >= 0xff01 && r <= 0xff5e: // fullwidth ASCII
			b = append(b, byte(r-0xfee0))
		case r == 0x200b || r == 0x200c || r == 0x200d || r == 0x2060 || r == 0xfeff || r == 0x00ad || r == 0x180e:
		case r >= 0xfe00 && r <= 0xfe0f: // variation selectors
		case r >= 0xe0000 && r <= 0xe007f: // tag characters
			if r >= 0xe0020 && r <= 0xe007e {
				b = append(b, byte(r-0xe0000))
			}
		default:
			if c, ok := confusables[r]; ok {
				b = utf8.AppendRune(b, c)
			} else {
				b = utf8.AppendRune(b, r)
			}
		}
	}
	return string(b)
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}

// confusables is a hand-picked subset of Unicode's confusables table covering
// the Cyrillic, Greek and mathematical letters that render like ASCII.
var confusables = func() map[rune]rune {
	m := map[rune]rune{}
	pairs := []string{
		"аa", "бb", "сc", "ԁd", "еe", "һh", "іi", "јj", "кk", "ӏl", "мm", "оo", "рp", "ԛq", "ѕs", "тt", "ԝw", "хx", "уy",
		"АA", "ВB", "СC", "ЕE", "НH", "ІI", "ЈJ", "КK", "МM", "ОO", "РP", "ЅS", "ТT", "ХX", "УY", "ԜW",
		"αa", "βb", "εe", "ιi", "κk", "νv", "οo", "ρp", "τt", "υu", "χx",
		"ΑA", "ΒB", "ΕE", "ΗH", "ΙI", "ΚK", "ΜM", "ΝN", "ΟO", "ΡP", "ΤT", "ΥY", "ΧX", "ΖZ",
		"ℓl", "ℯe", "ℴo", "ⅰi", "ⅼl", "ⅽc", "ⅾd", "ⅿm", "‐-", "‑-", "‒-", "–-", "—-", "−-", "⁄/", "∕/",
	}
	for _, p := range pairs {
		r := []rune(p)
		m[r[0]] = r[1]
	}
	// Mathematical alphanumerics: bold, italic, script, monospace and so on.
	for base := rune(0x1d400); base < 0x1d6a4; base += 52 {
		for i := range rune(26) {
			m[base+i] = 'A' + i
			m[base+26+i] = 'a' + i
		}
	}
	for base := rune(0x1d7ce); base < 0x1d800; base += 10 {
		for i := range rune(10) {
			m[base+i] = '0' + i
		}
	}
	return m
}()
