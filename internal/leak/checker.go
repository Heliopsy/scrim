// SPDX-License-Identifier: AGPL-3.0-only

package leak

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"
)

// Capture is one request as the fake provider received it.
type Capture struct {
	// Seq numbers captures in arrival order, starting at 1.
	Seq      int
	Method   string
	Path     string
	RawQuery string
	Header   http.Header
	Body     []byte
}

// Finding is one seed found in one place of one capture.
type Finding struct {
	Seed SeedRef `json:"seed"`
	// Request is the capture sequence number.
	Request int `json:"request"`
	// Location is where the value was found: "header:<name>", "query",
	// "path", "body" for the raw bytes, or "body:<json path>".
	Location string `json:"location"`
	// Encodings lists every decoding chain that exposed the value here, for
	// example "json>base64@1" or "json>skeleton>reversed".
	Encodings []string `json:"encodings"`
	// Match is "exact" when the whole value was recovered, "partial" when a
	// fragment above the threshold was.
	Match string `json:"match"`
	// Matched is the length of the longest recovered run, in bytes of the
	// compared form.
	Matched int `json:"matched"`
	// Of is the length of the compared form.
	Of int `json:"of"`
}

// Checker finds seeded values in captures under every transform the leak
// suite knows. It is stricter than the redactor by design: it decodes base64,
// base32, base85, hex, decimal byte lists, escapes, URL and HTML encoding,
// spelling alphabets, gzip and zlib, recursively, and compares every result
// case-folded, reversed, rot13 and rot47 shifted and reduced to letters and
// digits, with partial matches above a threshold.
type Checker struct {
	// MinPartial is the shortest fragment, in compared bytes outside public
	// parts, that counts as a partial leak. Default 8, the
	// default minimum secret length.
	MinPartial int
	// PartialFraction is the fraction of a value's length a fragment must
	// reach to count, capped by MaxPartial. Default 0.5.
	PartialFraction float64
	// MaxPartial caps the fragment length required for long values, so a
	// single leaked line of a private key counts. Default 24.
	MaxPartial int
	// MaxDepth bounds nested decoding. Default 3.
	MaxDepth int

	seeds []Seed
	fams  []*family
}

// family is a set of comparison forms that share a text projection.
type family struct {
	name    string
	project func(string) string
	forms   []form
	grams   map[string][]gramRef
	k       int
}

type form struct {
	seed   int
	label  string
	text   string
	public []bool // public[i] is true when text[i] comes from a public part
}

type gramRef struct {
	form int
	pos  int
}

// NewChecker returns a checker for the given seeds with default thresholds.
func NewChecker(seeds []Seed) *Checker {
	c := &Checker{MinPartial: 8, PartialFraction: 0.5, MaxPartial: 24, MaxDepth: 3, seeds: seeds}
	c.build()
	return c
}

// WithSeeds returns a checker with the same thresholds for other seeds.
func (c *Checker) WithSeeds(seeds []Seed) *Checker {
	n := &Checker{MinPartial: c.MinPartial, PartialFraction: c.PartialFraction, MaxPartial: c.MaxPartial, MaxDepth: c.MaxDepth, seeds: seeds}
	n.build()
	return n
}

// Seeds returns the seeds the checker looks for.
func (c *Checker) Seeds() []Seed { return c.seeds }

func rot13(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z':
			return 'a' + (r-'a'+13)%26
		case r >= 'A' && r <= 'Z':
			return 'A' + (r-'A'+13)%26
		}
		return r
	}, s)
}

func rot47(s string) string {
	return strings.Map(func(r rune) rune {
		if r >= '!' && r <= '~' {
			return '!' + (r-'!'+47)%94
		}
		return r
	}, s)
}

func reverse(s string) string {
	b := []byte(s)
	slices.Reverse(b)
	return string(b)
}

func reverseMask(m []bool) []bool {
	out := slices.Clone(m)
	slices.Reverse(out)
	return out
}

// lowerASCII lower-cases ASCII letters only, leaving every other byte, so
// positions stay aligned with the input.
func lowerASCII(s string) string {
	i := 0
	for i < len(s) && (s[i] < 'A' || s[i] > 'Z') {
		i++
	}
	if i == len(s) {
		return s
	}
	b := []byte(s)
	for ; i < len(b); i++ {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 'a' - 'A'
		}
	}
	return string(b)
}

// skeleton keeps only lower-cased ASCII letters and digits. It undoes spacing,
// one character per line, separators, quoting and case changes in one step.
func skeleton(s string) string {
	s = fold(s)
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
			b.WriteByte(c)
		case c >= 'A' && c <= 'Z':
			b.WriteByte(c + 'a' - 'A')
		}
	}
	return b.String()
}

func skeletonMask(s string, m []bool) []bool {
	var out []bool
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c >= 'A' && c <= 'Z' {
			out = append(out, m[i])
		}
	}
	return out
}

func publicMask(s Seed) []bool {
	m := make([]bool, len(s.value))
	for _, p := range s.Public {
		for off := 0; ; {
			i := strings.Index(s.value[off:], p)
			if i < 0 || p == "" {
				break
			}
			for j := off + i; j < off+i+len(p); j++ {
				m[j] = true
			}
			off += i + 1
		}
	}
	return m
}

func (c *Checker) build() {
	exact := &family{name: "", project: func(s string) string { return s }}
	lowered := &family{name: "case-folded", project: lowerASCII}
	skel := &family{name: "skeleton", project: skeleton}
	for i, s := range c.seeds {
		v, m := s.value, publicMask(s)
		exact.forms = append(exact.forms,
			form{i, "", v, m},
			form{i, "reversed", reverse(v), reverseMask(m)},
			form{i, "rot13", rot13(v), m},
			form{i, "rot47", rot47(v), m},
		)
		lv := lowerASCII(v)
		lowered.forms = append(lowered.forms,
			form{i, "", lv, m},
			form{i, "reversed", reverse(lv), reverseMask(m)},
		)
		// Seeds are ASCII, so fold leaves them unchanged and the mask stays
		// aligned with the skeleton.
		sm := skeletonMask(v, m)
		sk := skeleton(v)
		skel.forms = append(skel.forms,
			form{i, "", sk, sm},
			form{i, "reversed", reverse(sk), reverseMask(sm)},
			form{i, "rot13", rot13(sk), sm},
		)
	}
	c.fams = []*family{exact, lowered, skel}
	for _, f := range c.fams {
		f.k = c.minPartial()
		f.grams = map[string][]gramRef{}
		for fi, fm := range f.forms {
			for p := 0; p+f.k <= len(fm.text); p++ {
				g := fm.text[p : p+f.k]
				f.grams[g] = append(f.grams[g], gramRef{fi, p})
			}
		}
	}
}

func (c *Checker) minPartial() int {
	if c.MinPartial <= 0 {
		return 8
	}
	return c.MinPartial
}

// threshold is the run length that counts as a leak for a form of length n.
func (c *Checker) threshold(n int) int {
	frac := c.PartialFraction
	if frac <= 0 {
		frac = 0.5
	}
	maxP := c.MaxPartial
	if maxP <= 0 {
		maxP = 24
	}
	t := int(float64(n)*frac + 0.999)
	t = max(t, c.minPartial())
	t = min(t, maxP)
	return min(t, n)
}

// hit is a raw match of one form in one view.
type hit struct {
	seed    int
	enc     string
	loc     string
	exact   bool
	matched int
	of      int
}

// view is a piece of text derived from a capture.
type view struct {
	loc   string
	enc   string
	text  string
	depth int
	// final views are searched but not decoded further, because a more
	// specific view (each JSON string) is decoded instead.
	final bool
}

func (c *Checker) search(v view, out []hit) []hit {
	for _, f := range c.fams {
		t := f.project(v.text)
		if len(t) == 0 {
			continue
		}
		enc := v.enc
		if f.name != "" {
			enc += ">" + f.name
		}
		// Forms shorter than a gram can only be matched whole.
		for _, fm := range f.forms {
			if len(fm.text) < f.k && len(fm.text) > 0 && strings.Contains(t, fm.text) {
				out = append(out, hit{fm.seed, label(enc, fm.label), v.loc, true, len(fm.text), len(fm.text)})
			}
		}
		best := map[int]int{} // form index -> longest run
		for i := 0; i+f.k <= len(t); i++ {
			refs, ok := f.grams[t[i:i+f.k]]
			if !ok {
				continue
			}
			for _, r := range refs {
				fm := f.forms[r.form]
				// Extend left and right.
				l := 0
				for i-l-1 >= 0 && r.pos-l-1 >= 0 && t[i-l-1] == fm.text[r.pos-l-1] {
					l++
				}
				n := f.k
				for i+n < len(t) && r.pos+n < len(fm.text) && t[i+n] == fm.text[r.pos+n] {
					n++
				}
				run := l + n
				start := r.pos - l
				secretPart := 0
				for j := start; j < start+run; j++ {
					if !fm.public[j] {
						secretPart++
					}
				}
				if run < c.threshold(len(fm.text)) || (run < len(fm.text) && secretPart < c.minPartial()) {
					continue
				}
				if run > best[r.form] {
					best[r.form] = run
				}
			}
		}
		for fi, run := range best {
			fm := f.forms[fi]
			out = append(out, hit{fm.seed, label(enc, fm.label), v.loc, run == len(fm.text), run, len(fm.text)})
		}
	}
	return out
}

func label(enc, l string) string {
	if l == "" {
		return enc
	}
	return enc + ">" + l
}

// views returns the base views of a capture: headers, query, path, the raw
// body, and every JSON string (keys included) with its path.
func (c *Checker) views(cp Capture) []view {
	var vs []view
	names := make([]string, 0, len(cp.Header))
	for k := range cp.Header {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		vs = append(vs, view{loc: "header:" + k, enc: "header", text: k + ": " + strings.Join(cp.Header[k], ", ")})
	}
	if cp.RawQuery != "" {
		vs = append(vs, view{loc: "query", enc: "query", text: cp.RawQuery})
	}
	if cp.Path != "" {
		vs = append(vs, view{loc: "path", enc: "path", text: cp.Path})
	}
	body := cp.Body
	if strings.EqualFold(cp.Header.Get("Content-Encoding"), "gzip") {
		if zr, err := gzip.NewReader(bytes.NewReader(body)); err == nil {
			if u, err := io.ReadAll(io.LimitReader(zr, 64<<20)); err == nil {
				body = u
			}
		}
	}
	if len(body) == 0 {
		return vs
	}
	raw := view{loc: "body", enc: "raw", text: string(body)}
	var doc any
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	if err := dec.Decode(&doc); err == nil {
		var all, content []string
		walkJSON(doc, "", "", 0, func(path, key, s string, isKey bool) {
			vs = append(vs, view{loc: "body:" + path, enc: "json", text: s})
			if isKey {
				return
			}
			all = append(all, s)
			if contentKeys[key] {
				content = append(content, s)
			}
		})
		// Joined strings catch a value split across fields, blocks or
		// messages: every string value in order, and the message content
		// strings alone, which brings halves in separate tool results
		// together.
		vs = append(vs,
			view{loc: "body:<all strings joined>", enc: "json>joined", text: strings.Join(all, ""), final: true},
			view{loc: "body:<content joined>", enc: "json>content-joined", text: strings.Join(content, "")},
		)
		raw.final = true
	}
	return append(vs, raw)
}

// contentKeys are the JSON keys that hold message content in the supported
// provider APIs.
var contentKeys = map[string]bool{"content": true, "text": true, "output": true, "data": true, "input": true}

// walkJSON calls fn for every string in v, keys included, with the key the
// string sits under. Strings that are themselves JSON documents (tool call
// arguments) are walked too.
func walkJSON(v any, path, key string, depth int, fn func(path, key, s string, isKey bool)) {
	switch t := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			p := path + "." + k
			if path == "" {
				p = k
			}
			fn(p+"<key>", k, k, true)
			walkJSON(t[k], p, k, depth, fn)
		}
	case []any:
		for i, e := range t {
			walkJSON(e, path+"["+strconv.Itoa(i)+"]", key, depth, fn)
		}
	case string:
		fn(path, key, t, false)
		if depth < 2 {
			s := strings.TrimSpace(t)
			if len(s) > 1 && (s[0] == '{' || s[0] == '[') {
				var inner any
				if json.Unmarshal([]byte(s), &inner) == nil {
					walkJSON(inner, path+"<json>", key, depth+1, fn)
				}
			}
		}
	case json.Number:
		fn(path, key, t.String(), false)
	}
}

// Check returns every seeded value found in the capture. Set thresholds
// before the first call; a checker is safe for concurrent use only after it.
func (c *Checker) Check(cp Capture) []Finding {
	if len(c.fams) == 0 || c.fams[0].k != c.minPartial() {
		c.build() // thresholds changed after construction
	}
	maxDepth := c.MaxDepth
	if maxDepth <= 0 {
		maxDepth = 3
	}
	var hits []hit
	queue := c.views(cp)
	seen := map[string]bool{}
	budget := maxDecodedPerView * 8
	for len(queue) > 0 {
		v := queue[0]
		queue = queue[1:]
		if seen[v.text] && v.depth > 0 {
			continue
		}
		seen[v.text] = true
		hits = c.search(v, hits)
		if v.depth >= maxDepth || v.final {
			continue
		}
		folded := fold(v.text)
		if folded != v.text {
			queue = append(queue, view{loc: v.loc, enc: v.enc + ">homoglyph-fold", text: folded, depth: v.depth + 1})
		}
		for _, d := range decoders {
			for _, r := range d.fn(v.text) {
				if budget <= 0 {
					break
				}
				budget--
				queue = append(queue, view{loc: v.loc, enc: v.enc + ">" + r.enc, text: r.text, depth: v.depth + 1})
			}
		}
	}
	return c.collapse(cp.Seq, hits)
}

// collapse merges hits into one finding per seed and location, and drops the
// raw-body and joined views when a more specific JSON location already
// explains the leak.
func (c *Checker) collapse(seq int, hits []hit) []Finding {
	type key struct {
		seed int
		loc  string
	}
	agg := map[key]*Finding{}
	encs := map[key]map[string]bool{}
	specific := map[int]bool{}
	for _, h := range hits {
		if strings.HasPrefix(h.loc, "body:") && !strings.HasPrefix(h.loc, "body:<") {
			specific[h.seed] = true
		}
	}
	for _, h := range hits {
		if specific[h.seed] && (h.loc == "body" || strings.HasPrefix(h.loc, "body:<")) {
			continue
		}
		k := key{h.seed, h.loc}
		f := agg[k]
		if f == nil {
			f = &Finding{Seed: c.seeds[h.seed].Ref(), Request: seq, Location: h.loc, Match: "partial"}
			agg[k] = f
			encs[k] = map[string]bool{}
		}
		encs[k][h.enc] = true
		if h.exact {
			f.Match = "exact"
		}
		if h.matched > f.Matched || (h.matched == f.Matched && h.of < f.Of) {
			f.Matched, f.Of = h.matched, h.of
		}
	}
	out := make([]Finding, 0, len(agg))
	for k, f := range agg {
		for e := range encs[k] {
			f.Encodings = append(f.Encodings, e)
		}
		sort.Slice(f.Encodings, func(i, j int) bool {
			a, b := f.Encodings[i], f.Encodings[j]
			if strings.Count(a, ">") != strings.Count(b, ">") {
				return strings.Count(a, ">") < strings.Count(b, ">")
			}
			return a < b
		})
		out = append(out, *f)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Seed.Name != out[j].Seed.Name {
			return out[i].Seed.Name < out[j].Seed.Name
		}
		return out[i].Location < out[j].Location
	})
	return out
}

// CheckText checks a free-standing text, for example a transcript, as if it
// were the body of one capture.
func (c *Checker) CheckText(seq int, text string) []Finding {
	return c.Check(Capture{Seq: seq, Body: []byte(text)})
}
