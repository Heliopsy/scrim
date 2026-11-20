package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/rand/v2"
	"strings"
)

var words = strings.Fields(`the a to of and in is it that for on with as be this are was not by from at
or an have function return error value config request response server client token key file path line
build test deploy cluster service handler context buffer stream event json parse encode decode retry
timeout cache index query update delete create read write open close start stop run check verify
proxy upstream header body chunk message content block delta text tool input output result status`)

var idents = strings.Fields(`ctx req resp buf err cfg srv conn rows item items opts params data payload
user session handler router logger client cache store queue worker pool batch result value key name`)

var hitForms = []string{"json", "json", "json", "json", "json_slash", "json_u", "b64", "b64", "b64", "b64url", "hex", "url", "url"}

// seg: text to be JSON-escaped by the writer (raw=false) or pre-encoded bytes inserted verbatim (raw=true).
type seg struct {
	s   string
	raw bool
}

type bodyGen struct {
	r       *rand.Rand
	secrets []string
	hitRate float64 // hits per byte
	buf     []byte
	hits    map[string]int
}

func (g *bodyGen) word() string  { return words[g.r.IntN(len(words))] }
func (g *bodyGen) ident() string { return idents[g.r.IntN(len(idents))] }

func (g *bodyGen) sentence() string {
	n := 6 + g.r.IntN(14)
	ws := make([]string, n)
	for i := range ws {
		ws[i] = g.word()
	}
	s := strings.Join(ws, " ")
	if g.r.IntN(10) == 0 {
		s += ` (naïve → "quoted" path C:\tmp\x)`
	}
	return strings.ToUpper(s[:1]) + s[1:] + ". "
}

func (g *bodyGen) codeLine() string {
	ind := strings.Repeat("\t", g.r.IntN(4))
	switch g.r.IntN(6) {
	case 0:
		return fmt.Sprintf("%sif %s != nil {\n", ind, g.ident())
	case 1:
		return fmt.Sprintf("%s%s, err := %s.%s(%s, %q)\n", ind, g.ident(), g.ident(), strings.Title(g.word()), g.ident(), g.word())
	case 2:
		return fmt.Sprintf("%sreturn fmt.Errorf(\"%s %s: %%w\", err)\n", ind, g.word(), g.word())
	case 3:
		return fmt.Sprintf("%s// %s", ind, g.sentence()) + "\n"
	case 4:
		return fmt.Sprintf("%sdef %s_%s(self, %s=None):\n", ind, g.word(), g.ident(), g.ident())
	default:
		return fmt.Sprintf("%s%s[%d] = {\"%s\": %d, \"%s\": \"%s\"}\n", ind, g.ident(), g.r.IntN(100), g.word(), g.r.IntN(1e5), g.ident(), g.word())
	}
}

func (g *bodyGen) logLine() string {
	lv := []string{"INFO", "DEBUG", "WARN", "ERROR"}[g.r.IntN(4)]
	return fmt.Sprintf("2026-11-%02dT%02d:%02d:%02d.%03dZ %s [%s] req_id=%s %s latency_ms=%d\n",
		1+g.r.IntN(28), g.r.IntN(24), g.r.IntN(60), g.r.IntN(60), g.r.IntN(1000), lv, g.ident(),
		hex.EncodeToString(randBytes(g.r, 8)), g.sentence(), g.r.IntN(5000))
}

func (g *bodyGen) envLine() string {
	k := strings.ToUpper(g.word() + "_" + g.ident())
	switch g.r.IntN(4) {
	case 0:
		return fmt.Sprintf("%s=%d\n", k, g.r.IntN(65536))
	case 1:
		return fmt.Sprintf("%s=https://%s.internal.example:%d/%s\n", k, g.word(), 1000+g.r.IntN(9000), g.word())
	case 2:
		return fmt.Sprintf("%s=%s\n", k, hex.EncodeToString(randBytes(g.r, 16)))
	default:
		return fmt.Sprintf("%s=%s\n", k, []string{"true", "false", "debug", "production"}[g.r.IntN(4)])
	}
}

func (g *bodyGen) blobLine() string {
	// non-secret base64 noise, e.g. an embedded image or a checksum list
	return base64.StdEncoding.EncodeToString(randBytes(g.r, 45+g.r.IntN(300))) + "\n"
}

// hit produces segments embedding one secret in one form.
func (g *bodyGen) hit() []seg {
	si := g.r.IntN(len(g.secrets))
	s := g.secrets[si]
	form := hitForms[g.r.IntN(len(hitForms))]
	g.hits[form]++
	switch form {
	case "json":
		ctx := []string{"export API_TOKEN=", "Authorization: Bearer ", `{"api_key": "`, "password: ", "  token = "}[g.r.IntN(5)]
		return []seg{{ctx, false}, {s, false}, {"\n", false}}
	case "json_slash":
		return []seg{{`"secret":"`, false}, {jsonEscape(s, true, false), true}, {"\"\n", false}}
	case "json_u":
		return []seg{{"key=", false}, {jsonEscape(s, false, true), true}, {"\n", false}}
	case "b64", "b64url":
		var env strings.Builder
		for i := 0; i < g.r.IntN(4); i++ {
			env.WriteString(g.envLine())
		}
		env.WriteString("SECRET_VALUE=" + s + "\n")
		for i := 0; i < g.r.IntN(4); i++ {
			env.WriteString(g.envLine())
		}
		enc := base64.StdEncoding
		if form == "b64url" {
			enc = base64.URLEncoding
		}
		return []seg{{"$ base64 -w0 .env\n", false}, {enc.EncodeToString([]byte(env.String())), true}, {"\n", false}}
	case "hex":
		return []seg{{"$ printf %s \"$KEY\" | xxd -p -c0\n", false}, {hex.EncodeToString([]byte(s)), true}, {"\n", false}}
	case "url":
		return []seg{{"curl -s 'https://api.example.com/v1/auth?client=cli&token=", false}, {urlEncode(s), true}, {"&x=1'\n", false}}
	}
	panic(form)
}

// content builds a string of about n bytes of the given flavour, with hits.
func (g *bodyGen) content(n int, flavour int) []seg {
	var segs []seg
	total := 0
	for total < n {
		var l string
		switch flavour {
		case 0:
			l = g.sentence()
			if g.r.IntN(6) == 0 {
				l += "\n\n"
			}
		case 1:
			l = g.codeLine()
		case 2:
			l = g.logLine()
		case 3:
			l = g.envLine()
		default:
			if g.r.IntN(3) == 0 {
				l = g.blobLine()
			} else {
				l = g.logLine()
			}
		}
		segs = append(segs, seg{l, false})
		total += len(l)
		if g.hitRate > 0 && g.r.Float64() < float64(len(l))*g.hitRate {
			for _, h := range g.hit() {
				segs = append(segs, h)
				total += len(h.s)
			}
		}
	}
	return segs
}

func (g *bodyGen) w(s string) { g.buf = append(g.buf, s...) }

func (g *bodyGen) str(segs []seg) {
	g.buf = append(g.buf, '"')
	for _, s := range segs {
		if s.raw {
			g.buf = append(g.buf, s.s...)
		} else {
			g.buf = append(g.buf, jsonEscape(s.s, false, false)...)
		}
	}
	g.buf = append(g.buf, '"')
}

func (g *bodyGen) toolID() string { return "toolu_01" + randStr(g.r, base62, 22) }

func genBody(seed uint64, target int, secrets []string, hits bool) ([]byte, map[string]int) {
	g := &bodyGen{r: rand.New(rand.NewPCG(seed, 2)), secrets: secrets, hits: map[string]int{}}
	if hits {
		g.hitRate = 1.0 / 4096
	}
	g.buf = make([]byte, 0, target+65536)
	g.w(`{"model":"claude-sonnet-4-5","max_tokens":32000,"stream":true,"system":[{"type":"text","text":`)
	g.str(g.content(6000, 0))
	g.w(`,"cache_control":{"type":"ephemeral"}}],"tools":[`)
	for i, name := range []string{"Bash", "Read", "Edit", "Grep"} {
		if i > 0 {
			g.w(",")
		}
		g.w(`{"name":"` + name + `","description":`)
		g.str([]seg{{g.sentence() + g.sentence(), false}})
		g.w(`,"input_schema":{"type":"object","properties":{"command":{"type":"string"},"path":{"type":"string"}},"required":["command"]}}`)
	}
	g.w(`],"messages":[`)
	first := true
	for len(g.buf) < target-2048 {
		if !first {
			g.w(",")
		}
		first = false
		// user turn
		g.w(`{"role":"user","content":[{"type":"text","text":`)
		g.str(g.content(100+g.r.IntN(1500), 0))
		g.w(`}]},`)
		// assistant turn with tool_use
		id := g.toolID()
		g.w(`{"role":"assistant","content":[{"type":"text","text":`)
		g.str(g.content(100+g.r.IntN(800), 0))
		g.w(`},{"type":"tool_use","id":"` + id + `","name":"Bash","input":{"command":`)
		g.str(g.content(40+g.r.IntN(300), 3))
		g.w(`}}]},`)
		// tool result
		g.w(`{"role":"user","content":[{"type":"tool_result","tool_use_id":"` + id + `","content":`)
		g.str(g.content(500+g.r.IntN(12000), 1+g.r.IntN(4)))
		g.w(`}]}`)
	}
	g.w(`]}`)
	return g.buf, g.hits
}
