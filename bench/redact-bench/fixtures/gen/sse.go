package main

import (
	"encoding/base64"
	"fmt"
	"math/rand/v2"
	"unicode/utf8"
)

type pair struct{ orig, stream string }

type blockExp struct {
	Index     int    `json:"index"`
	Type      string `json:"type"`
	Content   string `json:"content"`
	Signature string `json:"signature,omitempty"`
}

type sseGen struct {
	bg       *bodyGen // reuse text helpers
	r        *rand.Rand
	key      []byte
	secrets  []string
	buf      []byte
	events   int
	expected []blockExp
}

func (g *sseGen) event(name, data string) {
	g.buf = append(g.buf, "event: "+name+"\ndata: "+data+"\n\n"...)
	g.events++
	if g.events%97 == 0 {
		g.buf = append(g.buf, "event: ping\ndata: {\"type\": \"ping\"}\n\n"...)
		g.events++
	}
}

func q(s string) string { return `"` + jsonEscape(s, false, false) + `"` }

// pieces splits s into chunks of 1..max bytes at UTF-8 boundaries.
func (g *sseGen) pieces(s string, max int) []string {
	var out []string
	for len(s) > 0 {
		n := 1 + g.r.IntN(max)
		if n >= len(s) {
			out = append(out, s)
			break
		}
		for n < len(s) && !utf8.RuneStart(s[n]) {
			n++
		}
		out = append(out, s[:n])
		s = s[n:]
	}
	return out
}

func (g *sseGen) unknownPH() string {
	return placeholder(g.key, "not-a-registered-secret-"+randStr(g.r, base62, 10))
}

// prosePairs: text with placeholders every ~200 bytes. raw=true means the secret value is
// inserted as is (text/thinking); raw=false means JSON-escaped (inside partial_json strings).
func (g *sseGen) prosePairs(n int, inJSON bool) []pair {
	var ps []pair
	total := 0
	for total < n {
		s := g.bg.sentence()
		if inJSON {
			s = jsonEscape(s, false, false)
		}
		ps = append(ps, pair{s, s})
		total += len(s)
		if g.r.IntN(200) < len(s) {
			sec := g.secrets[g.r.IntN(len(g.secrets))]
			ph := placeholder(g.key, sec)
			o := sec
			if inJSON {
				o = jsonEscape(sec, false, false)
			}
			ps = append(ps, pair{o, ph})
			total += len(ph)
		}
		if g.r.IntN(60) == 0 {
			u := g.unknownPH()
			ps = append(ps, pair{u, u})
		}
	}
	return ps
}

func joinPairs(ps []pair) (string, string) {
	var o, s []byte
	for _, p := range ps {
		o = append(o, p.orig...)
		s = append(s, p.stream...)
	}
	return string(o), string(s)
}

func (g *sseGen) deltas(idx int, dtype, field, stream string, max int) {
	for _, p := range g.pieces(stream, max) {
		g.event("content_block_delta", fmt.Sprintf(`{"type":"content_block_delta","index":%d,"delta":{"type":"%s","%s":%s}}`, idx, dtype, field, q(p)))
	}
}

func genStream(seed uint64, targetEvents int, key []byte, secrets []string) ([]byte, []blockExp) {
	r := rand.New(rand.NewPCG(seed, 3))
	g := &sseGen{bg: &bodyGen{r: r}, r: r, key: key, secrets: secrets}
	g.event("message_start", `{"type":"message_start","message":{"id":"msg_01`+randStr(r, base62, 22)+`","type":"message","role":"assistant","model":"claude-sonnet-4-5","content":[],"stop_reason":null,"stop_sequence":null,"usage":{"input_tokens":2048,"cache_creation_input_tokens":0,"cache_read_input_tokens":0,"output_tokens":1}}}`)
	g.event("ping", `{"type": "ping"}`)
	idx := 0
	// thinking block
	{
		o, s := joinPairs(g.prosePairs(1500+r.IntN(1500), false))
		g.event("content_block_start", fmt.Sprintf(`{"type":"content_block_start","index":%d,"content_block":{"type":"thinking","thinking":"","signature":""}}`, idx))
		g.deltas(idx, "thinking_delta", "thinking", s, 24)
		sig := base64.StdEncoding.EncodeToString(randBytes(r, 300))
		// a placeholder-shaped string inside the signature must pass through untouched
		sig = sig[:100] + placeholder(key, secrets[0]) + sig[100:]
		g.event("content_block_delta", fmt.Sprintf(`{"type":"content_block_delta","index":%d,"delta":{"type":"signature_delta","signature":%s}}`, idx, q(sig)))
		g.event("content_block_stop", fmt.Sprintf(`{"type":"content_block_stop","index":%d}`, idx))
		g.expected = append(g.expected, blockExp{idx, "thinking", o, sig})
		idx++
	}
	for g.events < targetEvents-3 {
		if r.IntN(3) > 0 {
			ps := g.prosePairs(200+r.IntN(2500), false)
			if r.IntN(3) == 0 { // trailing incomplete placeholder prefix, must be flushed literally
				t := "⟦kss:" + randStr(r, "0123456789abcdef", r.IntN(12))
				ps = append(ps, pair{t, t})
			}
			o, s := joinPairs(ps)
			g.event("content_block_start", fmt.Sprintf(`{"type":"content_block_start","index":%d,"content_block":{"type":"text","text":""}}`, idx))
			g.deltas(idx, "text_delta", "text", s, 20)
			g.event("content_block_stop", fmt.Sprintf(`{"type":"content_block_stop","index":%d}`, idx))
			g.expected = append(g.expected, blockExp{Index: idx, Type: "text", Content: o})
		} else {
			sec := secrets[r.IntN(len(secrets))]
			ph := placeholder(key, sec)
			ps := []pair{{`{"command":"curl -s -H \"Authorization: Bearer `, `{"command":"curl -s -H \"Authorization: Bearer `},
				{jsonEscape(sec, false, false), ph},
				{`\" https://api.example.com/v1/items?limit=10\",\"description\":\"`, `\" https://api.example.com/v1/items?limit=10\",\"description\":\"`}}
			ps = append(ps, g.prosePairs(50+r.IntN(400), true)...)
			ps = append(ps, pair{`"}`, `"}`})
			o, s := joinPairs(ps)
			g.event("content_block_start", fmt.Sprintf(`{"type":"content_block_start","index":%d,"content_block":{"type":"tool_use","id":"toolu_01%s","name":"Bash","input":{}}}`, idx, randStr(r, base62, 22)))
			g.deltas(idx, "input_json_delta", "partial_json", s, 16)
			g.event("content_block_stop", fmt.Sprintf(`{"type":"content_block_stop","index":%d}`, idx))
			g.expected = append(g.expected, blockExp{Index: idx, Type: "tool_use", Content: o})
		}
		idx++
	}
	g.event("message_delta", fmt.Sprintf(`{"type":"message_delta","delta":{"stop_reason":"end_turn","stop_sequence":null},"usage":{"output_tokens":%d}}`, g.events*3))
	g.event("message_stop", `{"type":"message_stop"}`)
	return g.buf, g.expected
}

func genChunks(seed uint64, total int) []int {
	r := rand.New(rand.NewPCG(seed, 4))
	var out []int
	for total > 0 {
		n := min(1+r.IntN(4096), total)
		out = append(out, n)
		total -= n
	}
	return out
}
