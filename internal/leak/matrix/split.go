// SPDX-License-Identifier: AGPL-3.0-only

package matrix

import (
	"bytes"
	"encoding/json"
	"slices"
	"strings"

	"github.com/heliopsy/scrim/internal/leak"

	fp "github.com/heliopsy/scrim/internal/testing/fakeprovider"
)

// Rows that split a value into short pieces over separate requests of one
// session, for the guard's cross-request transform. The checker looks for a
// value, or a fragment of at least half of it, in one capture, so it cannot
// see such pieces; these rows name their pieces (Placement.Pieces) and the
// runner reports a leak when every piece reached the provider.

// Guard limits these rows are built around (dataplane/crates/scrim-redact,
// guard_extra.rs and guard_cross.rs).
const (
	// minPiece is the guard's default minimum length: shorter pieces are
	// invisible to its fragment index.
	minPiece = 8
	// splitSlack is how many bytes at the end of a value its pieces may leave
	// uncovered, at most a quarter of the value.
	splitSlack = 7
	// consonantRun consonants in a row make a piece read as random.
	consonantRun = 4
	// maxFragment is the longest piece the fragment rule needs to count one
	// alone.
	maxFragment = 24
)

// looksRandom mirrors the guard's rule for pieces it remembers across
// requests: a lower-case letter followed by a capital, a letter next to a
// digit, two letters or digits next to punctuation that does not join words,
// or four consonants in a row. Pieces of words are not remembered
// (docs/limitations.md), so the rows cut their pieces where each one reads as
// random.
func looksRandom(p string) bool {
	isLower := func(c byte) bool { return c >= 'a' && c <= 'z' }
	isUpper := func(c byte) bool { return c >= 'A' && c <= 'Z' }
	isDigit := func(c byte) bool { return c >= '0' && c <= '9' }
	isAlpha := func(c byte) bool { return isLower(c) || isUpper(c) }
	isAlnum := func(c byte) bool { return isAlpha(c) || isDigit(c) }
	isSymbol := func(c byte) bool {
		return c > ' ' && c < 0x7f && !isAlnum(c) && !strings.ContainsRune("-_./:,", rune(c))
	}
	run, symbols := 0, 0
	var prev byte
	for i := 0; i < len(p); i++ {
		c := p[i]
		if (isLower(prev) && isUpper(c)) || (isAlpha(prev) && isDigit(c)) || (isDigit(prev) && isAlpha(c)) {
			return true
		}
		if (isAlnum(prev) && isSymbol(c)) || (isSymbol(prev) && isAlnum(c)) {
			if symbols++; symbols >= 2 {
				return true
			}
		}
		if isAlpha(c) && !strings.ContainsRune("aeiouyAEIOUY", rune(c)) {
			if run++; run >= consonantRun {
				return true
			}
		} else {
			run = 0
		}
		prev = c
	}
	return false
}

// shortPieces cuts v into three pieces the guard sees but no single one of
// which it counts alone: each of at least minPiece bytes and below half of
// v (or reaching beyond what the fragment rule looks at, for long values),
// except a last piece short enough to be left uncovered. Cuts move by up to
// three bytes so every counted piece reads as random. A value too short to
// cut, or without such cuts, is one piece.
func shortPieces(v string) []string {
	n := len(v)
	if n < 2*minPiece {
		return []string{v}
	}
	size := max(minPiece, (n+2)/3)
	slack := min(splitSlack, n/4)
	ok := func(a, b int) bool {
		// Below half the value, where the guard would count it alone, unless
		// the value is too long for three such pieces.
		if b-a < minPiece || (2*(b-a) >= n && b-a < maxFragment) {
			return false
		}
		return looksRandom(v[a:b])
	}
	c1, c2, found := randomCuts(size, n, slack, ok)
	if !found {
		// The guard does not join pieces that read as words (an AWS access
		// key ID's letters between its digits can): such a value is sent
		// whole, as the redactor's rows already test.
		return []string{v}
	}
	out := []string{v[:c1], v[c1:c2], v[c2:]}
	if out[2] == "" {
		out = out[:2]
	}
	return out
}

// randomCuts finds two cuts within three bytes of size and 2*size where ok
// holds for each counted piece (the last one only when longer than slack).
func randomCuts(size, n, slack int, ok func(a, b int) bool) (int, int, bool) {
	for d1 := 0; d1 <= 3; d1++ {
		for _, c1 := range []int{size + d1, size - d1} {
			for d2 := 0; d2 <= 3; d2++ {
				for _, c2 := range []int{min(2*size+d2, n), min(2*size-d2, n)} {
					if c1 <= 0 || c2 <= c1 || !ok(0, c1) || !ok(c1, c2) {
						continue
					}
					if n-c2 > slack && !ok(c2, n) {
						continue
					}
					return c1, c2, true
				}
			}
		}
	}
	return 0, 0, false
}

// pieceTurns builds one request per group of tool outputs, chained by
// previous_response_id in the Responses API and sent on one socket in its
// WebSocket mode. nil for APIs without a plain tool turn (Realtime).
func pieceTurns(api fp.API, mode Escape, outputs []string) []Request {
	var reqs []Request
	for i, out := range outputs {
		cmd := "sed -n " + string(rune('1'+i)) + "p .env"
		switch api {
		case fp.Anthropic:
			reqs = append(reqs, req(api, anthropicParts{messages: anthropicToolTurn(cmd, out)}.body(), mode, false))
		case fp.OpenAIChat:
			reqs = append(reqs, req(api, chatParts{messages: chatToolTurn(cmd, out)}.body(), mode, false))
		case fp.Gemini:
			reqs = append(reqs, req(api, geminiParts{contents: geminiToolTurn(cmd, obj("output", out))}.body(), mode, false))
		case fp.OpenAIResponses, fp.OpenAIResponsesWS:
			p := responsesParts{input: responsesToolTurn(cmd, out), extra: []kv{{"store", true}}}
			if i > 0 {
				p.input = []any{
					obj("type", "function_call", "call_id", callID, "name", toolName, "arguments", `{"command":"`+cmd+`"}`),
					obj("type", "function_call_output", "call_id", callID, "output", out),
				}
				p.extra = append(p.extra, kv{"previous_response_id", "resp_previous"})
			}
			reqs = append(reqs, req(api, p.body(), mode, false))
		default:
			return nil
		}
	}
	if api == fp.OpenAIResponsesWS && len(reqs) > 1 {
		for _, r := range reqs[1:] {
			reqs[0].Messages = append(reqs[0].Messages, r.Messages...)
		}
		return reqs[:1]
	}
	return reqs
}

// splitOutputs turns the pieces into tool outputs, the first with the text
// before the value and the last with the text after it. groups lists, per
// request, which pieces it carries.
func splitOutputs(c Content, groups [][]int) []string {
	pieces := shortPieces(c.Value)
	var outs []string
	for _, g := range groups {
		var parts []string
		for _, k := range g {
			if k < len(pieces) {
				parts = append(parts, pieces[k])
			}
		}
		if len(parts) == 0 {
			continue
		}
		// Words between pieces of one request: the checker compares a value's
		// letters and digits with the text's, symbols and spaces dropped, and
		// two pieces with only punctuation between them could read as one run.
		outs = append(outs, strings.Join(parts, "\n... skipped lines ...\n"))
	}
	if len(outs) == 0 {
		return nil
	}
	outs[0] = c.Before + outs[0]
	outs[len(outs)-1] += c.After
	return outs
}

const splitNote = "pieces are remembered per session only for values whose pieces read as random, and per replica"

var splitPlacements = []Placement{
	{ID: "split-requests-2", Desc: "the value in three short pieces over two requests: the first and last piece in one, the middle in the next (chained by previous_response_id, two events on one socket in the WebSocket mode)",
		Expect: Guard, Note: splitNote, Transforms: []string{"raw", "reversed"}, Pieces: shortPieces,
		Build: func(api fp.API, c Content, mode Escape) []Request {
			return pieceTurns(api, mode, splitOutputs(c, [][]int{{0, 2}, {1}}))
		}},
	{ID: "split-requests-3", Desc: "the value in three short pieces, one per request over three requests (chained by previous_response_id, three events on one socket in the WebSocket mode)",
		Expect: Guard, Note: splitNote, Transforms: []string{"raw", "reversed"}, Pieces: shortPieces,
		Build: func(api fp.API, c Content, mode Escape) []Request {
			return pieceTurns(api, mode, splitOutputs(c, [][]int{{0}, {1}, {2}}))
		}},
}

// The split rows go right after split-requests in the catalogue.
func init() {
	at := slices.IndexFunc(Placements, func(p Placement) bool { return p.ID == "split-requests" })
	Placements = slices.Insert(Placements, at+1, splitPlacements...)
}

// piecesLeaked reports a finding when every one of several pieces reached
// the provider in some exchange, as sent or JSON-escaped.
func piecesLeaked(pieces []string, ex []fp.Exchange, seed leak.Seed) (leak.Finding, bool) {
	if len(pieces) < 2 {
		return leak.Finding{}, false
	}
	total := 0
	for _, p := range pieces {
		forms := [][]byte{[]byte(p), jsonInner(p)}
		found := false
		for _, e := range ex {
			for _, f := range forms {
				found = found || bytes.Contains(e.Body, f)
			}
		}
		if !found {
			return leak.Finding{}, false
		}
		total += len(p)
	}
	return leak.Finding{Seed: seed.Ref(), Request: 0, Location: "body", Encodings: []string{"split-across-requests"},
		Match: "exact", Matched: total}, true
}

// jsonInner is s as it appears inside a JSON string.
func jsonInner(s string) []byte {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(s)
	out := bytes.TrimSpace(b.Bytes())
	return out[1 : len(out)-1]
}
