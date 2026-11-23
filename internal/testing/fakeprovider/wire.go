// SPDX-License-Identifier: AGPL-3.0-only

package fakeprovider

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// gen writes replies in each API's wire format.
type gen struct {
	// idSeed makes reply IDs a function of the request, so the same
	// conversation replayed gets the same IDs and stays cacheable.
	idSeed string
	n      int
	chunk  int
	model  string
	input  int
	cached int
}

func (g *gen) id(prefix string) string {
	g.n++
	return StableID(prefix, fmt.Sprintf("%s/%d", g.idSeed, g.n))
}

func (g *gen) pieces(s string) []string {
	r := []rune(s)
	if len(r) == 0 {
		return nil
	}
	var out []string
	for i := 0; i < len(r); i += g.chunk {
		out = append(out, string(r[i:min(i+g.chunk, len(r))]))
	}
	return out
}

func outputTokens(r Reply) int {
	n := len(r.Text) / 4
	for _, tc := range r.ToolCalls {
		b, _ := json.Marshal(tc.Input)
		n += len(b) / 4
	}
	return max(1, n)
}

type sse struct {
	w http.ResponseWriter
	f http.Flusher
}

func newSSE(w http.ResponseWriter) *sse {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	f, _ := w.(http.Flusher)
	return &sse{w: w, f: f}
}

func (s *sse) event(name string, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		b = []byte(`{}`)
	}
	if name != "" {
		_, _ = fmt.Fprintf(s.w, "event: %s\n", name)
	}
	_, _ = fmt.Fprintf(s.w, "data: %s\n\n", b)
	if s.f != nil {
		s.f.Flush()
	}
}

func (s *sse) raw(line string) {
	_, _ = fmt.Fprint(s.w, line)
	if s.f != nil {
		s.f.Flush()
	}
}

func inputJSON(tc ToolCall) string {
	in := tc.Input
	if in == nil {
		in = map[string]any{}
	}
	b, _ := json.Marshal(in)
	return string(b)
}

// Anthropic Messages.

func (g *gen) anthropicUsage(out int) map[string]any {
	return map[string]any{
		"input_tokens":                max(1, g.input-g.cached),
		"cache_creation_input_tokens": 0,
		"cache_read_input_tokens":     g.cached,
		"output_tokens":               out,
	}
}

func (g *gen) anthropic(w http.ResponseWriter, r Reply, stream bool) {
	id := g.id("msg_")
	stop := "end_turn"
	if len(r.ToolCalls) > 0 {
		stop = "tool_use"
	}
	type block struct {
		typ   string
		text  string
		id    string
		name  string
		input string
	}
	var blocks []block
	if r.Text != "" {
		blocks = append(blocks, block{typ: "text", text: r.Text})
	}
	for _, tc := range r.ToolCalls {
		blocks = append(blocks, block{typ: "tool_use", id: g.id("toolu_"), name: tc.Name, input: inputJSON(tc)})
	}
	out := outputTokens(r)
	if !stream {
		content := []any{}
		for _, b := range blocks {
			if b.typ == "text" {
				content = append(content, map[string]any{"type": "text", "text": b.text})
				continue
			}
			content = append(content, map[string]any{"type": "tool_use", "id": b.id, "name": b.name, "input": json.RawMessage(b.input)})
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"id": id, "type": "message", "role": "assistant", "model": g.model,
			"content": content, "stop_reason": stop, "stop_sequence": nil,
			"usage": g.anthropicUsage(out),
		})
		return
	}
	s := newSSE(w)
	start := g.anthropicUsage(1)
	s.event("message_start", map[string]any{"type": "message_start", "message": map[string]any{
		"id": id, "type": "message", "role": "assistant", "model": g.model, "content": []any{},
		"stop_reason": nil, "stop_sequence": nil, "usage": start,
	}})
	s.event("ping", map[string]any{"type": "ping"})
	for i, b := range blocks {
		if b.typ == "text" {
			s.event("content_block_start", map[string]any{"type": "content_block_start", "index": i, "content_block": map[string]any{"type": "text", "text": ""}})
			for _, p := range g.pieces(b.text) {
				s.event("content_block_delta", map[string]any{"type": "content_block_delta", "index": i, "delta": map[string]any{"type": "text_delta", "text": p}})
			}
		} else {
			s.event("content_block_start", map[string]any{"type": "content_block_start", "index": i, "content_block": map[string]any{"type": "tool_use", "id": b.id, "name": b.name, "input": map[string]any{}}})
			for _, p := range g.pieces(b.input) {
				s.event("content_block_delta", map[string]any{"type": "content_block_delta", "index": i, "delta": map[string]any{"type": "input_json_delta", "partial_json": p}})
			}
		}
		s.event("content_block_stop", map[string]any{"type": "content_block_stop", "index": i})
	}
	s.event("message_delta", map[string]any{"type": "message_delta", "delta": map[string]any{"stop_reason": stop, "stop_sequence": nil}, "usage": map[string]any{"output_tokens": out}})
	s.event("message_stop", map[string]any{"type": "message_stop"})
}

// OpenAI Chat Completions.

func (g *gen) chatUsage(out int) map[string]any {
	return map[string]any{
		"prompt_tokens": g.input, "completion_tokens": out, "total_tokens": g.input + out,
		"prompt_tokens_details":     map[string]any{"cached_tokens": g.cached, "audio_tokens": 0},
		"completion_tokens_details": map[string]any{"reasoning_tokens": 0, "audio_tokens": 0, "accepted_prediction_tokens": 0, "rejected_prediction_tokens": 0},
	}
}

func (g *gen) chat(w http.ResponseWriter, r Reply, stream, includeUsage bool) {
	id := g.id("chatcmpl-")
	created := time.Now().Unix()
	finish := "stop"
	if len(r.ToolCalls) > 0 {
		finish = "tool_calls"
	}
	type call struct{ id, name, args string }
	var calls []call
	for _, tc := range r.ToolCalls {
		calls = append(calls, call{g.id("call_"), tc.Name, inputJSON(tc)})
	}
	out := outputTokens(r)
	if !stream {
		msg := map[string]any{"role": "assistant", "content": nil, "refusal": nil}
		if r.Text != "" {
			msg["content"] = r.Text
		}
		if len(calls) > 0 {
			var tcs []any
			for _, c := range calls {
				tcs = append(tcs, map[string]any{"id": c.id, "type": "function", "function": map[string]any{"name": c.name, "arguments": c.args}})
			}
			msg["tool_calls"] = tcs
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"id": id, "object": "chat.completion", "created": created, "model": g.model,
			"choices":            []any{map[string]any{"index": 0, "message": msg, "logprobs": nil, "finish_reason": finish}},
			"usage":              g.chatUsage(out),
			"system_fingerprint": "fp_fake",
		})
		return
	}
	s := newSSE(w)
	chunk := func(delta map[string]any, finish any) {
		s.event("", map[string]any{
			"id": id, "object": "chat.completion.chunk", "created": created, "model": g.model, "system_fingerprint": "fp_fake",
			"choices": []any{map[string]any{"index": 0, "delta": delta, "logprobs": nil, "finish_reason": finish}},
		})
	}
	chunk(map[string]any{"role": "assistant", "content": "", "refusal": nil}, nil)
	for _, p := range g.pieces(r.Text) {
		chunk(map[string]any{"content": p}, nil)
	}
	for i, c := range calls {
		chunk(map[string]any{"tool_calls": []any{map[string]any{"index": i, "id": c.id, "type": "function", "function": map[string]any{"name": c.name, "arguments": ""}}}}, nil)
		for _, p := range g.pieces(c.args) {
			chunk(map[string]any{"tool_calls": []any{map[string]any{"index": i, "function": map[string]any{"arguments": p}}}}, nil)
		}
	}
	chunk(map[string]any{}, finish)
	if includeUsage {
		s.event("", map[string]any{
			"id": id, "object": "chat.completion.chunk", "created": created, "model": g.model,
			"choices": []any{}, "usage": g.chatUsage(out),
		})
	}
	s.raw("data: [DONE]\n\n")
}

// OpenAI Responses.

func (g *gen) responsesUsage(out int) map[string]any {
	return map[string]any{
		"input_tokens": g.input, "input_tokens_details": map[string]any{"cached_tokens": g.cached},
		"output_tokens": out, "output_tokens_details": map[string]any{"reasoning_tokens": 0},
		"total_tokens": g.input + out,
	}
}

func (g *gen) responses(w http.ResponseWriter, r Reply, stream bool) {
	id := g.id("resp_")
	created := time.Now().Unix()
	type item struct {
		m    map[string]any
		text string
		args string
	}
	var items []item
	if r.Text != "" {
		items = append(items, item{m: map[string]any{
			"type": "message", "id": g.id("msg_"), "status": "completed", "role": "assistant",
			"content": []any{map[string]any{"type": "output_text", "text": r.Text, "annotations": []any{}}},
		}, text: r.Text})
	}
	for _, tc := range r.ToolCalls {
		args := inputJSON(tc)
		m := map[string]any{
			"type": "function_call", "id": g.id("fc_"), "call_id": g.id("call_"), "name": tc.Name,
			"arguments": args, "status": "completed",
		}
		if tc.Namespace != "" {
			m["namespace"] = tc.Namespace
		}
		items = append(items, item{m: m, args: args})
	}
	out := outputTokens(r)
	full := func(status string, withOutput bool) map[string]any {
		output := []any{}
		if withOutput {
			for _, it := range items {
				output = append(output, it.m)
			}
		}
		resp := map[string]any{
			"id": id, "object": "response", "created_at": created, "status": status, "model": g.model,
			"output": output, "parallel_tool_calls": true, "tool_choice": "auto", "tools": []any{},
			"error": nil, "incomplete_details": nil, "usage": nil,
		}
		if status == "completed" {
			resp["usage"] = g.responsesUsage(out)
		}
		return resp
	}
	if !stream {
		writeJSON(w, http.StatusOK, full("completed", true))
		return
	}
	s := newSSE(w)
	seq := 0
	ev := func(name string, v map[string]any) {
		v["type"] = name
		v["sequence_number"] = seq
		seq++
		s.event(name, v)
	}
	ev("response.created", map[string]any{"response": full("in_progress", false)})
	ev("response.in_progress", map[string]any{"response": full("in_progress", false)})
	for oi, it := range items {
		itemID := it.m["id"]
		if it.m["type"] == "message" {
			added := map[string]any{"type": "message", "id": itemID, "status": "in_progress", "role": "assistant", "content": []any{}}
			ev("response.output_item.added", map[string]any{"output_index": oi, "item": added})
			ev("response.content_part.added", map[string]any{"item_id": itemID, "output_index": oi, "content_index": 0, "part": map[string]any{"type": "output_text", "text": "", "annotations": []any{}}})
			for _, p := range g.pieces(it.text) {
				ev("response.output_text.delta", map[string]any{"item_id": itemID, "output_index": oi, "content_index": 0, "delta": p, "logprobs": []any{}})
			}
			ev("response.output_text.done", map[string]any{"item_id": itemID, "output_index": oi, "content_index": 0, "text": it.text, "logprobs": []any{}})
			ev("response.content_part.done", map[string]any{"item_id": itemID, "output_index": oi, "content_index": 0, "part": map[string]any{"type": "output_text", "text": it.text, "annotations": []any{}}})
		} else {
			added := map[string]any{"type": "function_call", "id": itemID, "call_id": it.m["call_id"], "name": it.m["name"], "arguments": "", "status": "in_progress"}
			if ns, ok := it.m["namespace"]; ok {
				added["namespace"] = ns
			}
			ev("response.output_item.added", map[string]any{"output_index": oi, "item": added})
			for _, p := range g.pieces(it.args) {
				ev("response.function_call_arguments.delta", map[string]any{"item_id": itemID, "output_index": oi, "delta": p})
			}
			ev("response.function_call_arguments.done", map[string]any{"item_id": itemID, "output_index": oi, "arguments": it.args})
		}
		ev("response.output_item.done", map[string]any{"output_index": oi, "item": it.m})
	}
	ev("response.completed", map[string]any{"response": full("completed", true)})
}

// Google Gemini.

func (g *gen) geminiUsage(out int) map[string]any {
	return map[string]any{
		"promptTokenCount":        g.input,
		"candidatesTokenCount":    out,
		"totalTokenCount":         g.input + out,
		"cachedContentTokenCount": g.cached,
		"promptTokensDetails":     []any{map[string]any{"modality": "TEXT", "tokenCount": g.input}},
	}
}

// gemini writes a GenerateContentResponse, or a stream of them: server-sent
// events (alt=sse) or a JSON array flushed element by element, as the real
// API sends either. Text arrives in small deltas, one per chunk, so
// placeholders split across chunks; a functionCall part arrives whole. The
// first functionCall part carries a thoughtSignature, which the client must
// send back unchanged with the call.
func (g *gen) gemini(w http.ResponseWriter, r Reply, stream, sse bool) {
	respID := g.id("")[:22]
	var calls []map[string]any
	for i, tc := range r.ToolCalls {
		in := tc.Input
		if in == nil {
			in = map[string]any{}
		}
		p := map[string]any{"functionCall": map[string]any{"name": tc.Name, "args": in}}
		if i == 0 {
			p["thoughtSignature"] = base64.StdEncoding.EncodeToString([]byte(g.id("sig_")))
		}
		calls = append(calls, p)
	}
	out := outputTokens(r)
	chunk := func(parts []any, last bool) map[string]any {
		cand := map[string]any{"content": map[string]any{"role": "model", "parts": parts}, "index": 0}
		m := map[string]any{"candidates": []any{cand}, "modelVersion": g.model, "responseId": respID}
		if last {
			cand["finishReason"] = "STOP"
			m["usageMetadata"] = g.geminiUsage(out)
		}
		return m
	}
	if !stream {
		parts := []any{}
		if r.Text != "" {
			parts = append(parts, map[string]any{"text": r.Text})
		}
		for _, c := range calls {
			parts = append(parts, c)
		}
		writeJSON(w, http.StatusOK, chunk(parts, true))
		return
	}
	var chunks [][]any
	for _, p := range g.pieces(r.Text) {
		chunks = append(chunks, []any{map[string]any{"text": p}})
	}
	for _, c := range calls {
		chunks = append(chunks, []any{c})
	}
	if len(chunks) == 0 {
		chunks = append(chunks, []any{map[string]any{"text": ""}})
	}
	f, _ := w.(http.Flusher)
	write := func(s string) {
		_, _ = fmt.Fprint(w, s)
		if f != nil {
			f.Flush()
		}
	}
	if sse {
		w.Header().Set("Content-Type", "text/event-stream")
	} else {
		w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	}
	w.WriteHeader(http.StatusOK)
	for i, parts := range chunks {
		b, err := json.Marshal(chunk(parts, i == len(chunks)-1))
		if err != nil {
			b = []byte(`{}`)
		}
		switch {
		case sse:
			write("data: " + string(b) + "\r\n\r\n")
		case i == 0:
			write("[" + string(b) + "\r\n")
		default:
			write("," + string(b) + "\r\n")
		}
	}
	if !sse {
		write("]")
	}
}
