// SPDX-License-Identifier: AGPL-3.0-only

package scenario

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/heliopsy/scrim/internal/leak"
	"github.com/heliopsy/scrim/internal/leak/matrix"
	fp "github.com/heliopsy/scrim/internal/testing/fakeprovider"
)

const systemPrompt = "You are a coding agent. Use the tools to inspect the user's project."

// maxTurns bounds a session in case a proxy breaks the tool loop.
const maxTurns = 12

func marshal(v any) []byte {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
	return bytes.TrimSuffix(b.Bytes(), []byte("\n"))
}

func toolSchema(name string) (desc string, params map[string]any) {
	switch name {
	case "Read":
		return "Read a file from the workspace.", map[string]any{"type": "object", "properties": map[string]any{"file_path": map[string]any{"type": "string"}}, "required": []any{"file_path"}}
	case "mcp__vault__read_secret":
		return "Read a secret document from Vault (MCP server vault).", map[string]any{"type": "object", "properties": map[string]any{"path": map[string]any{"type": "string"}}, "required": []any{"path"}}
	}
	return "Run a shell command.", map[string]any{"type": "object", "properties": map[string]any{"command": map[string]any{"type": "string"}}, "required": []any{"command"}}
}

var toolNames = []string{"Bash", "Read", "mcp__vault__read_secret"}

// conversation is an agent's history in one API's shape.
type conversation struct {
	api    fp.API
	stream bool
	items  []any
}

func (c *conversation) user(text string) {
	switch c.api {
	case fp.OpenAIResponses:
		c.items = append(c.items, map[string]any{"type": "message", "role": "user", "content": []any{map[string]any{"type": "input_text", "text": text}}})
	case fp.Gemini:
		c.items = append(c.items, map[string]any{"role": "user", "parts": []any{map[string]any{"text": text}}})
	default:
		c.items = append(c.items, map[string]any{"role": "user", "content": text})
	}
}

// assistant appends a reply as the agent received it.
func (c *conversation) assistant(p fp.Parsed) {
	switch c.api {
	case fp.Anthropic:
		var content []any
		if p.Text != "" {
			content = append(content, map[string]any{"type": "text", "text": p.Text})
		}
		for _, tc := range p.ToolCalls {
			content = append(content, map[string]any{"type": "tool_use", "id": tc.ID, "name": tc.Name, "input": json.RawMessage(orEmpty(tc.Arguments))})
		}
		c.items = append(c.items, map[string]any{"role": "assistant", "content": content})
	case fp.OpenAIChat:
		m := map[string]any{"role": "assistant", "content": nil}
		if p.Text != "" {
			m["content"] = p.Text
		}
		var calls []any
		for _, tc := range p.ToolCalls {
			calls = append(calls, map[string]any{"id": tc.ID, "type": "function", "function": map[string]any{"name": tc.Name, "arguments": tc.Arguments}})
		}
		if calls != nil {
			m["tool_calls"] = calls
		}
		c.items = append(c.items, m)
	case fp.OpenAIResponses:
		if p.Text != "" {
			c.items = append(c.items, map[string]any{"type": "message", "role": "assistant", "content": []any{map[string]any{"type": "output_text", "text": p.Text}}})
		}
		for _, tc := range p.ToolCalls {
			c.items = append(c.items, map[string]any{"type": "function_call", "call_id": tc.ID, "name": tc.Name, "arguments": tc.Arguments})
		}
	case fp.Gemini:
		var parts []any
		if p.Text != "" {
			parts = append(parts, map[string]any{"text": p.Text})
		}
		for _, tc := range p.ToolCalls {
			call := map[string]any{"name": tc.Name, "args": json.RawMessage(orEmpty(tc.Arguments))}
			if tc.ID != "" {
				call["id"] = tc.ID
			}
			part := map[string]any{"functionCall": call}
			// The signature goes back unchanged with its call, as Gemini
			// requires for thinking models.
			if tc.Signature != "" {
				part["thoughtSignature"] = tc.Signature
			}
			parts = append(parts, part)
		}
		c.items = append(c.items, map[string]any{"role": "model", "parts": parts})
	}
}

func orEmpty(s string) string {
	if strings.TrimSpace(s) == "" {
		return "{}"
	}
	return s
}

func (c *conversation) toolResults(calls []fp.ParsedCall, outputs []string) {
	switch c.api {
	case fp.Anthropic:
		var content []any
		for i, tc := range calls {
			content = append(content, map[string]any{"type": "tool_result", "tool_use_id": tc.ID, "content": outputs[i]})
		}
		c.items = append(c.items, map[string]any{"role": "user", "content": content})
	case fp.OpenAIChat:
		for i, tc := range calls {
			c.items = append(c.items, map[string]any{"role": "tool", "tool_call_id": tc.ID, "content": outputs[i]})
		}
	case fp.OpenAIResponses:
		for i, tc := range calls {
			c.items = append(c.items, map[string]any{"type": "function_call_output", "call_id": tc.ID, "output": outputs[i]})
		}
	case fp.Gemini:
		// Gemini ties a functionResponse to its call by name (and by id
		// when the call had one), all of a turn's responses in one content.
		var parts []any
		for i, tc := range calls {
			resp := map[string]any{"name": tc.Name, "response": map[string]any{"output": outputs[i]}}
			if tc.ID != "" {
				resp["id"] = tc.ID
			}
			parts = append(parts, map[string]any{"functionResponse": resp})
		}
		c.items = append(c.items, map[string]any{"role": "user", "parts": parts})
	}
}

func (c *conversation) request() matrix.Request {
	var tools []any
	for _, n := range toolNames {
		desc, params := toolSchema(n)
		switch c.api {
		case fp.Anthropic:
			tools = append(tools, map[string]any{"name": n, "description": desc, "input_schema": params})
		case fp.OpenAIChat:
			tools = append(tools, map[string]any{"type": "function", "function": map[string]any{"name": n, "description": desc, "parameters": params}})
		case fp.OpenAIResponses:
			tools = append(tools, map[string]any{"type": "function", "name": n, "description": desc, "parameters": params})
		case fp.Gemini:
			tools = append(tools, map[string]any{"name": n, "description": desc, "parameters": params})
		}
	}
	var body map[string]any
	switch c.api {
	case fp.Anthropic:
		body = map[string]any{"model": "claude-sonnet-4-5", "max_tokens": 4096, "system": []any{map[string]any{"type": "text", "text": systemPrompt, "cache_control": map[string]any{"type": "ephemeral"}}}, "tools": tools, "messages": c.items}
	case fp.OpenAIChat:
		msgs := append([]any{map[string]any{"role": "system", "content": systemPrompt}}, c.items...)
		body = map[string]any{"model": "gpt-5", "messages": msgs, "tools": tools}
	case fp.OpenAIResponses:
		body = map[string]any{"model": "gpt-5", "instructions": systemPrompt, "input": c.items, "tools": tools, "store": false}
	case fp.Gemini:
		// Gemini declares every function in one tools entry and streams by
		// path, not by a body field.
		body = map[string]any{
			"systemInstruction": map[string]any{"parts": []any{map[string]any{"text": systemPrompt}}},
			"tools":             []any{map[string]any{"functionDeclarations": tools}},
			"contents":          c.items,
			"generationConfig":  map[string]any{"maxOutputTokens": 4096, "thinkingConfig": map[string]any{"includeThoughts": false}},
		}
	}
	if c.stream && c.api != fp.Gemini {
		body["stream"] = true
	}
	h := http.Header{"Content-Type": {"application/json"}}
	if c.api == fp.Anthropic {
		h.Set("Anthropic-Version", "2023-06-01")
	}
	r := matrix.Request{API: c.api, Path: c.api.Path(), Header: h, Body: marshal(body), Stream: c.stream}
	if c.stream {
		r.Path, r.Query = c.api.StreamPath(true)
	}
	return r
}

// session is what one run of a scenario did.
type session struct {
	requests int
	// restored counts tool calls in which the agent received a seed value,
	// that is, the proxy resolved a placeholder into the call.
	restored int
	err      error
}

func runSession(ctx context.Context, t matrix.Target, sc Scenario, api fp.API, stream bool, seeds []leak.Seed) session {
	var s session
	byKind := seedsByKind(seeds)
	prompt, err := Render(sc.Prompt, byKind)
	if err != nil {
		s.err = err
		return s
	}
	conv := &conversation{api: api, stream: stream}
	conv.user(prompt)
	for turn := 0; turn < maxTurns; turn++ {
		req := conv.request()
		status, body, err := t.Send(ctx, req)
		s.requests++
		if err != nil {
			s.err = fmt.Errorf("turn %d: %w", turn, err)
			return s
		}
		if status != http.StatusOK {
			s.err = fmt.Errorf("turn %d: proxy answered %d", turn, status)
			return s
		}
		p, err := fp.ParseReply(api, stream, body)
		if err != nil {
			s.err = fmt.Errorf("turn %d: parse reply: %w", turn, err)
			return s
		}
		conv.assistant(p)
		if len(p.ToolCalls) == 0 {
			return s
		}
		outputs := make([]string, len(p.ToolCalls))
		for i, tc := range p.ToolCalls {
			for _, seed := range seeds {
				if strings.Contains(tc.Arguments, seed.Value()) {
					s.restored++
					break
				}
			}
			if turn < len(sc.Steps) {
				out, err := Render(sc.Steps[turn].Output, byKind)
				if err != nil {
					s.err = err
					return s
				}
				outputs[i] = out
			}
		}
		conv.toolResults(p.ToolCalls, outputs)
	}
	s.err = fmt.Errorf("session did not finish in %d turns", maxTurns)
	return s
}
