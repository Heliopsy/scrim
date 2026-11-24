// SPDX-License-Identifier: AGPL-3.0-only

package fakeprovider

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
)

// ParsedCall is a tool call as an agent receives it.
type ParsedCall struct {
	ID   string
	Name string
	// Arguments is the raw JSON of the call input.
	Arguments string
	// Signature is a Gemini functionCall part's thoughtSignature, which the
	// client sends back unchanged with the call. Empty elsewhere.
	Signature string
}

// Parsed is a reply as an agent receives it, reassembled from either wire
// form.
type Parsed struct {
	Text      string
	ToolCalls []ParsedCall
	// Events lists the stream event types in order, empty when not
	// streamed.
	Events []string
	// Errors lists the code (or, without one, the message) of every error
	// event of a WebSocket conversation, in order.
	Errors []string
}

// ParseReply reassembles a reply body of the given API, streamed or not. A
// streamed Gemini reply may be server-sent events or a JSON array; the body
// tells which. Gemini function calls carry no ID unless the provider sent one.
//
// For a WebSocket API the body is the server events of a conversation, one
// JSON value after another (the form [Exchange].Response and the bypass
// matrix's Target use, one per line); stream is ignored.
func ParseReply(api API, stream bool, body []byte) (Parsed, error) {
	if api.WebSocket() {
		var msgs [][]byte
		dec := json.NewDecoder(bytes.NewReader(body))
		for {
			var raw json.RawMessage
			if err := dec.Decode(&raw); err != nil {
				if errors.Is(err, io.EOF) {
					break
				}
				return Parsed{}, fmt.Errorf("server event %d: %w", len(msgs)+1, err)
			}
			msgs = append(msgs, raw)
		}
		return ParseEvents(api, msgs)
	}
	if api == Gemini {
		return parseGemini(stream, body)
	}
	if !stream {
		return parseJSON(api, body)
	}
	return parseSSE(api, body)
}

func parseJSON(api API, body []byte) (Parsed, error) {
	var p Parsed
	switch api {
	case Anthropic:
		var m struct {
			Content []struct {
				Type  string          `json:"type"`
				Text  string          `json:"text"`
				ID    string          `json:"id"`
				Name  string          `json:"name"`
				Input json.RawMessage `json:"input"`
			} `json:"content"`
		}
		if err := json.Unmarshal(body, &m); err != nil {
			return p, err
		}
		for _, c := range m.Content {
			switch c.Type {
			case "text":
				p.Text += c.Text
			case "tool_use":
				p.ToolCalls = append(p.ToolCalls, ParsedCall{ID: c.ID, Name: c.Name, Arguments: string(c.Input)})
			}
		}
	case OpenAIChat:
		var m struct {
			Choices []struct {
				Message struct {
					Content   *string `json:"content"`
					ToolCalls []struct {
						ID       string `json:"id"`
						Function struct {
							Name      string `json:"name"`
							Arguments string `json:"arguments"`
						} `json:"function"`
					} `json:"tool_calls"`
				} `json:"message"`
			} `json:"choices"`
		}
		if err := json.Unmarshal(body, &m); err != nil {
			return p, err
		}
		if len(m.Choices) == 0 {
			return p, errors.New("no choices")
		}
		msg := m.Choices[0].Message
		if msg.Content != nil {
			p.Text = *msg.Content
		}
		for _, tc := range msg.ToolCalls {
			p.ToolCalls = append(p.ToolCalls, ParsedCall{ID: tc.ID, Name: tc.Function.Name, Arguments: tc.Function.Arguments})
		}
	case OpenAIResponses:
		var m struct {
			Output []responsesItem `json:"output"`
		}
		if err := json.Unmarshal(body, &m); err != nil {
			return p, err
		}
		for _, it := range m.Output {
			p.add(it)
		}
	default:
		return p, fmt.Errorf("unknown api %q", api)
	}
	return p, nil
}

type responsesItem struct {
	Type    string `json:"type"`
	ID      string `json:"id"`
	CallID  string `json:"call_id"`
	Name    string `json:"name"`
	Args    string `json:"arguments"`
	Content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
}

func (p *Parsed) add(it responsesItem) {
	switch it.Type {
	case "message":
		for _, c := range it.Content {
			if c.Type == "output_text" {
				p.Text += c.Text
			}
		}
	case "function_call":
		p.ToolCalls = append(p.ToolCalls, ParsedCall{ID: it.CallID, Name: it.Name, Arguments: it.Args})
	}
}

// sseEvents splits an SSE body into (event, data) pairs.
func sseEvents(body []byte) ([][2]string, error) {
	var out [][2]string
	sc := bufio.NewScanner(bytes.NewReader(body))
	sc.Buffer(make([]byte, 0, 64<<10), 64<<20)
	var name string
	var data []string
	flush := func() {
		if len(data) > 0 {
			out = append(out, [2]string{name, strings.Join(data, "\n")})
		}
		name, data = "", nil
	}
	for sc.Scan() {
		line := sc.Text()
		switch {
		case line == "":
			flush()
		case strings.HasPrefix(line, ":"):
		case strings.HasPrefix(line, "event:"):
			name = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
		case strings.HasPrefix(line, "data:"):
			data = append(data, strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " "))
		}
	}
	flush()
	return out, sc.Err()
}

func parseSSE(api API, body []byte) (Parsed, error) {
	var p Parsed
	evs, err := sseEvents(body)
	if err != nil {
		return p, err
	}
	type acc struct {
		id, name string
		args     strings.Builder
	}
	calls := map[int]*acc{}
	for _, e := range evs {
		if e[1] == "[DONE]" {
			p.Events = append(p.Events, "[DONE]")
			continue
		}
		var m map[string]json.RawMessage
		if err := json.Unmarshal([]byte(e[1]), &m); err != nil {
			return p, fmt.Errorf("event %q: %w", e[0], err)
		}
		var typ string
		_ = json.Unmarshal(m["type"], &typ)
		switch api {
		case Anthropic:
			p.Events = append(p.Events, typ)
			var ev struct {
				Index        int `json:"index"`
				ContentBlock struct {
					Type string `json:"type"`
					ID   string `json:"id"`
					Name string `json:"name"`
				} `json:"content_block"`
				Delta struct {
					Type        string `json:"type"`
					Text        string `json:"text"`
					PartialJSON string `json:"partial_json"`
				} `json:"delta"`
			}
			_ = json.Unmarshal([]byte(e[1]), &ev)
			switch typ {
			case "content_block_start":
				if ev.ContentBlock.Type == "tool_use" {
					calls[ev.Index] = &acc{id: ev.ContentBlock.ID, name: ev.ContentBlock.Name}
				}
			case "content_block_delta":
				switch ev.Delta.Type {
				case "text_delta":
					p.Text += ev.Delta.Text
				case "input_json_delta":
					if c := calls[ev.Index]; c != nil {
						c.args.WriteString(ev.Delta.PartialJSON)
					}
				}
			}
		case OpenAIChat:
			p.Events = append(p.Events, "chunk")
			var ev struct {
				Choices []struct {
					Delta struct {
						Content   *string `json:"content"`
						ToolCalls []struct {
							Index    int    `json:"index"`
							ID       string `json:"id"`
							Function struct {
								Name      string `json:"name"`
								Arguments string `json:"arguments"`
							} `json:"function"`
						} `json:"tool_calls"`
					} `json:"delta"`
				} `json:"choices"`
			}
			_ = json.Unmarshal([]byte(e[1]), &ev)
			for _, ch := range ev.Choices {
				if ch.Delta.Content != nil {
					p.Text += *ch.Delta.Content
				}
				for _, tc := range ch.Delta.ToolCalls {
					c := calls[tc.Index]
					if c == nil {
						c = &acc{}
						calls[tc.Index] = c
					}
					if tc.ID != "" {
						c.id = tc.ID
					}
					if tc.Function.Name != "" {
						c.name = tc.Function.Name
					}
					c.args.WriteString(tc.Function.Arguments)
				}
			}
		case OpenAIResponses:
			p.Events = append(p.Events, typ)
			var ev struct {
				OutputIndex int           `json:"output_index"`
				Delta       string        `json:"delta"`
				Item        responsesItem `json:"item"`
			}
			_ = json.Unmarshal([]byte(e[1]), &ev)
			switch typ {
			case "response.output_text.delta":
				p.Text += ev.Delta
			case "response.output_item.added":
				if ev.Item.Type == "function_call" {
					calls[ev.OutputIndex] = &acc{id: ev.Item.CallID, name: ev.Item.Name}
				}
			case "response.function_call_arguments.delta":
				if c := calls[ev.OutputIndex]; c != nil {
					c.args.WriteString(ev.Delta)
				}
			}
		}
	}
	idx := make([]int, 0, len(calls))
	for i := range calls {
		idx = append(idx, i)
	}
	sort.Ints(idx)
	for _, i := range idx {
		c := calls[i]
		p.ToolCalls = append(p.ToolCalls, ParsedCall{ID: c.id, Name: c.name, Arguments: c.args.String()})
	}
	return p, nil
}

// geminiResponse is the part of a GenerateContentResponse a client reads.
type geminiResponse struct {
	Candidates []struct {
		Content struct {
			Parts []struct {
				Text         string `json:"text"`
				Thought      bool   `json:"thought"`
				FunctionCall *struct {
					ID   string          `json:"id"`
					Name string          `json:"name"`
					Args json.RawMessage `json:"args"`
				} `json:"functionCall"`
				ThoughtSignature string `json:"thoughtSignature"`
			} `json:"parts"`
		} `json:"content"`
	} `json:"candidates"`
}

func (p *Parsed) addGemini(r geminiResponse) {
	if len(r.Candidates) == 0 {
		return
	}
	for _, part := range r.Candidates[0].Content.Parts {
		switch {
		case part.FunctionCall != nil:
			args := string(part.FunctionCall.Args)
			if args == "" {
				args = "{}"
			}
			p.ToolCalls = append(p.ToolCalls, ParsedCall{ID: part.FunctionCall.ID, Name: part.FunctionCall.Name, Arguments: args, Signature: part.ThoughtSignature})
		case !part.Thought:
			p.Text += part.Text
		}
	}
}

func parseGemini(stream bool, body []byte) (Parsed, error) {
	var p Parsed
	if !stream {
		var r geminiResponse
		if err := json.Unmarshal(body, &r); err != nil {
			return p, err
		}
		if len(r.Candidates) == 0 {
			return p, errors.New("no candidates")
		}
		p.addGemini(r)
		return p, nil
	}
	if trimmed := bytes.TrimSpace(body); len(trimmed) > 0 && trimmed[0] == '[' {
		var arr []geminiResponse
		if err := json.Unmarshal(trimmed, &arr); err != nil {
			return p, fmt.Errorf("json array stream: %w", err)
		}
		for _, r := range arr {
			p.Events = append(p.Events, "chunk")
			p.addGemini(r)
		}
		return p, nil
	}
	evs, err := sseEvents(body)
	if err != nil {
		return p, err
	}
	for _, e := range evs {
		var r geminiResponse
		if err := json.Unmarshal([]byte(e[1]), &r); err != nil {
			return p, fmt.Errorf("sse chunk: %w", err)
		}
		p.Events = append(p.Events, "chunk")
		p.addGemini(r)
	}
	return p, nil
}

// ParseEvents reassembles what a client of a WebSocket API received from its
// server event messages: the text of response.output_text.delta events and
// the tool calls of function_call output items with their argument deltas,
// across every response of the conversation, in the order they began. The
// Realtime API and the Responses WebSocket mode share these event shapes.
func ParseEvents(api API, msgs [][]byte) (Parsed, error) {
	var p Parsed
	if !api.WebSocket() {
		return p, fmt.Errorf("api %q is not a WebSocket API", api)
	}
	type acc struct {
		id, name string
		args     strings.Builder
	}
	var order []string
	calls := map[string]*acc{}
	for i, msg := range msgs {
		var ev struct {
			Type   string `json:"type"`
			ItemID string `json:"item_id"`
			Delta  string `json:"delta"`
			Item   struct {
				ID     string `json:"id"`
				Type   string `json:"type"`
				CallID string `json:"call_id"`
				Name   string `json:"name"`
			} `json:"item"`
			Error struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		if err := json.Unmarshal(msg, &ev); err != nil {
			return p, fmt.Errorf("server event %d: %w", i+1, err)
		}
		p.Events = append(p.Events, ev.Type)
		switch ev.Type {
		case "response.output_text.delta":
			p.Text += ev.Delta
		case "response.output_item.added":
			if ev.Item.Type == "function_call" && calls[ev.Item.ID] == nil {
				calls[ev.Item.ID] = &acc{id: ev.Item.CallID, name: ev.Item.Name}
				order = append(order, ev.Item.ID)
			}
		case "response.function_call_arguments.delta":
			if c := calls[ev.ItemID]; c != nil {
				c.args.WriteString(ev.Delta)
			}
		case "error":
			e := ev.Error.Code
			if e == "" {
				e = ev.Error.Message
			}
			p.Errors = append(p.Errors, e)
		}
	}
	for _, id := range order {
		c := calls[id]
		p.ToolCalls = append(p.ToolCalls, ParsedCall{ID: c.id, Name: c.name, Arguments: c.args.String()})
	}
	return p, nil
}
