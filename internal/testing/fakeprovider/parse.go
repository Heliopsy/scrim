// SPDX-License-Identifier: AGPL-3.0-only

package fakeprovider

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// ParsedCall is a tool call as an agent receives it.
type ParsedCall struct {
	ID   string
	Name string
	// Arguments is the raw JSON of the call input.
	Arguments string
}

// Parsed is a reply as an agent receives it, reassembled from either wire
// form.
type Parsed struct {
	Text      string
	ToolCalls []ParsedCall
	// Events lists the stream event types in order, empty when not
	// streamed.
	Events []string
}

// ParseReply reassembles a reply body of the given API, streamed or not.
func ParseReply(api API, stream bool, body []byte) (Parsed, error) {
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
				p.ToolCalls = append(p.ToolCalls, ParsedCall{c.ID, c.Name, string(c.Input)})
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
			p.ToolCalls = append(p.ToolCalls, ParsedCall{tc.ID, tc.Function.Name, tc.Function.Arguments})
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
		p.ToolCalls = append(p.ToolCalls, ParsedCall{it.CallID, it.Name, it.Args})
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
		p.ToolCalls = append(p.ToolCalls, ParsedCall{c.id, c.name, c.args.String()})
	}
	return p, nil
}
