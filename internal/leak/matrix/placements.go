// SPDX-License-Identifier: AGPL-3.0-only

package matrix

import (
	"encoding/base64"
	"net/http"
	"net/url"

	fp "github.com/heliopsy/scrim/internal/testing/fakeprovider"
)

// Content is the secret-bearing text a placement puts into a request: the
// transformed value with the tool output around it.
type Content struct {
	Command string
	Before  string
	Value   string
	After   string
	// FilesURL is where the fake provider serves the files a request
	// references (see Request.Files), set by the runner.
	FilesURL string
}

// Text is the whole tool output.
func (c Content) Text() string { return c.Before + c.Value + c.After }

// halves splits the content inside the value.
func (c Content) halves() (string, string) {
	mid := len(c.Value) / 2
	// Keep multi-byte characters whole.
	for mid > 0 && mid < len(c.Value) && c.Value[mid]&0xc0 == 0x80 {
		mid++
	}
	return c.Before + c.Value[:mid], c.Value[mid:] + c.After
}

// Request is one HTTP request a row sends through the proxy, or one
// WebSocket conversation.
type Request struct {
	API    fp.API
	Path   string
	Query  url.Values
	Header http.Header
	Body   []byte
	Stream bool
	// WS sends the request as a WebSocket conversation: a GET upgrade of
	// Path and Query with Header, then each of Messages in order on that
	// connection. Body is unused. The secret-bearing message comes first,
	// so a proxy that refuses it has forwarded nothing.
	WS       bool
	Messages []Frame
	// Files are held at the fake provider before the request is sent, for a
	// request that references them by URL or file ID (Content.FilesURL).
	Files []fp.File
}

// Frame is one WebSocket message: a text frame, or a binary one.
type Frame struct {
	Binary bool
	Data   []byte
}

// Placement is where in a provider request the secret-bearing content goes.
type Placement struct {
	ID     string
	Desc   string
	Expect Expect
	Note   string
	// Build returns the requests for one API, or nil when the placement does
	// not exist in that API.
	Build func(api fp.API, c Content, mode Escape) []Request
}

const (
	userAsk  = "The billing service fails to start. Find out why."
	sysText  = "You are a coding agent working in the user's repository."
	toolID   = "toolu_01Leak"
	callID   = "call_01Leak"
	toolName = "Bash"
)

func bashToolAnthropic(desc string) any {
	return obj("name", toolName, "description", desc, "input_schema", obj(
		"type", "object",
		"properties", obj("command", obj("type", "string", "description", "The command to run")),
		"required", []any{"command"},
	))
}

func bashToolChat(desc string) any {
	return obj("type", "function", "function", obj("name", toolName, "description", desc, "parameters", obj(
		"type", "object",
		"properties", obj("command", obj("type", "string")),
		"required", []any{"command"},
	)))
}

func bashToolResponses(desc string) any {
	return obj("type", "function", "name", toolName, "description", desc, "parameters", obj(
		"type", "object",
		"properties", obj("command", obj("type", "string")),
		"required", []any{"command"},
	))
}

// anthropicBody assembles a Messages request. Each argument may be nil to
// use the default.
type anthropicParts struct {
	system   any
	tools    []any
	messages []any
	extra    []kv
	stream   bool
}

func (p anthropicParts) body() any {
	if p.system == nil {
		p.system = sysText
	}
	if p.tools == nil {
		p.tools = []any{bashToolAnthropic("Run a shell command.")}
	}
	m := obj("model", "claude-sonnet-4-5", "max_tokens", 1024, "system", p.system, "tools", p.tools, "messages", p.messages)
	if p.stream {
		m = append(m, kv{"stream", true})
	}
	return append(m, p.extra...)
}

func anthropicToolTurn(command string, result any) []any {
	return []any{
		obj("role", "user", "content", userAsk),
		obj("role", "assistant", "content", []any{
			obj("type", "text", "text", "I'll look at the service configuration."),
			obj("type", "tool_use", "id", toolID, "name", toolName, "input", obj("command", command)),
		}),
		obj("role", "user", "content", []any{obj("type", "tool_result", "tool_use_id", toolID, "content", result)}),
	}
}

type chatParts struct {
	messages []any
	tools    []any
	extra    []kv
	stream   bool
}

func (p chatParts) body() any {
	if p.tools == nil {
		p.tools = []any{bashToolChat("Run a shell command.")}
	}
	m := obj("model", "gpt-5", "messages", p.messages, "tools", p.tools)
	if p.stream {
		m = append(m, kv{"stream", true}, kv{"stream_options", obj("include_usage", true)})
	}
	return append(m, p.extra...)
}

func chatToolTurn(command string, result any) []any {
	return []any{
		obj("role", "system", "content", sysText),
		obj("role", "user", "content", userAsk),
		obj("role", "assistant", "content", nil, "tool_calls", []any{
			obj("id", callID, "type", "function", "function", obj("name", toolName, "arguments", string(encode(obj("command", command), EscapeMinimal)))),
		}),
		obj("role", "tool", "tool_call_id", callID, "content", result),
	}
}

type responsesParts struct {
	instructions any
	input        []any
	tools        []any
	extra        []kv
	stream       bool
}

func (p responsesParts) body() any {
	if p.instructions == nil {
		p.instructions = sysText
	}
	if p.tools == nil {
		p.tools = []any{bashToolResponses("Run a shell command.")}
	}
	m := obj("model", "gpt-5", "instructions", p.instructions, "input", p.input, "tools", p.tools)
	if p.stream {
		m = append(m, kv{"stream", true})
	}
	return append(m, p.extra...)
}

func responsesToolTurn(command string, output any) []any {
	return []any{
		obj("type", "message", "role", "user", "content", []any{obj("type", "input_text", "text", userAsk)}),
		obj("type", "function_call", "call_id", callID, "name", toolName, "arguments", string(encode(obj("command", command), EscapeMinimal))),
		obj("type", "function_call_output", "call_id", callID, "output", output),
	}
}

// bashToolGemini is a Gemini tools entry declaring the Bash function.
func bashToolGemini(desc string) any {
	return obj("functionDeclarations", []any{obj("name", toolName, "description", desc, "parameters", obj(
		"type", "object",
		"properties", obj("command", obj("type", "string", "description", "The command to run")),
		"required", []any{"command"},
	))})
}

// geminiParts assembles a generateContent request. Gemini streams by path,
// so the body is the same either way.
type geminiParts struct {
	system   any
	tools    []any
	contents []any
	extra    []kv
}

func (p geminiParts) body() any {
	if p.system == nil {
		p.system = obj("parts", []any{obj("text", sysText)})
	}
	if p.tools == nil {
		p.tools = []any{bashToolGemini("Run a shell command.")}
	}
	m := obj("contents", p.contents, "systemInstruction", p.system, "tools", p.tools,
		"generationConfig", obj("temperature", 1, "maxOutputTokens", 1024))
	return append(m, p.extra...)
}

func geminiText(role string, texts ...string) any {
	parts := make([]any, 0, len(texts))
	for _, t := range texts {
		parts = append(parts, obj("text", t))
	}
	return obj("role", role, "parts", parts)
}

func geminiCall(command string) any {
	return obj("functionCall", obj("name", toolName, "args", obj("command", command)))
}

func geminiResult(response any) any {
	return obj("functionResponse", obj("name", toolName, "response", response))
}

// geminiToolTurn is a user ask, a model turn calling Bash and the user turn
// carrying the functionResponse. Gemini ties a response to its call by name.
func geminiToolTurn(command string, response any) []any {
	return []any{
		geminiText("user", userAsk),
		obj("role", "model", "parts", []any{obj("text", "I'll look at the service configuration."), geminiCall(command)}),
		obj("role", "user", "parts", []any{geminiResult(response)}),
	}
}

// geminiMCPContent is a functionResponse.response in the shape Gemini CLI
// sends MCP tool results: a list of MCP content blocks.
func geminiMCPContent(texts ...string) any {
	blocks := make([]any, 0, len(texts))
	for _, t := range texts {
		blocks = append(blocks, obj("type", "text", "text", t))
	}
	return obj("content", blocks)
}

func req(api fp.API, body any, mode Escape, stream bool) Request {
	if api == fp.OpenAIResponsesWS {
		// The WebSocket mode carries a Responses create body as the fields
		// of one response.create event.
		return wsReq(api, mode, append(obj("type", "response.create"), body.(orderedMap)...))
	}
	h := http.Header{}
	h.Set("Content-Type", "application/json")
	if api == fp.Anthropic {
		h.Set("Anthropic-Version", "2023-06-01")
	}
	r := Request{API: api, Path: api.Path(), Header: h, Body: encode(body, mode), Stream: stream}
	if stream {
		r.Path, r.Query = api.StreamPath(true)
	}
	return r
}

// wsReq builds a WebSocket conversation of text messages to the API's
// canonical URL.
func wsReq(api fp.API, mode Escape, msgs ...any) Request {
	r := Request{API: api, Path: api.Path(), Query: api.Query(), Header: http.Header{}, Stream: true, WS: true}
	for _, m := range msgs {
		r.Messages = append(r.Messages, Frame{Data: encode(m, mode)})
	}
	return r
}

// Realtime client events. A real session's function_call items come from
// the model and live on the server, so a client sends its tool result alone
// and the secret-bearing event can open the conversation.

func rtCreate() any { return obj("type", "response.create") }

func rtItem(item any) any { return obj("type", "conversation.item.create", "item", item) }

func rtUserItem(parts ...any) any {
	return obj("type", "message", "role", "user", "content", parts)
}

func rtUser(parts ...any) any { return rtItem(rtUserItem(parts...)) }

func rtText(t string) any { return obj("type", "input_text", "text", t) }

func rtCall(id, command string) any {
	return rtItem(obj("type", "function_call", "call_id", id, "name", toolName, "arguments", string(encode(obj("command", command), EscapeMinimal))))
}

func rtOutput(id, output string) any {
	return rtItem(obj("type", "function_call_output", "call_id", id, "output", output))
}

func rtSession(field string, v any) any {
	return obj("type", "session.update", "session", obj("type", "realtime", field, v))
}

// standard builds the primary tool-result request, with optional changes.
func standard(api fp.API, c Content, mode Escape, stream bool) Request {
	switch api {
	case fp.OpenAIRealtime:
		return wsReq(api, mode, rtOutput(callID, c.Text()), rtCreate())
	case fp.Anthropic:
		return req(api, anthropicParts{messages: anthropicToolTurn(c.Command, c.Text()), stream: stream}.body(), mode, stream)
	case fp.OpenAIChat:
		return req(api, chatParts{messages: chatToolTurn(c.Command, c.Text()), stream: stream}.body(), mode, stream)
	case fp.OpenAIResponses, fp.OpenAIResponsesWS:
		return req(api, responsesParts{input: responsesToolTurn(c.Command, c.Text()), stream: stream}.body(), mode, stream)
	case fp.Gemini:
		return req(api, geminiParts{contents: geminiToolTurn(c.Command, obj("output", c.Text()))}.body(), mode, stream)
	}
	return Request{}
}

func one(r Request) []Request { return []Request{r} }

// Placements is the catalogue of places a secret can sit in a request.
var Placements = []Placement{
	{ID: "tool-result", Desc: "tool result content as a string (primary placement)", Expect: Redacted,
		Build: func(api fp.API, c Content, mode Escape) []Request { return one(standard(api, c, mode, false)) }},
	{ID: "tool-result-streaming", Desc: "tool result in a streaming request", Expect: Redacted,
		Build: func(api fp.API, c Content, mode Escape) []Request {
			if api.WebSocket() {
				// Every WebSocket response streams: tool-result is this row.
				return nil
			}
			return one(standard(api, c, mode, true))
		}},
	{ID: "tool-result-blocks", Desc: "tool result content as text blocks", Expect: Redacted,
		Build: func(api fp.API, c Content, mode Escape) []Request {
			switch api {
			case fp.Anthropic:
				return one(req(api, anthropicParts{messages: anthropicToolTurn(c.Command, []any{obj("type", "text", "text", c.Text())})}.body(), mode, false))
			case fp.OpenAIChat:
				return one(req(api, chatParts{messages: chatToolTurn(c.Command, []any{obj("type", "text", "text", c.Text())})}.body(), mode, false))
			case fp.OpenAIResponses, fp.OpenAIResponsesWS:
				return one(req(api, responsesParts{input: responsesToolTurn(c.Command, []any{obj("type", "input_text", "text", c.Text())})}.body(), mode, false))
			case fp.Gemini:
				return one(req(api, geminiParts{contents: geminiToolTurn(c.Command, geminiMCPContent(c.Text()))}.body(), mode, false))
			}
			return nil
		}},
	{ID: "user-text", Desc: "user message text", Expect: Redacted,
		Build: func(api fp.API, c Content, mode Escape) []Request {
			switch api {
			case fp.Anthropic:
				return one(req(api, anthropicParts{messages: []any{obj("role", "user", "content", c.Text())}}.body(), mode, false))
			case fp.OpenAIChat:
				return one(req(api, chatParts{messages: []any{obj("role", "user", "content", c.Text())}}.body(), mode, false))
			case fp.OpenAIResponses, fp.OpenAIResponsesWS:
				return one(req(api, responsesParts{input: []any{obj("role", "user", "content", c.Text())}}.body(), mode, false))
			case fp.Gemini:
				return one(req(api, geminiParts{contents: []any{geminiText("user", c.Text())}}.body(), mode, false))
			case fp.OpenAIRealtime:
				return one(wsReq(api, mode, rtUser(rtText(c.Text())), rtCreate()))
			}
			return nil
		}},
	{ID: "user-blocks", Desc: "user message content parts", Expect: Redacted,
		Build: func(api fp.API, c Content, mode Escape) []Request {
			switch api {
			case fp.Anthropic:
				return one(req(api, anthropicParts{messages: []any{obj("role", "user", "content", []any{obj("type", "text", "text", c.Text())})}}.body(), mode, false))
			case fp.OpenAIChat:
				return one(req(api, chatParts{messages: []any{obj("role", "user", "content", []any{obj("type", "text", "text", c.Text())})}}.body(), mode, false))
			case fp.OpenAIResponses, fp.OpenAIResponsesWS:
				return one(req(api, responsesParts{input: []any{obj("type", "message", "role", "user", "content", []any{obj("type", "input_text", "text", c.Text())})}}.body(), mode, false))
			case fp.Gemini:
				return one(req(api, geminiParts{contents: []any{geminiText("user", "Here is the service's output:", c.Text())}}.body(), mode, false))
			case fp.OpenAIRealtime:
				return one(wsReq(api, mode, rtUser(rtText("Here is the service's output:"), rtText(c.Text())), rtCreate()))
			}
			return nil
		}},
	{ID: "system-prompt", Desc: "system prompt, instructions or system/developer message", Expect: Redacted,
		Build: func(api fp.API, c Content, mode Escape) []Request {
			switch api {
			case fp.Anthropic:
				return one(req(api, anthropicParts{system: []any{obj("type", "text", "text", sysText), obj("type", "text", "text", c.Text(), "cache_control", obj("type", "ephemeral"))}, messages: []any{obj("role", "user", "content", userAsk)}}.body(), mode, false))
			case fp.OpenAIChat:
				return one(req(api, chatParts{messages: []any{obj("role", "developer", "content", c.Text()), obj("role", "user", "content", userAsk)}}.body(), mode, false))
			case fp.OpenAIResponses, fp.OpenAIResponsesWS:
				return one(req(api, responsesParts{instructions: c.Text(), input: []any{obj("role", "user", "content", userAsk)}}.body(), mode, false))
			case fp.Gemini:
				return one(req(api, geminiParts{system: obj("parts", []any{obj("text", sysText), obj("text", c.Text())}), contents: []any{geminiText("user", userAsk)}}.body(), mode, false))
			case fp.OpenAIRealtime:
				return one(wsReq(api, mode, rtSession("instructions", c.Text()), rtUser(rtText(userAsk)), rtCreate()))
			}
			return nil
		}},
	{ID: "tool-call-input", Desc: "a prior tool call's input in the history (a restored value sent back)", Expect: Redacted,
		Build: func(api fp.API, c Content, mode Escape) []Request {
			cmd := "printf '%s' '" + c.Text() + "' > .env"
			switch api {
			case fp.Anthropic:
				return one(req(api, anthropicParts{messages: anthropicToolTurn(cmd, "")}.body(), mode, false))
			case fp.OpenAIChat:
				return one(req(api, chatParts{messages: chatToolTurn(cmd, "")}.body(), mode, false))
			case fp.OpenAIResponses, fp.OpenAIResponsesWS:
				return one(req(api, responsesParts{input: responsesToolTurn(cmd, "")}.body(), mode, false))
			case fp.Gemini:
				return one(req(api, geminiParts{contents: geminiToolTurn(cmd, obj("output", ""))}.body(), mode, false))
			case fp.OpenAIRealtime:
				// The client echoes the call it ran back into the
				// conversation, then its (empty) output.
				return one(wsReq(api, mode, rtCall(callID, cmd), rtOutput(callID, ""), rtCreate()))
			}
			return nil
		}},
	{ID: "assistant-text", Desc: "a prior assistant message in the history", Expect: Redacted,
		Build: func(api fp.API, c Content, mode Escape) []Request {
			hist := func(asst any) []any {
				return []any{obj("role", "user", "content", userAsk), asst, obj("role", "user", "content", "Thanks, go on.")}
			}
			switch api {
			case fp.Anthropic:
				return one(req(api, anthropicParts{messages: hist(obj("role", "assistant", "content", []any{obj("type", "text", "text", c.Text())}))}.body(), mode, false))
			case fp.OpenAIChat:
				return one(req(api, chatParts{messages: hist(obj("role", "assistant", "content", c.Text()))}.body(), mode, false))
			case fp.OpenAIResponses, fp.OpenAIResponsesWS:
				return one(req(api, responsesParts{input: hist(obj("type", "message", "role", "assistant", "content", []any{obj("type", "output_text", "text", c.Text())}))}.body(), mode, false))
			case fp.Gemini:
				return one(req(api, geminiParts{contents: []any{geminiText("user", userAsk), geminiText("model", c.Text()), geminiText("user", "Thanks, go on.")}}.body(), mode, false))
			case fp.OpenAIRealtime:
				asst := rtItem(obj("type", "message", "role", "assistant", "content", []any{obj("type", "output_text", "text", c.Text())}))
				return one(wsReq(api, mode, asst, rtUser(rtText("Thanks, go on.")), rtCreate()))
			}
			return nil
		}},
	{ID: "tool-definition", Desc: "a tool description (an MCP server describing itself)", Expect: Redacted,
		Build: func(api fp.API, c Content, mode Escape) []Request {
			msgs := []any{obj("role", "user", "content", userAsk)}
			switch api {
			case fp.Anthropic:
				return one(req(api, anthropicParts{tools: []any{bashToolAnthropic(c.Text())}, messages: msgs}.body(), mode, false))
			case fp.OpenAIChat:
				return one(req(api, chatParts{tools: []any{bashToolChat(c.Text())}, messages: msgs}.body(), mode, false))
			case fp.OpenAIResponses, fp.OpenAIResponsesWS:
				return one(req(api, responsesParts{tools: []any{bashToolResponses(c.Text())}, input: msgs}.body(), mode, false))
			case fp.Gemini:
				return one(req(api, geminiParts{tools: []any{bashToolGemini(c.Text())}, contents: []any{geminiText("user", userAsk)}}.body(), mode, false))
			case fp.OpenAIRealtime:
				return one(wsReq(api, mode, rtSession("tools", []any{bashToolResponses(c.Text())}), rtUser(rtText(userAsk)), rtCreate()))
			}
			return nil
		}},
	{ID: "metadata", Desc: "request metadata (user id, metadata map)", Expect: Redacted,
		Build: func(api fp.API, c Content, mode Escape) []Request {
			msgs := []any{obj("role", "user", "content", userAsk)}
			switch api {
			case fp.Anthropic:
				return one(req(api, anthropicParts{messages: msgs, extra: []kv{{"metadata", obj("user_id", c.Text())}}}.body(), mode, false))
			case fp.OpenAIChat:
				return one(req(api, chatParts{messages: msgs, extra: []kv{{"user", c.Text()}, {"metadata", obj("session", c.Text())}}}.body(), mode, false))
			case fp.OpenAIResponses, fp.OpenAIResponsesWS:
				return one(req(api, responsesParts{input: msgs, extra: []kv{{"metadata", obj("session", c.Text())}}}.body(), mode, false))
			case fp.OpenAIRealtime:
				// An out-of-band response carries its own input, so the
				// metadata-bearing event is the whole conversation.
				return one(wsReq(api, mode, obj("type", "response.create", "response", obj(
					"conversation", "none", "metadata", obj("session", c.Text()), "input", []any{rtUserItem(rtText(userAsk))}))))
			}
			// The Gemini API has no metadata or user field (Vertex AI's
			// labels are not accepted by generativelanguage.googleapis.com);
			// an arbitrary top-level field is the unknown-field row.
			return nil
		}},
	{ID: "unknown-field", Desc: "an undocumented top-level field (like Claude Code's safeguards field)", Expect: Redacted,
		Build: func(api fp.API, c Content, mode Escape) []Request {
			msgs := []any{obj("role", "user", "content", userAsk)}
			extra := []kv{{"x_client_context", obj("cwd", "/home/dev/billing", "env_preview", c.Text())}}
			switch api {
			case fp.Anthropic:
				return one(req(api, anthropicParts{messages: msgs, extra: extra}.body(), mode, false))
			case fp.OpenAIChat:
				return one(req(api, chatParts{messages: msgs, extra: extra}.body(), mode, false))
			case fp.OpenAIResponses, fp.OpenAIResponsesWS:
				return one(req(api, responsesParts{input: msgs, extra: extra}.body(), mode, false))
			case fp.Gemini:
				return one(req(api, geminiParts{contents: []any{geminiText("user", userAsk)}, extra: extra}.body(), mode, false))
			case fp.OpenAIRealtime:
				ev := append(obj("type", "conversation.item.create", "item", rtUserItem(rtText(userAsk))), extra...)
				return one(wsReq(api, mode, ev, rtCreate()))
			}
			return nil
		}},
	{ID: "unknown-block-field", Desc: "an undocumented field inside a content block", Expect: Redacted,
		Build: func(api fp.API, c Content, mode Escape) []Request {
			switch api {
			case fp.Anthropic:
				return one(req(api, anthropicParts{messages: []any{obj("role", "user", "content", []any{obj("type", "text", "text", userAsk, "x_source", c.Text())})}}.body(), mode, false))
			case fp.OpenAIChat:
				return one(req(api, chatParts{messages: []any{obj("role", "user", "content", userAsk, "x_source", c.Text())}}.body(), mode, false))
			case fp.OpenAIResponses, fp.OpenAIResponsesWS:
				return one(req(api, responsesParts{input: []any{obj("type", "message", "role", "user", "content", []any{obj("type", "input_text", "text", userAsk, "x_source", c.Text())})}}.body(), mode, false))
			case fp.Gemini:
				return one(req(api, geminiParts{contents: []any{obj("role", "user", "parts", []any{obj("text", userAsk, "x_source", c.Text())})}}.body(), mode, false))
			case fp.OpenAIRealtime:
				return one(wsReq(api, mode, rtUser(obj("type", "input_text", "text", userAsk, "x_source", c.Text())), rtCreate()))
			}
			return nil
		}},
	{ID: "document-text", Desc: "a plain-text document or file input", Expect: Redacted,
		Build: func(api fp.API, c Content, mode Escape) []Request {
			switch api {
			case fp.Anthropic:
				doc := obj("type", "document", "source", obj("type", "text", "media_type", "text/plain", "data", c.Text()), "title", ".env")
				return one(req(api, anthropicParts{messages: []any{obj("role", "user", "content", []any{doc, obj("type", "text", "text", userAsk)})}}.body(), mode, false))
			case fp.OpenAIChat:
				data := "data:text/plain;base64," + base64.StdEncoding.EncodeToString([]byte(c.Text()))
				file := obj("type", "file", "file", obj("filename", ".env", "file_data", data))
				return one(req(api, chatParts{messages: []any{obj("role", "user", "content", []any{file, obj("type", "text", "text", userAsk)})}}.body(), mode, false))
			case fp.OpenAIResponses, fp.OpenAIResponsesWS:
				data := "data:text/plain;base64," + base64.StdEncoding.EncodeToString([]byte(c.Text()))
				file := obj("type", "input_file", "filename", ".env", "file_data", data)
				return one(req(api, responsesParts{input: []any{obj("type", "message", "role", "user", "content", []any{file, obj("type", "input_text", "text", userAsk)})}}.body(), mode, false))
			case fp.Gemini:
				// A document is an inlineData part; the scan binary policy
				// redacts a text one and encodes it again.
				doc := obj("inlineData", obj("mimeType", "text/plain", "data", base64.StdEncoding.EncodeToString([]byte(c.Text()))))
				return one(req(api, geminiParts{contents: []any{obj("role", "user", "parts", []any{doc, obj("text", userAsk)})}}.body(), mode, false))
			}
			// The Realtime API takes no file input.
			return nil
		}},
	{ID: "header", Desc: "a custom HTTP request header (on a WebSocket API, in the handshake)", Expect: Guard,
		Build: func(api fp.API, c Content, mode Escape) []Request {
			r := standard(api, Content{Command: c.Command, Before: "(no output)"}, mode, false)
			r.Header.Set("X-Debug-Context", headerSafe(c.Text()))
			return one(r)
		}},
	{ID: "query", Desc: "the request URL query string (on a WebSocket API, the handshake URL's)", Expect: Guard,
		Build: func(api fp.API, c Content, mode Escape) []Request {
			r := standard(api, Content{Command: c.Command, Before: "(no output)"}, mode, false)
			q := url.Values{}
			for k, vs := range r.Query {
				q[k] = vs
			}
			q.Set("trace", c.Text())
			r.Query = q
			return one(r)
		}},
	{ID: "image-metadata", Desc: "text in an image's PNG tEXt metadata", Expect: Withheld,
		Note: "the scan binary policy reads PNG text chunks and refuses the request: an image cannot be redacted in place",
		Build: func(api fp.API, c Content, mode Escape) []Request {
			return attachment(api, "image/png", pngWithText("Comment", c.Text()), mode)
		}},
	{ID: "image-metadata-compressed", Desc: "text in an image's compressed PNG zTXt metadata", Expect: Withheld,
		Note: "the scan binary policy inflates compressed PNG text chunks",
		Build: func(api fp.API, c Content, mode Escape) []Request {
			return attachment(api, "image/png", pngWithZText("Comment", c.Text()), mode)
		}},
	{ID: "jpeg-comment", Desc: "text in a JPEG COM segment", Expect: Withheld,
		Note: "the scan binary policy reads JPEG comment and APP segments",
		Build: func(api fp.API, c Content, mode Escape) []Request {
			return attachment(api, "image/jpeg", jpegWithComment(c.Text()), mode)
		}},
	{ID: "svg-text", Desc: "text drawn by an SVG image", Expect: Withheld,
		Note: "the scan binary policy reads SVG as text, entities decoded",
		Build: func(api fp.API, c Content, mode Escape) []Request {
			return attachment(api, "image/svg+xml", svgWithText(c.Text()), mode)
		}},
	{ID: "pdf-text", Desc: "text in a PDF page's Flate-compressed content stream", Expect: Withheld,
		Note: "the scan binary policy inflates PDF streams and reads their strings",
		Build: func(api fp.API, c Content, mode Escape) []Request {
			return attachment(api, "application/pdf", pdfWithText(c.Text()), mode)
		}},
	{ID: "remote-image-url", Desc: "text in the metadata of an image the request references by URL", Expect: Withheld,
		Note: "remote attachments inline: scrim fetches the image, scans it and refuses (WebSocket messages with a URL are refused)",
		Build: func(api fp.API, c Content, mode Escape) []Request {
			return remoteAttachment(api, c, mode, remoteImage, fp.File{Name: "scrim-leak-image.png", MediaType: "image/png", Data: pngWithText("Comment", c.Text())})
		}},
	{ID: "remote-document-url", Desc: "text in a PDF the request references by URL", Expect: Withheld,
		Note: "remote attachments inline: scrim fetches the PDF, scans it and refuses",
		Build: func(api fp.API, c Content, mode Escape) []Request {
			return remoteAttachment(api, c, mode, remoteDocument, fp.File{Name: "scrim-leak-document.pdf", MediaType: "application/pdf", Data: pdfWithText(c.Text())})
		}},
	{ID: "remote-text-url", Desc: "a plain-text file the request references by URL", Expect: Guard,
		Note: "remote attachments inline: scrim fetches the text, redacts it and sends it inline; refused where the fetch is not allowed",
		Build: func(api fp.API, c Content, mode Escape) []Request {
			return remoteAttachment(api, c, mode, remoteDocument, fp.File{Name: "scrim-leak-notes.txt", MediaType: "text/plain", Data: []byte(c.Text())})
		}},
	{ID: "remote-file-id", Desc: "a file the request references by a provider file ID, uploaded without scrim", Expect: Withheld,
		Note: "remote attachments: a file ID passes only when scrim scanned its upload on the route",
		Build: func(api fp.API, c Content, mode Escape) []Request {
			return remoteAttachment(api, c, mode, remoteFileID, fp.File{Name: "file-scrimleak01", MediaType: "application/pdf", Data: pdfWithText(c.Text())})
		}},
	{ID: "image-pixels", Desc: "the value as an image's pixel data (rendered text in a screenshot)", Expect: Limitation,
		Note: "limitation: pixel data is not decoded and text in an image is not recognised (no OCR)",
		Build: func(api fp.API, c Content, mode Escape) []Request {
			return attachment(api, "image/png", pngWithPixels(c.Text()), mode)
		}},
	{ID: "split-blocks", Desc: "the value split across two content blocks of one message", Expect: Limitation,
		Note: "limitation: a value split across fields of one request is matched by the guard's fragment rules (a piece of at least half the value, or pieces of at least the minimum length that together cover it, split-fragments); the checker cannot tell such a split from no leak, so the row is not gated",
		Build: func(api fp.API, c Content, mode Escape) []Request {
			a, b := c.halves()
			switch api {
			case fp.Anthropic:
				return one(req(api, anthropicParts{messages: anthropicToolTurn(c.Command, []any{obj("type", "text", "text", a), obj("type", "text", "text", b)})}.body(), mode, false))
			case fp.OpenAIChat:
				return one(req(api, chatParts{messages: chatToolTurn(c.Command, []any{obj("type", "text", "text", a), obj("type", "text", "text", b)})}.body(), mode, false))
			case fp.OpenAIResponses, fp.OpenAIResponsesWS:
				return one(req(api, responsesParts{input: responsesToolTurn(c.Command, []any{obj("type", "input_text", "text", a), obj("type", "input_text", "text", b)})}.body(), mode, false))
			case fp.Gemini:
				return one(req(api, geminiParts{contents: geminiToolTurn(c.Command, geminiMCPContent(a, b))}.body(), mode, false))
			case fp.OpenAIRealtime:
				// A function_call_output is a string; the blocks are a
				// user message's parts.
				return one(wsReq(api, mode, rtUser(rtText(a), rtText(b)), rtCreate()))
			}
			return nil
		}},
	{ID: "split-tool-results", Desc: "the value split across two tool results", Expect: Limitation,
		Note: "limitation: a value split across tool results of one request is matched like split-blocks; pieces shorter than the minimum length are not",
		Build: func(api fp.API, c Content, mode Escape) []Request {
			a, b := c.halves()
			switch api {
			case fp.Anthropic:
				msgs := append(anthropicToolTurn("head -c 40 .env", a),
					obj("role", "assistant", "content", []any{obj("type", "tool_use", "id", toolID+"2", "name", toolName, "input", obj("command", "tail -c +41 .env"))}),
					obj("role", "user", "content", []any{obj("type", "tool_result", "tool_use_id", toolID+"2", "content", b)}))
				return one(req(api, anthropicParts{messages: msgs}.body(), mode, false))
			case fp.OpenAIChat:
				msgs := append(chatToolTurn("head -c 40 .env", a),
					obj("role", "assistant", "content", nil, "tool_calls", []any{obj("id", callID+"2", "type", "function", "function", obj("name", toolName, "arguments", `{"command":"tail -c +41 .env"}`))}),
					obj("role", "tool", "tool_call_id", callID+"2", "content", b))
				return one(req(api, chatParts{messages: msgs}.body(), mode, false))
			case fp.OpenAIResponses, fp.OpenAIResponsesWS:
				in := append(responsesToolTurn("head -c 40 .env", a),
					obj("type", "function_call", "call_id", callID+"2", "name", toolName, "arguments", `{"command":"tail -c +41 .env"}`),
					obj("type", "function_call_output", "call_id", callID+"2", "output", b))
				return one(req(api, responsesParts{input: in}.body(), mode, false))
			case fp.Gemini:
				contents := append(geminiToolTurn("head -c 40 .env", obj("output", a)),
					obj("role", "model", "parts", []any{geminiCall("tail -c +41 .env")}),
					obj("role", "user", "parts", []any{geminiResult(obj("output", b))}))
				return one(req(api, geminiParts{contents: contents}.body(), mode, false))
			case fp.OpenAIRealtime:
				return one(wsReq(api, mode, rtOutput(callID, a), rtOutput(callID+"2", b), rtCreate()))
			}
			return nil
		}},
	{ID: "split-requests", Desc: "the value split across two requests chained by previous_response_id (two events on one socket in the WebSocket mode)", Expect: Limitation,
		Note: "limitation: server-side conversation state lets pieces arrive in separate requests; each is checked alone, so only a piece of at least half the value is caught",
		Build: func(api fp.API, c Content, mode Escape) []Request {
			if api != fp.OpenAIResponses && api != fp.OpenAIResponsesWS {
				return nil
			}
			a, b := c.halves()
			r1 := req(api, responsesParts{input: responsesToolTurn("head -c 40 .env", a), extra: []kv{{"store", true}}}.body(), mode, false)
			in2 := []any{
				obj("type", "function_call", "call_id", callID+"2", "name", toolName, "arguments", `{"command":"tail -c +41 .env"}`),
				obj("type", "function_call_output", "call_id", callID+"2", "output", b),
			}
			r2 := req(api, responsesParts{input: in2, extra: []kv{{"previous_response_id", "resp_previous"}}}.body(), mode, false)
			if api == fp.OpenAIResponsesWS {
				// The WebSocket mode's own use: the second response.create
				// follows the first on the same connection.
				r1.Messages = append(r1.Messages, r2.Messages...)
				return one(r1)
			}
			return []Request{r1, r2}
		}},
	{ID: "ws-binary-frame", Desc: "the tool result event sent as a binary WebSocket frame", Expect: Redacted,
		Build: func(api fp.API, c Content, mode Escape) []Request {
			if !api.WebSocket() {
				return nil
			}
			r := standard(api, c, mode, false)
			r.Messages[0].Binary = true
			return one(r)
		}},
	{ID: "audio-buffer", Desc: "text in base64 audio appended to the Realtime input buffer", Expect: Withheld,
		Note: "the scan binary policy decodes base64 audio and refuses the message when its bytes hold a value (speech is not transcribed)",
		Build: func(api fp.API, c Content, mode Escape) []Request {
			if api != fp.OpenAIRealtime {
				return nil
			}
			audio := base64.StdEncoding.EncodeToString([]byte(c.Text()))
			return one(wsReq(api, mode, obj("type", "input_audio_buffer.append", "audio", audio), rtCreate()))
		}},
}

// headerSafe keeps a header value legal: control characters and non-ASCII
// would make the client refuse to send it.
func headerSafe(s string) string {
	b := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c > 0x7e {
			c = ' '
		}
		b = append(b, c)
	}
	return string(b)
}

// PlacementByID returns the placement with the given ID.
func PlacementByID(id string) (Placement, bool) {
	for _, p := range Placements {
		if p.ID == id {
			return p, true
		}
	}
	return Placement{}, false
}
