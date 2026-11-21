// SPDX-License-Identifier: AGPL-3.0-only

// Package fakeprovider is a model provider stand-in for the leak suite and
// integration tests. It speaks the Anthropic Messages API and the OpenAI Chat
// Completions and Responses APIs, streaming and non-streaming, with tool use
// round trips, and records every byte it receives.
//
// It is faithful where the proxy under test can tell the difference: paths,
// event names and order, JSON shapes, SSE framing, small streamed deltas that
// split placeholders across chunks, usage blocks with cache counters, and
// provider-shaped errors. It is not a model: replies come from a [Responder].
//
// Captures are what a real provider would have seen. They hold whatever the
// proxy forwarded, which in a leak test may include generated fake secrets;
// they never hold real ones.
package fakeprovider

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/heliopsy/scrim/internal/leak"
)

// API identifies a provider API.
type API string

// Supported APIs.
const (
	Anthropic       API = "anthropic-messages"
	OpenAIChat      API = "openai-chat"
	OpenAIResponses API = "openai-responses"
)

// APIs lists every API the fake speaks.
var APIs = []API{Anthropic, OpenAIChat, OpenAIResponses}

// Path returns the canonical request path of an API.
func (a API) Path() string {
	switch a {
	case Anthropic:
		return "/v1/messages"
	case OpenAIChat:
		return "/v1/chat/completions"
	case OpenAIResponses:
		return "/v1/responses"
	}
	return ""
}

// Exchange is one recorded request and the reply the fake sent.
type Exchange struct {
	leak.Capture
	Time   time.Time
	API    API
	Stream bool
	Model  string
	Status int
	// PromptBytes is the size of the prompt prefix blocks (tools, system,
	// messages or input items) and CachedBytes the part of it that matched
	// an earlier request block for block, the way provider prompt caching
	// matches prefixes.
	PromptBytes int
	CachedBytes int
	// Placeholders lists every scrim placeholder found in the request.
	Placeholders []string
	// Response is the reply body as sent.
	Response []byte
}

// ToolCall is a tool call the fake asks the agent to make.
type ToolCall struct {
	Name  string
	Input map[string]any
	// Namespace, in the Responses API only, names the namespace tool that
	// holds Name (Codex groups each MCP server's tools in one).
	Namespace string
}

// Reply is what the fake answers.
type Reply struct {
	Text      string
	ToolCalls []ToolCall
	// Status, when set and not 200, makes the fake answer with a
	// provider-shaped error of that status.
	Status int
	// Error is the error message for a non-200 Status.
	Error string
}

// Turn is what a Responder sees of a request.
type Turn struct {
	API    API
	Model  string
	Stream bool
	// Body is the decoded request.
	Body map[string]any
	// Placeholders found anywhere in the request, in order, deduplicated.
	Placeholders []string
	// ToolResults counts tool results in the request.
	ToolResults int
	// Assistant counts prior assistant turns in the request.
	Assistant int
	// Header is the request header.
	Header http.Header
}

// Responder decides the reply to a request.
type Responder func(Turn) Reply

// Echo is the default responder. It names the placeholders it saw so the
// proxy's restorer has something to resolve, split across stream chunks.
func Echo(t Turn) Reply {
	if len(t.Placeholders) == 0 {
		return Reply{Text: "ok"}
	}
	return Reply{Text: "I saw " + strings.Join(t.Placeholders, " and ") + "."}
}

// Options configure a Server.
type Options struct {
	// Responder decides replies. Default [Echo].
	Responder Responder
	// ChunkSize is the number of runes per streamed text or argument delta.
	// Small chunks split placeholders across events. Default 5.
	ChunkSize int
	// PlaceholderPattern matches scrim placeholders. Default
	// [DefaultPlaceholderPattern].
	PlaceholderPattern *regexp.Regexp
	// RequireAuth makes the fake refuse requests without provider
	// authentication, like a real provider.
	RequireAuth bool
}

// DefaultPlaceholderPattern matches the placeholder format of design D3.
var DefaultPlaceholderPattern = regexp.MustCompile(`⟦scrim:[^⟧\s]{1,200}⟧`)

// Server is the fake provider. It is an http.Handler.
type Server struct {
	opts Options

	mu        sync.Mutex
	exchanges []Exchange
	prefixes  [][]string
}

// New returns a fake provider.
func New(opts Options) *Server {
	if opts.Responder == nil {
		opts.Responder = Echo
	}
	if opts.ChunkSize <= 0 {
		opts.ChunkSize = 5
	}
	if opts.PlaceholderPattern == nil {
		opts.PlaceholderPattern = DefaultPlaceholderPattern
	}
	return &Server{opts: opts}
}

// SetResponder replaces the responder for subsequent requests.
func (s *Server) SetResponder(r Responder) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r == nil {
		r = Echo
	}
	s.opts.Responder = r
}

// Exchanges returns a copy of every recorded exchange.
func (s *Server) Exchanges() []Exchange {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Exchange, len(s.exchanges))
	copy(out, s.exchanges)
	return out
}

// Captures returns the recorded requests.
func (s *Server) Captures() []leak.Capture {
	ex := s.Exchanges()
	out := make([]leak.Capture, len(ex))
	for i, e := range ex {
		out[i] = e.Capture
	}
	return out
}

// Reset forgets every exchange and every cached prefix.
func (s *Server) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.exchanges = nil
	s.prefixes = nil
}

func (s *Server) record(e Exchange) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e.Seq = len(s.exchanges) + 1
	s.exchanges = append(s.exchanges, e)
}

// ServeHTTP implements http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/_fake/") {
		s.control(w, r)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 256<<20))
	if err != nil {
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}
	ex := Exchange{
		Capture: leak.Capture{
			Method:   r.Method,
			Path:     r.URL.Path,
			RawQuery: r.URL.RawQuery,
			Header:   r.Header.Clone(),
			Body:     body,
		},
		Time: time.Now().UTC(),
	}
	rw := &recorder{ResponseWriter: w, status: http.StatusOK}
	defer func() {
		ex.Status = rw.status
		ex.Response = rw.buf.Bytes()
		s.record(ex)
	}()

	path := r.URL.Path
	switch {
	case r.Method == http.MethodGet && strings.HasSuffix(path, "/v1/models"):
		writeJSON(rw, http.StatusOK, map[string]any{"object": "list", "data": []any{
			map[string]any{"id": "fake-model", "object": "model", "type": "model", "display_name": "Fake model", "created": 0, "owned_by": "scrim"},
		}})
		return
	case strings.HasSuffix(path, "/v1/messages/count_tokens"):
		ex.API = Anthropic
		writeJSON(rw, http.StatusOK, map[string]any{"input_tokens": max(1, len(body)/4)})
		return
	case strings.HasSuffix(path, "/v1/messages"):
		ex.API = Anthropic
	case strings.HasSuffix(path, "/chat/completions"):
		ex.API = OpenAIChat
	case strings.HasSuffix(path, "/responses"):
		ex.API = OpenAIResponses
	default:
		s.apiError(rw, "", http.StatusNotFound, "not_found_error", "unknown path "+path)
		return
	}
	if r.Method != http.MethodPost {
		s.apiError(rw, ex.API, http.StatusMethodNotAllowed, "invalid_request_error", "method not allowed")
		return
	}
	if s.opts.RequireAuth && r.Header.Get("Authorization") == "" && r.Header.Get("X-Api-Key") == "" {
		s.apiError(rw, ex.API, http.StatusUnauthorized, "authentication_error", "missing credentials")
		return
	}
	var req map[string]any
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	if err := dec.Decode(&req); err != nil {
		s.apiError(rw, ex.API, http.StatusBadRequest, "invalid_request_error", "body is not valid JSON")
		return
	}
	ex.Model, _ = req["model"].(string)
	ex.Stream, _ = req["stream"].(bool)
	ex.Placeholders = uniq(s.opts.PlaceholderPattern.FindAllString(string(body), -1))
	ex.PromptBytes, ex.CachedBytes = s.cache(ex.API, ex.Model, body)

	turn := Turn{API: ex.API, Model: ex.Model, Stream: ex.Stream, Body: req, Placeholders: ex.Placeholders, Header: r.Header}
	turn.ToolResults, turn.Assistant = countTurns(ex.API, req)
	s.mu.Lock()
	responder := s.opts.Responder
	s.mu.Unlock()
	reply := responder(turn)
	if reply.Status != 0 && reply.Status != http.StatusOK {
		s.apiError(rw, ex.API, reply.Status, errorType(reply.Status), reply.Error)
		return
	}
	sum := sha256.Sum256(body)
	g := &gen{idSeed: hex.EncodeToString(sum[:]), chunk: s.opts.ChunkSize, model: ex.Model, cached: ex.CachedBytes / 4, input: max(1, ex.PromptBytes/4)}
	switch ex.API {
	case Anthropic:
		g.anthropic(rw, reply, ex.Stream)
	case OpenAIChat:
		g.chat(rw, reply, ex.Stream, includeUsage(req))
	case OpenAIResponses:
		g.responses(rw, reply, ex.Stream)
	}
}

func includeUsage(req map[string]any) bool {
	so, _ := req["stream_options"].(map[string]any)
	v, _ := so["include_usage"].(bool)
	return v
}

func errorType(status int) string {
	switch status {
	case http.StatusBadRequest:
		return "invalid_request_error"
	case http.StatusUnauthorized:
		return "authentication_error"
	case http.StatusForbidden:
		return "permission_error"
	case http.StatusNotFound:
		return "not_found_error"
	case http.StatusTooManyRequests:
		return "rate_limit_error"
	case 529:
		return "overloaded_error"
	}
	return "api_error"
}

func (s *Server) apiError(w http.ResponseWriter, api API, status int, typ, msg string) {
	if status == http.StatusTooManyRequests {
		w.Header().Set("Retry-After", "1")
	}
	switch api {
	case OpenAIChat, OpenAIResponses:
		writeJSON(w, status, map[string]any{"error": map[string]any{"message": msg, "type": typ, "param": nil, "code": nil}})
	default:
		writeJSON(w, status, map[string]any{"type": "error", "error": map[string]any{"type": typ, "message": msg}})
	}
}

// control serves the out-of-band endpoints the standalone binary exposes.
func (s *Server) control(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/_fake/health":
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	case r.URL.Path == "/_fake/reset" && r.Method == http.MethodPost:
		s.Reset()
		w.WriteHeader(http.StatusNoContent)
	case r.URL.Path == "/_fake/exchanges" && r.Method == http.MethodGet:
		writeJSON(w, http.StatusOK, s.Exchanges())
	default:
		http.NotFound(w, r)
	}
}

// MarshalJSON writes an exchange with its body as a string when it is UTF-8
// and base64 otherwise.
func (e Exchange) MarshalJSON() ([]byte, error) {
	type wire struct {
		Seq          int         `json:"seq"`
		Time         time.Time   `json:"time"`
		API          API         `json:"api,omitempty"`
		Method       string      `json:"method"`
		Path         string      `json:"path"`
		RawQuery     string      `json:"query,omitempty"`
		Header       http.Header `json:"header"`
		Body         []byte      `json:"body"`
		Stream       bool        `json:"stream"`
		Model        string      `json:"model,omitempty"`
		Status       int         `json:"status"`
		PromptBytes  int         `json:"prompt_bytes"`
		CachedBytes  int         `json:"cached_bytes"`
		Placeholders []string    `json:"placeholders,omitempty"`
		Response     []byte      `json:"response"`
	}
	return json.Marshal(wire{e.Seq, e.Time, e.API, e.Method, e.Path, e.RawQuery, e.Header, e.Body, e.Stream, e.Model, e.Status, e.PromptBytes, e.CachedBytes, e.Placeholders, e.Response})
}

// UnmarshalJSON reads the form written by MarshalJSON.
func (e *Exchange) UnmarshalJSON(b []byte) error {
	var w struct {
		Seq          int         `json:"seq"`
		Time         time.Time   `json:"time"`
		API          API         `json:"api"`
		Method       string      `json:"method"`
		Path         string      `json:"path"`
		RawQuery     string      `json:"query"`
		Header       http.Header `json:"header"`
		Body         []byte      `json:"body"`
		Stream       bool        `json:"stream"`
		Model        string      `json:"model"`
		Status       int         `json:"status"`
		PromptBytes  int         `json:"prompt_bytes"`
		CachedBytes  int         `json:"cached_bytes"`
		Placeholders []string    `json:"placeholders"`
		Response     []byte      `json:"response"`
	}
	if err := json.Unmarshal(b, &w); err != nil {
		return err
	}
	*e = Exchange{
		Capture: leak.Capture{Seq: w.Seq, Method: w.Method, Path: w.Path, RawQuery: w.RawQuery, Header: w.Header, Body: w.Body},
		Time:    w.Time, API: w.API, Stream: w.Stream, Model: w.Model, Status: w.Status,
		PromptBytes: w.PromptBytes, CachedBytes: w.CachedBytes, Placeholders: w.Placeholders, Response: w.Response,
	}
	return nil
}

type recorder struct {
	http.ResponseWriter
	status int
	buf    bytes.Buffer
	wrote  bool
}

func (r *recorder) WriteHeader(code int) {
	if !r.wrote {
		r.status = code
		r.wrote = true
	}
	r.ResponseWriter.WriteHeader(code)
}

func (r *recorder) Write(b []byte) (int, error) {
	r.wrote = true
	r.buf.Write(b)
	return r.ResponseWriter.Write(b)
}

func (r *recorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		status, b = http.StatusInternalServerError, []byte(`{"error":"marshal"}`)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", fmt.Sprint(len(b)))
	w.WriteHeader(status)
	_, _ = w.Write(b)
}

func uniq(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func countTurns(api API, req map[string]any) (toolResults, assistant int) {
	var items []any
	switch api {
	case Anthropic, OpenAIChat:
		items, _ = req["messages"].([]any)
	case OpenAIResponses:
		items, _ = req["input"].([]any)
	}
	for _, it := range items {
		m, _ := it.(map[string]any)
		role, _ := m["role"].(string)
		typ, _ := m["type"].(string)
		switch {
		case role == "assistant":
			assistant++
		case role == "tool", typ == "function_call_output":
			toolResults++
		}
		if typ == "function_call" {
			assistant++
		}
		if parts, ok := m["content"].([]any); ok {
			for _, p := range parts {
				pm, _ := p.(map[string]any)
				if pm["type"] == "tool_result" {
					toolResults++
				}
			}
		}
	}
	return toolResults, assistant
}

// cache computes the prompt prefix blocks of a request and how many of their
// bytes match an earlier request with the same model, block for block from
// the start. This is how provider prompt caches behave: any byte change in a
// block invalidates it and everything after.
func (s *Server) cache(api API, model string, body []byte) (total, cached int) {
	var raw map[string]json.RawMessage
	if json.Unmarshal(body, &raw) != nil {
		return 0, 0
	}
	blocks := []string{"model:" + model}
	addArray := func(prefix, key string) {
		v, ok := raw[key]
		if !ok {
			return
		}
		var arr []json.RawMessage
		if json.Unmarshal(v, &arr) == nil {
			for _, e := range arr {
				blocks = append(blocks, prefix+canonicalBlock(e))
			}
			return
		}
		blocks = append(blocks, prefix+canonicalBlock(v))
	}
	switch api {
	case Anthropic:
		addArray("tools:", "tools")
		addArray("system:", "system")
		addArray("msg:", "messages")
	case OpenAIChat:
		addArray("tools:", "tools")
		addArray("msg:", "messages")
	case OpenAIResponses:
		addArray("tools:", "tools")
		addArray("instructions:", "instructions")
		addArray("input:", "input")
	}
	for _, b := range blocks[1:] {
		total += len(b)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, prev := range s.prefixes {
		n := 0
		for i := 0; i < len(prev) && i < len(blocks) && prev[i] == blocks[i]; i++ {
			if i > 0 {
				n += len(blocks[i])
			}
		}
		// A provider never reports the whole prompt as cached.
		if n == total && n > 0 && len(prev) >= len(blocks) {
			n -= len(blocks[len(blocks)-1])
		}
		cached = max(cached, n)
	}
	s.prefixes = append(s.prefixes, blocks)
	return total, cached
}

// StableID derives a deterministic ID from content, for tests that compare
// replies across runs.
func StableID(prefix, content string) string {
	sum := sha256.Sum256([]byte(content))
	return prefix + hex.EncodeToString(sum[:12])
}

// canonicalBlock drops cache_control markers, which move between turns and
// are not part of the cached content. Every block is re-encoded the same way
// so a block with a marker compares equal to the same block without one, as
// it does at a real provider. Byte-level instability is still caught by the
// replay check, which compares raw bodies.
func canonicalBlock(b json.RawMessage) string {
	var v any
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	if dec.Decode(&v) != nil {
		return string(b)
	}
	var strip func(any) any
	strip = func(v any) any {
		switch t := v.(type) {
		case map[string]any:
			delete(t, "cache_control")
			for k, e := range t {
				t[k] = strip(e)
			}
		case []any:
			for i, e := range t {
				t[i] = strip(e)
			}
		}
		return v
	}
	var out bytes.Buffer
	enc := json.NewEncoder(&out)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(strip(v)); err != nil {
		return string(b)
	}
	return strings.TrimSuffix(out.String(), "\n")
}
