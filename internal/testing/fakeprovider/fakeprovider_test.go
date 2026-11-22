// SPDX-License-Identifier: AGPL-3.0-only

package fakeprovider

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
)

const ph = "⟦scrim:leak-api-key:0123456789abcdef⟧"

func post(t *testing.T, url, body string) (int, []byte) {
	t.Helper()
	resp, err := http.Post(url, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}

func requestFor(api API, stream bool) string {
	s := "false"
	if stream {
		s = "true"
	}
	switch api {
	case Anthropic:
		return `{"model":"claude-x","max_tokens":10,"stream":` + s + `,"messages":[{"role":"user","content":"key is ` + ph + `"}]}`
	case OpenAIChat:
		return `{"model":"gpt-x","stream":` + s + `,"stream_options":{"include_usage":true},"messages":[{"role":"user","content":"key is ` + ph + `"}]}`
	case Gemini:
		return `{"contents":[{"role":"user","parts":[{"text":"key is ` + ph + `"}]}],"generationConfig":{"maxOutputTokens":10}}`
	default:
		return `{"model":"gpt-x","stream":` + s + `,"input":[{"role":"user","content":"key is ` + ph + `"}]}`
	}
}

// urlFor is the request URL of an API, streamed or not. Gemini streams by
// path, as server-sent events.
func urlFor(base string, api API, stream bool) string {
	if !stream {
		return base + api.Path()
	}
	p, q := api.StreamPath(true)
	if len(q) > 0 {
		p += "?" + q.Encode()
	}
	return base + p
}

func TestRoundTripEveryAPI(t *testing.T) {
	steps := []ScriptStep{{Text: "reading {{placeholder}} now", ToolCalls: []ScriptToolCall{{Name: "Bash", Input: map[string]any{"command": "echo {{placeholder}}"}}}}}
	fake := New(Options{Responder: Script(steps), ChunkSize: 3})
	srv := httptest.NewServer(fake)
	defer srv.Close()
	wantEvents := map[API][]string{
		Anthropic: {"message_start", "ping", "content_block_start", "content_block_delta", "content_block_stop", "content_block_start", "content_block_delta", "content_block_stop", "message_delta", "message_stop"},
		OpenAIResponses: {"response.created", "response.in_progress", "response.output_item.added", "response.content_part.added", "response.output_text.delta",
			"response.output_text.done", "response.content_part.done", "response.output_item.done", "response.output_item.added",
			"response.function_call_arguments.delta", "response.function_call_arguments.done", "response.output_item.done", "response.completed"},
	}
	for _, api := range APIs {
		for _, stream := range []bool{false, true} {
			status, body := post(t, urlFor(srv.URL, api, stream), requestFor(api, stream))
			if status != 200 {
				t.Fatalf("%s stream=%v: status %d %s", api, stream, status, body)
			}
			p, err := ParseReply(api, stream, body)
			if err != nil {
				t.Fatalf("%s stream=%v: %v", api, stream, err)
			}
			if p.Text != "reading "+ph+" now" {
				t.Errorf("%s stream=%v: text %q", api, stream, p.Text)
			}
			// Gemini function calls carry no ID; the name ties the
			// functionResponse to its call.
			if len(p.ToolCalls) != 1 || p.ToolCalls[0].Name != "Bash" || (p.ToolCalls[0].ID == "") != (api == Gemini) {
				t.Fatalf("%s stream=%v: calls %+v", api, stream, p.ToolCalls)
			}
			var in map[string]string
			if err := json.Unmarshal([]byte(p.ToolCalls[0].Arguments), &in); err != nil || in["command"] != "echo "+ph {
				t.Errorf("%s stream=%v: arguments %q", api, stream, p.ToolCalls[0].Arguments)
			}
			if stream {
				// Placeholders must be split across delta events to exercise
				// the proxy's holdback. Responses' done events repeat the full
				// text, as the real API does, so the proxy must restore those
				// too.
				// A Gemini functionCall part arrives whole, so only its text
				// chunks must split the placeholder.
				text := body
				if api == Gemini {
					text = body[:bytes.Index(body, []byte(`"functionCall"`))]
				}
				if api != OpenAIResponses && bytes.Contains(text, []byte(ph)) {
					t.Errorf("%s: placeholder arrived in one event", api)
				}
				if want := wantEvents[api]; want != nil {
					got := slices.Compact(slices.Clone(p.Events))
					if !slices.Equal(got, slices.Compact(slices.Clone(want))) {
						t.Errorf("%s events: %v", api, got)
					}
				}
				if api == OpenAIChat && p.Events[len(p.Events)-1] != "[DONE]" {
					t.Error("chat stream does not end with [DONE]")
				}
			}
		}
	}
	ex := fake.Exchanges()
	if len(ex) != 2*len(APIs) {
		t.Fatalf("recorded %d exchanges", len(ex))
	}
	for _, e := range ex {
		if len(e.Placeholders) != 1 || e.Placeholders[0] != ph {
			t.Errorf("exchange %d placeholders %v", e.Seq, e.Placeholders)
		}
		if e.API == Gemini && (e.Model != GeminiModel || e.Stream != strings.Contains(e.Path, ":streamGenerateContent")) {
			t.Errorf("gemini exchange %d: model %q stream %v path %s", e.Seq, e.Model, e.Stream, e.Path)
		}
	}
}

func TestPromptCacheCounters(t *testing.T) {
	fake := New(Options{})
	srv := httptest.NewServer(fake)
	defer srv.Close()
	turn1 := `{"model":"m","max_tokens":5,"system":"sys","messages":[{"role":"user","content":"hello there, a long enough prefix"}]}`
	turn2 := `{"model":"m","max_tokens":5,"system":"sys","messages":[{"role":"user","content":"hello there, a long enough prefix"},{"role":"assistant","content":"ok"},{"role":"user","content":"more"}]}`
	changed := `{"model":"m","max_tokens":5,"system":"sys","messages":[{"role":"user","content":"hello there, a long enough prefiX"},{"role":"assistant","content":"ok"},{"role":"user","content":"more"}]}`
	for _, b := range []string{turn1, turn2, changed} {
		post(t, srv.URL+"/v1/messages", b)
	}
	ex := fake.Exchanges()
	if ex[0].CachedBytes != 0 {
		t.Errorf("first request cached %d", ex[0].CachedBytes)
	}
	if ex[1].CachedBytes == 0 || ex[1].CachedBytes >= ex[1].PromptBytes {
		t.Errorf("second request cached %d of %d", ex[1].CachedBytes, ex[1].PromptBytes)
	}
	if ex[2].CachedBytes != len("system:\"sys\"") {
		t.Errorf("changed prefix cached %d, want only the system block", ex[2].CachedBytes)
	}
	var resp struct {
		Usage struct {
			CacheRead int `json:"cache_read_input_tokens"`
		} `json:"usage"`
	}
	_ = json.Unmarshal(ex[1].Response, &resp)
	if resp.Usage.CacheRead == 0 {
		t.Error("usage does not report cache reads")
	}
}

func TestErrorsAndControl(t *testing.T) {
	fake := New(Options{RequireAuth: true, Responder: func(Turn) Reply { return Reply{Status: 429, Error: "slow down"} }})
	srv := httptest.NewServer(fake)
	defer srv.Close()
	if s, _ := post(t, srv.URL+"/v1/messages", `{}`); s != 401 {
		t.Errorf("unauthenticated: %d", s)
	}
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/anthropic/v1/messages", strings.NewReader(`{"model":"m"}`))
	req.Header.Set("X-Api-Key", "k")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != 429 || resp.Header.Get("Retry-After") == "" || !strings.Contains(string(b), `"rate_limit_error"`) {
		t.Errorf("rate limit: %d %s", resp.StatusCode, b)
	}
	if s, _ := post(t, srv.URL+"/nowhere", `{}`); s != 404 {
		t.Errorf("unknown path: %d", s)
	}
	resp, _ = http.Get(srv.URL + "/_fake/exchanges")
	var ex []Exchange
	_ = json.NewDecoder(resp.Body).Decode(&ex)
	_ = resp.Body.Close()
	if len(ex) != 3 || ex[1].Header.Get("X-Api-Key") != "k" || string(ex[1].Body) != `{"model":"m"}` {
		t.Errorf("exchanges over HTTP: %+v", ex)
	}
	if s, _ := post(t, srv.URL+"/_fake/reset", ``); s != 204 || len(fake.Exchanges()) != 0 {
		t.Errorf("reset: %d", s)
	}
}

// A Responses tool call inside a namespace tool carries the namespace in the
// output item and, when streamed, in output_item.added as well.
func TestResponsesNamespacedToolCall(t *testing.T) {
	fake := New(Options{Responder: func(Turn) Reply {
		return Reply{ToolCalls: []ToolCall{{Namespace: "mcp__scrim", Name: "secrets_list", Input: map[string]any{}}}}
	}})
	srv := httptest.NewServer(fake)
	defer srv.Close()
	for _, stream := range []bool{false, true} {
		code, body := post(t, srv.URL+OpenAIResponses.Path(), requestFor(OpenAIResponses, stream))
		if code != http.StatusOK {
			t.Fatalf("stream=%v: status %d: %s", stream, code, body)
		}
		want := 1
		if stream {
			want = 3 // output_item.added, output_item.done, response.completed
		}
		if n := bytes.Count(body, []byte(`"namespace":"mcp__scrim"`)); n != want {
			t.Errorf("stream=%v: namespace appears %d times, want %d: %s", stream, n, want, body)
		}
	}
}

// Gemini streams by path: with alt=sse as server-sent events with no event
// names and no [DONE], without it as a JSON array whose elements are flushed
// one by one. Both carry the same chunks; only the last has finishReason and
// usageMetadata, and the functionCall part arrives whole with its
// thoughtSignature.
func TestGeminiStreamForms(t *testing.T) {
	steps := []ScriptStep{{Text: "reading {{placeholder}} now", ToolCalls: []ScriptToolCall{{Name: "Bash", Input: map[string]any{"command": "echo {{placeholder}}"}}}}}
	fake := New(Options{Responder: Script(steps), ChunkSize: 3})
	srv := httptest.NewServer(fake)
	defer srv.Close()
	req := requestFor(Gemini, true)
	var parsed []Parsed
	for _, sse := range []bool{true, false} {
		p, q := Gemini.StreamPath(sse)
		u := srv.URL + "/gemini" + p
		if len(q) > 0 {
			u += "?" + q.Encode()
		}
		resp, err := http.Post(u, "application/json", strings.NewReader(req))
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		ct := resp.Header.Get("Content-Type")
		if resp.StatusCode != 200 {
			t.Fatalf("sse=%v: status %d %s", sse, resp.StatusCode, body)
		}
		if sse {
			if ct != "text/event-stream" || !bytes.HasPrefix(body, []byte("data: {")) || bytes.Contains(body, []byte("event:")) || bytes.Contains(body, []byte("[DONE]")) {
				t.Errorf("sse framing: %s %q", ct, body)
			}
			if !bytes.HasSuffix(body, []byte("}\r\n\r\n")) {
				t.Errorf("sse chunks do not end with CRLF CRLF: %q", body)
			}
		} else {
			if !strings.HasPrefix(ct, "application/json") || !bytes.HasPrefix(body, []byte("[{")) || !bytes.HasSuffix(body, []byte("}\r\n]")) || !bytes.Contains(body, []byte("}\r\n,{")) {
				t.Errorf("json array framing: %s %q", ct, body)
			}
		}
		if bytes.Contains(body[:bytes.Index(body, []byte(`"functionCall"`))], []byte(ph)) {
			t.Errorf("sse=%v: placeholder arrived in one text chunk", sse)
		}
		if n := bytes.Count(body, []byte(`"finishReason":"STOP"`)); n != 1 {
			t.Errorf("sse=%v: finishReason appears %d times", sse, n)
		}
		if n := bytes.Count(body, []byte(`"cachedContentTokenCount"`)); n != 1 {
			t.Errorf("sse=%v: usageMetadata appears %d times", sse, n)
		}
		got, err := ParseReply(Gemini, true, body)
		if err != nil {
			t.Fatalf("sse=%v: %v", sse, err)
		}
		if got.Text != "reading "+ph+" now" || len(got.ToolCalls) != 1 || got.ToolCalls[0].Signature == "" || len(got.Events) < 3 {
			t.Errorf("sse=%v: parsed %+v", sse, got)
		}
		parsed = append(parsed, got)
	}
	if parsed[0].Text != parsed[1].Text || parsed[0].ToolCalls[0] != parsed[1].ToolCalls[0] || len(parsed[0].Events) != len(parsed[1].Events) {
		t.Errorf("stream forms differ: %+v vs %+v", parsed[0], parsed[1])
	}
	for _, e := range fake.Exchanges() {
		if !e.Stream || e.API != Gemini || e.Model != GeminiModel {
			t.Errorf("exchange %d: %+v", e.Seq, e)
		}
	}
}

// Thought parts are not answer text, and a functionResponse after a model
// turn counts as a tool result for the script.
func TestGeminiParseAndTurns(t *testing.T) {
	body := `{"candidates":[{"content":{"role":"model","parts":[{"text":"thinking","thought":true},{"text":"answer"},{"functionCall":{"name":"Read","args":{"file_path":".env"}},"thoughtSignature":"c2ln"}]},"finishReason":"STOP","index":0}]}`
	p, err := ParseReply(Gemini, false, []byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if p.Text != "answer" || len(p.ToolCalls) != 1 || p.ToolCalls[0].Arguments != `{"file_path":".env"}` || p.ToolCalls[0].Signature != "c2ln" {
		t.Errorf("parsed %+v", p)
	}
	fake := New(Options{Responder: func(tn Turn) Reply {
		if tn.ToolResults != 1 || tn.Assistant != 1 {
			return Reply{Status: 400, Error: "wrong turn count"}
		}
		return Reply{Text: "done"}
	}})
	srv := httptest.NewServer(fake)
	defer srv.Close()
	req := `{"systemInstruction":{"parts":[{"text":"sys"}]},"tools":[{"functionDeclarations":[{"name":"Read","description":"d","parameters":{"type":"object"}}]}],"contents":[{"role":"user","parts":[{"text":"hi"}]},{"role":"model","parts":[{"functionCall":{"name":"Read","args":{}}}]},{"role":"user","parts":[{"functionResponse":{"name":"Read","response":{"output":"x"}}}]}]}`
	if code, b := post(t, srv.URL+Gemini.Path(), req); code != 200 {
		t.Fatalf("status %d %s", code, b)
	}
	if ex := fake.Exchanges(); ex[0].PromptBytes == 0 {
		t.Error("gemini prompt blocks not counted")
	}
}

func TestGeminiErrorsAuthAndCountTokens(t *testing.T) {
	fake := New(Options{RequireAuth: true, Responder: func(Turn) Reply { return Reply{Status: 429, Error: "slow down"} }})
	srv := httptest.NewServer(fake)
	defer srv.Close()
	code, b := post(t, srv.URL+Gemini.Path(), requestFor(Gemini, false))
	if code != 401 || !strings.Contains(string(b), `"status":"UNAUTHENTICATED"`) || !strings.Contains(string(b), `"code":401`) {
		t.Errorf("unauthenticated: %d %s", code, b)
	}
	code, b = post(t, srv.URL+Gemini.Path()+"?key=k", requestFor(Gemini, false))
	if code != 429 || !strings.Contains(string(b), `"status":"RESOURCE_EXHAUSTED"`) {
		t.Errorf("key query: %d %s", code, b)
	}
	r, _ := http.NewRequest(http.MethodPost, srv.URL+Gemini.Path(), strings.NewReader(requestFor(Gemini, false)))
	r.Header.Set("X-Goog-Api-Key", "k")
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 429 {
		t.Errorf("x-goog-api-key: %d", resp.StatusCode)
	}
	code, b = post(t, srv.URL+"/v1beta/models/gemini-2.5-flash:countTokens", requestFor(Gemini, false))
	if code != 200 || !strings.Contains(string(b), `"totalTokens":`) {
		t.Errorf("countTokens: %d %s", code, b)
	}
	if ex := fake.Exchanges(); ex[len(ex)-1].Model != "gemini-2.5-flash" || ex[len(ex)-1].API != Gemini {
		t.Errorf("countTokens exchange: %+v", ex[len(ex)-1])
	}
}
