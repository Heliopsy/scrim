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
	default:
		return `{"model":"gpt-x","stream":` + s + `,"input":[{"role":"user","content":"key is ` + ph + `"}]}`
	}
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
			status, body := post(t, srv.URL+api.Path(), requestFor(api, stream))
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
			if len(p.ToolCalls) != 1 || p.ToolCalls[0].Name != "Bash" || p.ToolCalls[0].ID == "" {
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
				if api != OpenAIResponses && bytes.Contains(body, []byte(ph)) {
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
	if len(ex) != 6 {
		t.Fatalf("recorded %d exchanges", len(ex))
	}
	for _, e := range ex {
		if len(e.Placeholders) != 1 || e.Placeholders[0] != ph {
			t.Errorf("exchange %d placeholders %v", e.Seq, e.Placeholders)
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
