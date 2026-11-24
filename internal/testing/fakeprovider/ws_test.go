// SPDX-License-Identifier: AGPL-3.0-only

package fakeprovider

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
)

func wsURL(base, path string) string { return "ws" + strings.TrimPrefix(base, "http") + path }

func dialWS(t *testing.T, u string, h http.Header) *websocket.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, _, err := websocket.Dial(ctx, u, &websocket.DialOptions{HTTPHeader: h})
	if err != nil {
		t.Fatal(err)
	}
	c.SetReadLimit(64 << 20)
	t.Cleanup(func() { _ = c.CloseNow() })
	return c
}

func sendWS(t *testing.T, c *websocket.Conn, typ websocket.MessageType, msg string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := c.Write(ctx, typ, []byte(msg)); err != nil {
		t.Fatal(err)
	}
}

// readWS reads server events until one of the given types arrives.
func readWS(t *testing.T, c *websocket.Conn, until ...string) [][]byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var out [][]byte
	for {
		_, b, err := c.Read(ctx)
		if err != nil {
			t.Fatalf("read after %d events: %v", len(out), err)
		}
		out = append(out, b)
		var ev struct {
			Type string `json:"type"`
		}
		_ = json.Unmarshal(b, &ev)
		if slices.Contains(until, ev.Type) {
			return out
		}
	}
}

func eventTypes(t *testing.T, evs [][]byte) []string {
	t.Helper()
	var out []string
	for _, b := range evs {
		var ev struct {
			Type    string `json:"type"`
			EventID string `json:"event_id"`
		}
		if err := json.Unmarshal(b, &ev); err != nil {
			t.Fatalf("event %s: %v", b, err)
		}
		out = append(out, ev.Type)
	}
	return out
}

func bearer() http.Header { return http.Header{"Authorization": {"Bearer k"}} }

func TestRealtimeConversation(t *testing.T) {
	steps := []ScriptStep{{Text: "reading {{placeholder}} now", ToolCalls: []ScriptToolCall{{Name: "Bash", Input: map[string]any{"command": "echo {{placeholder}}"}}}}}
	var turns []Turn
	script := Script(steps)
	fake := New(Options{ChunkSize: 3, RequireAuth: true, Responder: func(tn Turn) Reply { turns = append(turns, tn); return script(tn) }})
	srv := httptest.NewServer(fake)
	defer srv.Close()
	c := dialWS(t, wsURL(srv.URL, "/openai/v1/realtime?model=gpt-realtime"), bearer())

	created := readWS(t, c, "session.created")
	if len(created) != 1 || !bytes.Contains(created[0], []byte(`"model":"gpt-realtime"`)) {
		t.Fatalf("session.created: %s", created)
	}
	sendWS(t, c, websocket.MessageText, `{"type":"session.update","session":{"type":"realtime","instructions":"be brief"}}`)
	if got := readWS(t, c, "session.updated"); !bytes.Contains(got[0], []byte(`"instructions":"be brief"`)) {
		t.Errorf("session.updated: %s", got)
	}
	user := `{"type":"conversation.item.create","item":{"type":"message","role":"user","content":[{"type":"input_text","text":"key is ` + ph + `"}]}}`
	sendWS(t, c, websocket.MessageText, user)
	if got := eventTypes(t, readWS(t, c, "conversation.item.done")); !slices.Equal(got, []string{"conversation.item.added", "conversation.item.done"}) {
		t.Errorf("item events: %v", got)
	}
	out := `{"type":"conversation.item.create","item":{"type":"function_call_output","call_id":"call_1","output":"ok"}}`
	sendWS(t, c, websocket.MessageBinary, out)
	readWS(t, c, "conversation.item.done")
	sendWS(t, c, websocket.MessageText, `{"type":"input_audio_buffer.append","audio":"AAAA"}`)
	sendWS(t, c, websocket.MessageText, `{"type":"response.create"}`)
	evs := readWS(t, c, "response.done")
	want := []string{"response.created", "response.output_item.added", "response.content_part.added", "response.output_text.delta",
		"response.output_text.done", "response.content_part.done", "response.output_item.done", "response.output_item.added",
		"response.function_call_arguments.delta", "response.function_call_arguments.done", "response.output_item.done", "response.done"}
	// input_audio_buffer.append is not answered: the next event belongs to
	// response.create.
	if got := slices.Compact(eventTypes(t, evs)); !slices.Equal(got, want) {
		t.Errorf("response events: %v", got)
	}
	for _, b := range evs {
		if !bytes.Contains(b, []byte(`"event_id":"event_`)) {
			t.Errorf("event without event_id: %s", b)
		}
	}
	deltas := 0
	for _, b := range evs {
		if bytes.Contains(b, []byte(`"response.output_text.delta"`)) || bytes.Contains(b, []byte(`"response.function_call_arguments.delta"`)) {
			deltas++
			if bytes.Contains(b, []byte(ph)) {
				t.Errorf("placeholder arrived in one delta: %s", b)
			}
			for _, k := range []string{`"response_id":"resp_`, `"item_id":"item_`, `"output_index":`} {
				if !bytes.Contains(b, []byte(k)) {
					t.Errorf("delta without %s: %s", k, b)
				}
			}
		}
	}
	if deltas < 4 {
		t.Errorf("only %d deltas", deltas)
	}
	p, err := ParseEvents(OpenAIRealtime, evs)
	if err != nil {
		t.Fatal(err)
	}
	if p.Text != "reading "+ph+" now" || len(p.ToolCalls) != 1 || p.ToolCalls[0].Name != "Bash" || !strings.HasPrefix(p.ToolCalls[0].ID, "call_") {
		t.Fatalf("parsed %+v", p)
	}
	var in map[string]string
	if err := json.Unmarshal([]byte(p.ToolCalls[0].Arguments), &in); err != nil || in["command"] != "echo "+ph {
		t.Errorf("arguments %q", p.ToolCalls[0].Arguments)
	}
	last := evs[len(evs)-1]
	if !bytes.Contains(last, []byte(`"type":"function_call"`)) || !bytes.Contains(last, []byte(`"type":"output_text"`)) || !bytes.Contains(last, []byte(`"usage":{`)) {
		t.Errorf("response.done does not hold the output items and usage: %s", last)
	}
	if len(turns) != 1 || turns[0].ToolResults != 1 || turns[0].Body["instructions"] != "be brief" || !slices.Equal(turns[0].Placeholders, []string{ph}) {
		t.Fatalf("turns: %+v", turns)
	}

	ex := fake.Exchanges()
	kinds := []string{"handshake", "text", "text", "binary", "text", "text"}
	if len(ex) != len(kinds) {
		t.Fatalf("recorded %d exchanges", len(ex))
	}
	for i, e := range ex {
		if e.WS != kinds[i] || e.API != OpenAIRealtime || e.Conn != 1 || e.Method != http.MethodGet ||
			e.Path != "/openai/v1/realtime" || e.RawQuery != "model=gpt-realtime" || e.Header.Get("Authorization") != "Bearer k" || e.Model != RealtimeModel {
			t.Errorf("exchange %d: %+v", i, e)
		}
	}
	if ex[0].Status != http.StatusSwitchingProtocols || len(ex[0].Body) != 0 {
		t.Errorf("handshake exchange: %+v", ex[0])
	}
	if string(ex[2].Body) != user || !slices.Equal(ex[2].Placeholders, []string{ph}) || string(ex[3].Body) != out {
		t.Errorf("message bodies or placeholders: %q %v %q", ex[2].Body, ex[2].Placeholders, ex[3].Body)
	}
	if len(ex[4].Response) != 0 || !bytes.Equal(ex[5].Response, bytes.Join(evs, []byte("\n"))) {
		t.Errorf("responses: %q / %d bytes", ex[4].Response, len(ex[5].Response))
	}
	// The JSON form keeps the WebSocket fields.
	b, _ := json.Marshal(ex[3])
	var back Exchange
	if err := json.Unmarshal(b, &back); err != nil || back.WS != "binary" || back.Conn != 1 || string(back.Body) != out {
		t.Errorf("exchange JSON round trip: %v %+v", err, back)
	}
	pr, err := ParseReply(OpenAIRealtime, true, ex[5].Response)
	if err != nil || pr.Text != p.Text || len(pr.ToolCalls) != 1 {
		t.Errorf("ParseReply of the recorded response: %v %+v", err, pr)
	}
}

// A second response.create sees the first response's output in the
// conversation, as the Script responder's turn count needs.
func TestRealtimeConversationState(t *testing.T) {
	var assistant []int
	fake := New(Options{Responder: func(tn Turn) Reply { assistant = append(assistant, tn.Assistant); return Reply{Text: "ok"} }})
	srv := httptest.NewServer(fake)
	defer srv.Close()
	c := dialWS(t, wsURL(srv.URL, "/v1/realtime?model=gpt-realtime"), nil)
	readWS(t, c, "session.created")
	for range 2 {
		sendWS(t, c, websocket.MessageText, `{"type":"response.create"}`)
		readWS(t, c, "response.done")
	}
	// An out-of-band response uses its own input and leaves the
	// conversation alone.
	sendWS(t, c, websocket.MessageText, `{"type":"response.create","response":{"conversation":"none","input":[],"metadata":{"k":"v"}}}`)
	done := readWS(t, c, "response.done")
	if !bytes.Contains(done[len(done)-1], []byte(`"metadata":{"k":"v"}`)) || !bytes.Contains(done[len(done)-1], []byte(`"conversation_id":null`)) {
		t.Errorf("out-of-band response.done: %s", done[len(done)-1])
	}
	if !slices.Equal(assistant, []int{0, 1, 0}) {
		t.Errorf("assistant turns %v", assistant)
	}
}

func TestRealtimeErrors(t *testing.T) {
	fake := New(Options{Responder: func(Turn) Reply { return Reply{Status: 429, Error: "slow down"} }})
	srv := httptest.NewServer(fake)
	defer srv.Close()
	c := dialWS(t, wsURL(srv.URL, "/v1/realtime?model=gpt-realtime"), nil)
	readWS(t, c, "session.created")
	for _, tc := range []struct{ msg, code string }{
		{`{"type":"response.create","event_id":"evt_1"}`, "rate_limit_exceeded"},
		{`{"type":"no.such.event"}`, "unknown_event"},
		{`not json`, "invalid_json"},
		{`{"type":"conversation.item.create"}`, "missing_required_parameter"},
	} {
		sendWS(t, c, websocket.MessageText, tc.msg)
		evs := readWS(t, c, "error")
		p, err := ParseEvents(OpenAIRealtime, evs)
		if err != nil || !slices.Equal(p.Errors, []string{tc.code}) || !bytes.Contains(evs[0], []byte(`"event_id":"event_`)) {
			t.Errorf("%s: %v %+v %s", tc.msg, err, p, evs)
		}
	}
	// The connection stays open after errors.
	sendWS(t, c, websocket.MessageText, `{"type":"session.update","session":{}}`)
	readWS(t, c, "session.updated")
	ex := fake.Exchanges()
	if ex[1].Status != 429 || ex[2].Status != 400 || ex[5].Status != 200 {
		t.Errorf("statuses %d %d %d", ex[1].Status, ex[2].Status, ex[5].Status)
	}
}

func TestWebSocketHandshake(t *testing.T) {
	fake := New(Options{RequireAuth: true})
	srv := httptest.NewServer(fake)
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, resp, err := websocket.Dial(ctx, wsURL(srv.URL, "/v1/realtime?model=gpt-realtime&trace="+ph), nil)
	if err == nil || resp == nil || resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated handshake: %v %v", err, resp)
	}
	ex := fake.Exchanges()
	if len(ex) != 1 || ex[0].WS != "handshake" || ex[0].Status != 401 || !slices.Equal(ex[0].Placeholders, []string{ph}) || !bytes.Contains(ex[0].Response, []byte("authentication_error")) {
		t.Fatalf("refused handshake exchange: %+v", ex)
	}
	// Without an upgrade the Realtime path is not served, and GET
	// /v1/responses without one is not the WebSocket mode.
	for path, want := range map[string]int{"/v1/realtime": http.StatusUpgradeRequired, "/v1/responses": http.StatusMethodNotAllowed} {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+path, nil)
		req.Header.Set("Authorization", "Bearer k")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != want {
			t.Errorf("GET %s without upgrade: %d, want %d", path, resp.StatusCode, want)
		}
	}
}

func TestResponsesWebSocket(t *testing.T) {
	steps := []ScriptStep{{Text: "reading {{placeholder}} now", ToolCalls: []ScriptToolCall{{Name: "Bash", Input: map[string]any{"command": "echo {{placeholder}}"}}}}}
	fake := New(Options{Responder: Script(steps), ChunkSize: 3})
	srv := httptest.NewServer(fake)
	defer srv.Close()
	// The SSE stream of the same request is the reference.
	status, sse := post(t, srv.URL+"/v1/responses", requestFor(OpenAIResponses, true))
	if status != 200 {
		t.Fatalf("sse: %d", status)
	}
	ref, err := ParseReply(OpenAIResponses, true, sse)
	if err != nil {
		t.Fatal(err)
	}

	c := dialWS(t, wsURL(srv.URL, "/openai/v1/responses"), bearer())
	msg := `{"type":"response.create","model":"gpt-x","store":false,"tools":[{"type":"function","name":"Bash","parameters":{"type":"object"}}],"input":[{"role":"user","content":"key is ` + ph + `"}]}`
	sendWS(t, c, websocket.MessageText, msg)
	evs := readWS(t, c, "response.completed")
	got, err := ParseEvents(OpenAIResponsesWS, evs)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got.Events, ref.Events) || got.Text != ref.Text || len(got.ToolCalls) != 1 || got.ToolCalls[0].Arguments != ref.ToolCalls[0].Arguments {
		t.Errorf("websocket mode differs from the SSE stream:\n%+v\n%+v", got, ref)
	}
	// The event data are the SSE data, one per message, apart from IDs and
	// usage, which depend on the request bytes.
	sseEvs, _ := sseEvents(sse)
	if len(sseEvs) != len(evs) {
		t.Fatalf("%d events over SSE, %d over WebSocket", len(sseEvs), len(evs))
	}
	var norm func(v any) any
	norm = func(v any) any {
		switch m := v.(type) {
		case map[string]any:
			for _, k := range []string{"id", "item_id", "call_id", "created_at", "usage"} {
				delete(m, k)
			}
			for k, e := range m {
				m[k] = norm(e)
			}
		case []any:
			for i, e := range m {
				m[i] = norm(e)
			}
		}
		return v
	}
	for i := range evs {
		var a, b any
		_ = json.Unmarshal(evs[i], &a)
		_ = json.Unmarshal([]byte(sseEvs[i][1]), &b)
		ja, _ := json.Marshal(norm(a))
		jb, _ := json.Marshal(norm(b))
		if !bytes.Equal(ja, jb) {
			t.Errorf("event %d differs:\n%s\n%s", i, ja, jb)
		}
	}
	// Errors keep the connection open.
	sendWS(t, c, websocket.MessageText, `{"type":"response.cancel"}`)
	if p, _ := ParseEvents(OpenAIResponsesWS, readWS(t, c, "error")); !slices.Equal(p.Errors, []string{"unknown_event"}) {
		t.Errorf("unknown event: %+v", p)
	}
	sendWS(t, c, websocket.MessageBinary, msg)
	readWS(t, c, "response.completed")
	ex := fake.Exchanges()
	if len(ex) != 5 || ex[0].API != OpenAIResponses || ex[1].WS != "handshake" || ex[2].WS != "text" || ex[3].Status != 400 || ex[4].WS != "binary" ||
		string(ex[2].Body) != msg || ex[2].Model != "gpt-x" || ex[2].API != OpenAIResponsesWS || ex[2].Status != 200 || !slices.Equal(ex[2].Placeholders, []string{ph}) {
		t.Fatalf("exchanges: %+v", ex)
	}
	// The repeated request finds its prompt in the cache.
	if ex[4].CachedBytes == 0 {
		t.Error("websocket mode does not report prompt caching")
	}
}

// TestResponsesWebSocketPreviousResponse checks that a response.create naming
// an earlier response on the socket is answered with that response's input
// and output in front of its own, as Codex chains turns over WebSocket.
func TestResponsesWebSocketPreviousResponse(t *testing.T) {
	var seen []Turn
	var mu sync.Mutex
	fake := New(Options{Responder: func(tn Turn) Reply {
		mu.Lock()
		defer mu.Unlock()
		seen = append(seen, tn)
		if tn.ToolResults == 0 {
			return Reply{ToolCalls: []ToolCall{{Name: "Bash", Input: map[string]any{"command": "ls"}}}}
		}
		return Reply{Text: "Done."}
	}})
	srv := httptest.NewServer(fake)
	defer srv.Close()
	c := dialWS(t, wsURL(srv.URL, "/v1/responses"), bearer())

	sendWS(t, c, websocket.MessageText, `{"type":"response.create","model":"gpt-x","input":[{"role":"user","content":"go"}]}`)
	var done struct {
		Response struct {
			ID     string `json:"id"`
			Output []struct {
				CallID string `json:"call_id"`
			} `json:"output"`
		} `json:"response"`
	}
	evs := readWS(t, c, "response.completed")
	if err := json.Unmarshal(evs[len(evs)-1], &done); err != nil || done.Response.ID == "" || len(done.Response.Output) != 1 {
		t.Fatalf("first response: %v %s", err, evs[len(evs)-1])
	}
	next := `{"type":"response.create","model":"gpt-x","previous_response_id":"` + done.Response.ID +
		`","input":[{"type":"function_call_output","call_id":"` + done.Response.Output[0].CallID + `","output":"a b"}]}`
	sendWS(t, c, websocket.MessageText, next)
	got, err := ParseEvents(OpenAIResponsesWS, readWS(t, c, "response.completed"))
	if err != nil || got.Text != "Done." {
		t.Fatalf("second response: %v %+v", err, got)
	}
	// An unknown id leaves the request as sent.
	sendWS(t, c, websocket.MessageText, `{"type":"response.create","model":"gpt-x","previous_response_id":"resp_unknown","input":[{"role":"user","content":"again"}]}`)
	readWS(t, c, "response.completed")

	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 3 {
		t.Fatalf("%d turns", len(seen))
	}
	in, _ := seen[1].Body["input"].([]any)
	if seen[1].ToolResults != 1 || len(in) != 3 {
		t.Errorf("chained turn: %d tool results, input %v", seen[1].ToolResults, in)
	}
	if in, _ := seen[2].Body["input"].([]any); len(in) != 1 {
		t.Errorf("unknown previous id: input %v", in)
	}
	// What was sent is recorded, not the chained input.
	ex := fake.Exchanges()
	if body := string(ex[len(ex)-2].Body); body != next {
		t.Errorf("recorded %s", body)
	}
}
