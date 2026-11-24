// SPDX-License-Identifier: AGPL-3.0-only

package fakeprovider

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/coder/websocket"

	"github.com/heliopsy/scrim/internal/leak"
)

// The WebSocket APIs.
//
// Realtime (/v1/realtime?model=...): on connect the fake sends
// session.created. session.update merges into the session and is answered
// with session.updated; conversation.item.create stores the item and is
// answered with conversation.item.added and conversation.item.done;
// input_audio_buffer.append is recorded and not answered; response.create
// builds a [Turn] from the conversation (or from response.input, for an
// out-of-band response), asks the [Responder] and streams the reply with GA
// event names, text and function call arguments in small deltas, ending
// with response.done. Every server event carries an event_id.
//
// Responses WebSocket mode (GET /v1/responses upgraded): each client event
// is {"type":"response.create", ...} with the fields of a Responses create
// body at the top level, answered with the same events the SSE stream
// carries, response.created to response.completed, one per message.
//
// In both, a reply with a non-200 Status, an unknown client event and a
// message that is not JSON are answered with an error event and the
// connection stays open, as the real APIs do.

// wsReadLimit bounds one client message.
const wsReadLimit = 256 << 20

// wsAPI reports whether a request is a WebSocket upgrade to one of the
// WebSocket APIs, under any path prefix.
func wsAPI(r *http.Request) (API, bool) {
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") || !headerToken(r.Header, "Connection", "upgrade") {
		return "", false
	}
	switch {
	case strings.HasSuffix(r.URL.Path, "/realtime"):
		return OpenAIRealtime, true
	case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/responses"):
		return OpenAIResponsesWS, true
	}
	return "", false
}

func headerToken(h http.Header, key, token string) bool {
	for _, v := range h.Values(key) {
		for _, t := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(t), token) {
				return true
			}
		}
	}
	return false
}

// wsConn is the state of one WebSocket connection.
type wsConn struct {
	s    *Server
	c    *websocket.Conn
	api  API
	base Exchange
	// seen is every message received so far, for reply IDs that depend on
	// the conversation, and placeholders the conversation's placeholders.
	seen         []byte
	placeholders []string
	// Realtime state.
	session map[string]any
	items   []any
	convID  string
	events  int
	// Responses WebSocket mode: the full input and output of each response
	// on this connection, by response id, for previous_response_id.
	history map[string][]any
}

func (s *Server) serveWS(w http.ResponseWriter, r *http.Request, api API) {
	s.mu.Lock()
	s.conns++
	n := s.conns
	s.mu.Unlock()
	base := Exchange{
		Capture: leak.Capture{Method: r.Method, Path: r.URL.Path, RawQuery: r.URL.RawQuery, Header: r.Header.Clone()},
		API:     api, Stream: true, Conn: n,
	}
	if api == OpenAIRealtime {
		base.Model = r.URL.Query().Get("model")
	}
	hs := base
	hs.Time, hs.WS = time.Now().UTC(), "handshake"
	var head strings.Builder
	head.WriteString(r.URL.RawQuery)
	for _, vs := range r.Header {
		for _, v := range vs {
			head.WriteString("\n" + v)
		}
	}
	hs.Placeholders = uniq(s.opts.PlaceholderPattern.FindAllString(head.String(), -1))
	if s.opts.RequireAuth && !authenticated(r) {
		rw := &recorder{ResponseWriter: w, status: http.StatusOK}
		s.apiError(rw, api, http.StatusUnauthorized, "authentication_error", "missing credentials")
		hs.Status, hs.Response = rw.status, rw.buf.Bytes()
		s.record(hs)
		return
	}
	hs.Status = http.StatusSwitchingProtocols
	s.record(hs)
	c, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
	if err != nil {
		return
	}
	defer func() { _ = c.CloseNow() }()
	c.SetReadLimit(wsReadLimit)
	ctx := r.Context()
	wc := &wsConn{s: s, c: c, api: api, base: base}
	if api == OpenAIRealtime {
		sum := sha256.Sum256([]byte(r.URL.String()))
		seed := hex.EncodeToString(sum[:])
		wc.convID = StableID("conv_", seed)
		wc.session = map[string]any{
			"type": "realtime", "object": "realtime.session", "id": StableID("sess_", seed), "model": base.Model,
			"output_modalities": []any{"audio"}, "instructions": "", "tools": []any{}, "tool_choice": "auto",
		}
		ev := wc.realtimeEvent("session.created", map[string]any{"session": wc.session})
		if wc.write(ctx, [][]byte{ev}) != nil {
			return
		}
	}
	for {
		typ, msg, err := c.Read(ctx)
		if err != nil {
			return
		}
		ex := base
		ex.Time, ex.Body, ex.WS = time.Now().UTC(), msg, "text"
		if typ == websocket.MessageBinary {
			ex.WS = "binary"
		}
		ex.Placeholders = uniq(s.opts.PlaceholderPattern.FindAllString(string(msg), -1))
		wc.seen = append(append(wc.seen, msg...), '\n')
		wc.placeholders = uniq(append(wc.placeholders, ex.Placeholders...))
		var events [][]byte
		switch api {
		case OpenAIRealtime:
			events, ex.Status = wc.realtime(msg, &ex)
		default:
			events, ex.Status = wc.responses(msg, &ex)
		}
		ex.Response = bytes.Join(events, []byte("\n"))
		s.record(ex)
		if wc.write(ctx, events) != nil {
			return
		}
	}
}

func (wc *wsConn) write(ctx context.Context, events [][]byte) error {
	for _, e := range events {
		if err := wc.c.Write(ctx, websocket.MessageText, e); err != nil {
			return err
		}
	}
	return nil
}

func (wc *wsConn) responder() Responder {
	wc.s.mu.Lock()
	defer wc.s.mu.Unlock()
	return wc.s.opts.Responder
}

func marshalEvent(v map[string]any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		return []byte(`{"type":"error","error":{"type":"server_error","code":"marshal","message":"marshal"}}`)
	}
	return b
}

func decodeObject(msg []byte) (map[string]any, bool) {
	var m map[string]any
	dec := json.NewDecoder(bytes.NewReader(msg))
	dec.UseNumber()
	if dec.Decode(&m) != nil || m == nil {
		return nil, false
	}
	return m, true
}

func errorCode(status int) string {
	switch status {
	case http.StatusTooManyRequests:
		return "rate_limit_exceeded"
	case http.StatusUnauthorized:
		return "invalid_api_key"
	}
	return errorType(status)
}

// Realtime.

// realtimeEvent builds one server event with its type and a fresh event_id.
func (wc *wsConn) realtimeEvent(typ string, v map[string]any) []byte {
	wc.events++
	v["type"] = typ
	v["event_id"] = StableID("event_", wc.convID+"/"+strconv.Itoa(wc.events))
	return marshalEvent(v)
}

func (wc *wsConn) realtimeError(status int, code, msg string, clientEvent any) [][]byte {
	return [][]byte{wc.realtimeEvent("error", map[string]any{"error": map[string]any{
		"type": errorType(status), "code": code, "message": msg, "param": nil, "event_id": clientEvent,
	}})}
}

func (wc *wsConn) realtime(msg []byte, ex *Exchange) ([][]byte, int) {
	m, ok := decodeObject(msg)
	if !ok {
		return wc.realtimeError(http.StatusBadRequest, "invalid_json", "the message is not a JSON object", nil), http.StatusBadRequest
	}
	typ, _ := m["type"].(string)
	clientEvent := m["event_id"]
	switch typ {
	case "session.update":
		upd, ok := m["session"].(map[string]any)
		if !ok {
			return wc.realtimeError(http.StatusBadRequest, "missing_required_parameter", "session.update needs a session object", clientEvent), http.StatusBadRequest
		}
		for k, v := range upd {
			wc.session[k] = v
		}
		return [][]byte{wc.realtimeEvent("session.updated", map[string]any{"session": wc.session})}, http.StatusOK
	case "conversation.item.create":
		item, ok := m["item"].(map[string]any)
		if !ok {
			return wc.realtimeError(http.StatusBadRequest, "missing_required_parameter", "conversation.item.create needs an item", clientEvent), http.StatusBadRequest
		}
		var prev any
		if len(wc.items) > 0 {
			prev = wc.items[len(wc.items)-1].(map[string]any)["id"]
		}
		if _, ok := item["id"].(string); !ok {
			item["id"] = StableID("item_", string(wc.seen))
		}
		item["object"] = "realtime.item"
		if _, ok := item["status"]; !ok {
			item["status"] = "completed"
		}
		wc.items = append(wc.items, item)
		return [][]byte{
			wc.realtimeEvent("conversation.item.added", map[string]any{"previous_item_id": prev, "item": item}),
			wc.realtimeEvent("conversation.item.done", map[string]any{"previous_item_id": prev, "item": item}),
		}, http.StatusOK
	case "input_audio_buffer.append":
		return nil, http.StatusOK
	case "response.create":
		return wc.realtimeResponse(m, ex)
	}
	return wc.realtimeError(http.StatusBadRequest, "unknown_event", "unknown client event type "+jsonString(typ), clientEvent), http.StatusBadRequest
}

func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func (wc *wsConn) realtimeResponse(m map[string]any, ex *Exchange) ([][]byte, int) {
	resp, _ := m["response"].(map[string]any)
	input := append([]any{}, wc.items...)
	outOfBand := false
	if in, ok := resp["input"].([]any); ok {
		input, outOfBand = in, true
	}
	instructions := wc.session["instructions"]
	if v, ok := resp["instructions"]; ok {
		instructions = v
	}
	tools := wc.session["tools"]
	if v, ok := resp["tools"]; ok {
		tools = v
	}
	body := map[string]any{"model": wc.base.Model, "instructions": instructions, "tools": tools, "input": input}
	if md, ok := resp["metadata"]; ok {
		body["metadata"] = md
	}
	bodyJSON, _ := json.Marshal(body)
	turn := Turn{API: OpenAIRealtime, Model: wc.base.Model, Stream: true, Body: body, Placeholders: wc.placeholders, Header: wc.base.Header}
	turn.ToolResults, turn.Assistant = countTurns(OpenAIResponses, map[string]any{"input": input})
	ex.PromptBytes = len(bodyJSON)
	reply := wc.responder()(turn)
	if reply.Status != 0 && reply.Status != http.StatusOK {
		return wc.realtimeError(reply.Status, errorCode(reply.Status), reply.Error, m["event_id"]), reply.Status
	}
	sum := sha256.Sum256(wc.seen)
	g := &gen{idSeed: hex.EncodeToString(sum[:]), chunk: wc.s.opts.ChunkSize, model: wc.base.Model, input: max(1, len(bodyJSON)/4)}
	respID := g.id("resp_")
	out := outputTokens(reply)
	var metadata any
	if md, ok := resp["metadata"]; ok {
		metadata = md
	}
	conv := any(wc.convID)
	if outOfBand {
		conv = nil
	}
	response := func(status string, output []any, usage bool) map[string]any {
		r := map[string]any{
			"object": "realtime.response", "id": respID, "status": status, "status_details": nil,
			"output": output, "conversation_id": conv, "output_modalities": []any{"text"},
			"metadata": metadata, "usage": nil,
		}
		if usage {
			r["usage"] = map[string]any{
				"total_tokens": g.input + out, "input_tokens": g.input, "output_tokens": out,
				"input_token_details":  map[string]any{"text_tokens": g.input, "audio_tokens": 0, "cached_tokens": 0},
				"output_token_details": map[string]any{"text_tokens": out, "audio_tokens": 0},
			}
		}
		return r
	}
	var events [][]byte
	ev := func(typ string, v map[string]any) { events = append(events, wc.realtimeEvent(typ, v)) }
	ev("response.created", map[string]any{"response": response("in_progress", []any{}, false)})
	var output []any
	idx := 0
	if reply.Text != "" {
		itemID := g.id("item_")
		item := map[string]any{"id": itemID, "object": "realtime.item", "type": "message", "status": "completed", "role": "assistant",
			"content": []any{map[string]any{"type": "output_text", "text": reply.Text}}}
		ev("response.output_item.added", map[string]any{"response_id": respID, "output_index": idx,
			"item": map[string]any{"id": itemID, "object": "realtime.item", "type": "message", "status": "in_progress", "role": "assistant", "content": []any{}}})
		where := func(v map[string]any) map[string]any {
			v["response_id"], v["item_id"], v["output_index"], v["content_index"] = respID, itemID, idx, 0
			return v
		}
		ev("response.content_part.added", where(map[string]any{"part": map[string]any{"type": "output_text", "text": ""}}))
		for _, p := range g.pieces(reply.Text) {
			ev("response.output_text.delta", where(map[string]any{"delta": p}))
		}
		ev("response.output_text.done", where(map[string]any{"text": reply.Text}))
		ev("response.content_part.done", where(map[string]any{"part": map[string]any{"type": "output_text", "text": reply.Text}}))
		ev("response.output_item.done", map[string]any{"response_id": respID, "output_index": idx, "item": item})
		output = append(output, item)
		idx++
	}
	for _, tc := range reply.ToolCalls {
		itemID, callID, args := g.id("item_"), g.id("call_"), inputJSON(tc)
		item := map[string]any{"id": itemID, "object": "realtime.item", "type": "function_call", "status": "completed",
			"name": tc.Name, "call_id": callID, "arguments": args}
		ev("response.output_item.added", map[string]any{"response_id": respID, "output_index": idx,
			"item": map[string]any{"id": itemID, "object": "realtime.item", "type": "function_call", "status": "in_progress", "name": tc.Name, "call_id": callID, "arguments": ""}})
		for _, p := range g.pieces(args) {
			ev("response.function_call_arguments.delta", map[string]any{"response_id": respID, "item_id": itemID, "output_index": idx, "call_id": callID, "delta": p})
		}
		ev("response.function_call_arguments.done", map[string]any{"response_id": respID, "item_id": itemID, "output_index": idx, "call_id": callID, "name": tc.Name, "arguments": args})
		ev("response.output_item.done", map[string]any{"response_id": respID, "output_index": idx, "item": item})
		output = append(output, item)
		idx++
	}
	if output == nil {
		output = []any{}
	}
	ev("response.done", map[string]any{"response": response("completed", output, true)})
	if !outOfBand {
		wc.items = append(wc.items, output...)
	}
	return events, http.StatusOK
}

// Responses WebSocket mode.

func (wc *wsConn) responsesError(status int, code, msg string) [][]byte {
	return [][]byte{marshalEvent(map[string]any{"type": "error", "status": status, "error": map[string]any{
		"type": errorType(status), "code": code, "message": msg, "param": nil,
	}})}
}

func (wc *wsConn) responses(msg []byte, ex *Exchange) ([][]byte, int) {
	m, ok := decodeObject(msg)
	if !ok {
		return wc.responsesError(http.StatusBadRequest, "invalid_json", "the message is not a JSON object"), http.StatusBadRequest
	}
	if typ, _ := m["type"].(string); typ != "response.create" {
		return wc.responsesError(http.StatusBadRequest, "unknown_event", "unknown client event type "+jsonString(typ)), http.StatusBadRequest
	}
	delete(m, "type")
	full := wc.chain(m)
	ex.Model, _ = m["model"].(string)
	ex.PromptBytes, ex.CachedBytes = wc.s.cache(OpenAIResponses, ex.Model, msg)
	turn := Turn{API: OpenAIResponsesWS, Model: ex.Model, Stream: true, Body: full, Placeholders: ex.Placeholders, Header: wc.base.Header}
	turn.ToolResults, turn.Assistant = countTurns(OpenAIResponses, full)
	reply := wc.responder()(turn)
	if reply.Status != 0 && reply.Status != http.StatusOK {
		return wc.responsesError(reply.Status, errorCode(reply.Status), reply.Error), reply.Status
	}
	sum := sha256.Sum256(msg)
	g := &gen{idSeed: hex.EncodeToString(sum[:]), chunk: wc.s.opts.ChunkSize, model: ex.Model, cached: ex.CachedBytes / 4, input: max(1, ex.PromptBytes/4)}
	resp, evs := g.responsesEvents(reply)
	wc.remember(resp, full)
	out := make([][]byte, 0, len(evs))
	for _, e := range evs {
		out = append(out, marshalEvent(e.data))
	}
	return out, http.StatusOK
}

// chain returns the request as the model sees it: with previous_response_id
// naming an earlier response on this connection, its input and output come
// before the request's own input, as the Responses API does. An unknown id
// leaves the request as sent.
func (wc *wsConn) chain(m map[string]any) map[string]any {
	prev, _ := m["previous_response_id"].(string)
	past, ok := wc.history[prev]
	if prev == "" || !ok {
		return m
	}
	full := make(map[string]any, len(m))
	for k, v := range m {
		full[k] = v
	}
	input, _ := m["input"].([]any)
	full["input"] = append(slices.Clone(past), input...)
	return full
}

// remember stores a response's full input and output under its id.
func (wc *wsConn) remember(resp, req map[string]any) {
	id, _ := resp["id"].(string)
	if id == "" {
		return
	}
	input, _ := req["input"].([]any)
	output, _ := resp["output"].([]any)
	if wc.history == nil {
		wc.history = map[string][]any{}
	}
	wc.history[id] = append(slices.Clone(input), output...)
}
