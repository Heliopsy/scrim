// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/heliopsy/scrim/internal/leak"
	"github.com/heliopsy/scrim/internal/testing/fakeprovider"
)

// TestEndToEndWebSocketRealDataPlane runs the daemon with the real data
// plane and the fake provider as the OpenAI upstream, and holds a Realtime
// conversation through scrim's base URL listener
// (/openai/v1/realtime?model=gpt-realtime).
//
// redacted: a conversation.item.create holding two display values in an
// input_text part, a function_call_output holding the credential, then
// response.create. Nothing the provider received holds a value in any
// encoding the leak checker knows, placeholders arrived, the agent's own
// Authorization passed through, and the reply the client received has the
// display value restored and the one a rule keeps (tier=prod) left as its
// placeholder, as TestRestoreRuleOnLabelRealDataPlane checks over HTTP.
//
// refused: a binary frame that is not UTF-8 cannot be scanned, so scrim
// answers it with a scrim_error event, closes the socket with 1008 and
// forwards nothing.
func TestEndToEndWebSocketRealDataPlane(t *testing.T) {
	bin := realDataPlane(t)
	fake := fakeprovider.New(fakeprovider.Options{})
	up := httptest.NewServer(fake)
	defer up.Close()

	token := seed(t, "sk-ws-")
	h := newHarness(t, token)
	note, prod := withLabels(t, h)
	h.opts.DataPlaneEnv = nil
	h.opts.Config.Environ = append(h.opts.Config.Environ, "SCRIM_DATAPLANE_PATH="+bin,
		"SCRIM_PROXY_UPSTREAM_OPENAI="+up.URL)
	d := startDaemon(t, h)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	checker := leak.NewChecker([]leak.Seed{
		leak.NewSeed("acme", leak.KindAPIKey, token),
		leak.NewSeed("note", leak.KindPassword, note),
		leak.NewSeed("prodnote", leak.KindPassword, prod),
	})
	u := "ws" + strings.TrimPrefix(d.Addrs().BaseURL, "http") + "/openai/v1/realtime?model=" + fakeprovider.RealtimeModel
	dial := func(t *testing.T) *websocket.Conn {
		t.Helper()
		dctx, dcancel := context.WithTimeout(ctx, 10*time.Second)
		defer dcancel()
		c, resp, err := websocket.Dial(dctx, u, &websocket.DialOptions{HTTPHeader: http.Header{"Authorization": {"Bearer agent-own-key"}}})
		if err != nil {
			status := 0
			if resp != nil {
				status = resp.StatusCode
			}
			t.Fatalf("dial through scrim: status %d: %v\n%s", status, err, h.logs.String())
		}
		c.SetReadLimit(16 << 20)
		t.Cleanup(func() { _ = c.CloseNow() })
		return c
	}
	write := func(t *testing.T, c *websocket.Conn, typ websocket.MessageType, msg []byte) {
		t.Helper()
		wctx, wcancel := context.WithTimeout(ctx, 10*time.Second)
		defer wcancel()
		if err := c.Write(wctx, typ, msg); err != nil {
			t.Fatal(err)
		}
	}
	// read returns the server events up to and including one of the given
	// types, and the error that ended the read when none arrived.
	read := func(c *websocket.Conn, until ...string) ([][]byte, error) {
		rctx, rcancel := context.WithTimeout(ctx, 15*time.Second)
		defer rcancel()
		var evs [][]byte
		for {
			_, b, err := c.Read(rctx)
			if err != nil {
				return evs, err
			}
			evs = append(evs, b)
			var ev struct {
				Type string `json:"type"`
			}
			_ = json.Unmarshal(b, &ev)
			if slices.Contains(until, ev.Type) {
				return evs, nil
			}
		}
	}
	event := func(v any) []byte {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}

	t.Run("redacted", func(t *testing.T) {
		var reply fakeprovider.Parsed
		eventually(t, "both display values redacted in a conversation", func() bool {
			fake.Reset()
			c := dial(t)
			if _, err := read(c, "session.created"); err != nil {
				t.Fatalf("session.created: %v", err)
			}
			write(t, c, websocket.MessageText, event(map[string]any{"type": "conversation.item.create", "item": map[string]any{
				"type": "message", "role": "user", "content": []any{map[string]any{"type": "input_text", "text": "notes: " + note + " and " + prod}},
			}}))
			write(t, c, websocket.MessageText, event(map[string]any{"type": "conversation.item.create", "item": map[string]any{
				"type": "function_call_output", "call_id": "call_e2e", "output": "API_TOKEN=" + token + "\n",
			}}))
			write(t, c, websocket.MessageText, event(map[string]any{"type": "response.create"}))
			evs, err := read(c, "response.done")
			if err != nil {
				t.Fatalf("conversation ended before response.done: %v (close %d)\n%s", err, websocket.CloseStatus(err), h.logs.String())
			}
			_ = c.Close(websocket.StatusNormalClosure, "")
			if reply, err = fakeprovider.ParseEvents(fakeprovider.OpenAIRealtime, evs); err != nil {
				t.Fatal(err)
			}
			var ph []string
			for _, e := range fake.Exchanges() {
				ph = append(ph, e.Placeholders...)
			}
			return slices.ContainsFunc(ph, func(p string) bool { return strings.HasPrefix(p, "⟦scrim:prodnote:") }) &&
				slices.ContainsFunc(ph, func(p string) bool { return strings.HasPrefix(p, "⟦scrim:note:") })
		})
		ex := fake.Exchanges()
		messages := 0
		for _, e := range ex {
			if fs := checker.Check(e.Capture); len(fs) > 0 {
				t.Fatalf("the provider received a value: exchange %d (%s) at %s", e.Seq, e.WS, fs[0].Location)
			}
			if e.WS == "handshake" && e.Header.Get("Authorization") != "Bearer agent-own-key" {
				t.Fatal("the agent's own credential did not pass through the handshake")
			}
			if e.WS == "text" || e.WS == "binary" {
				messages++
			}
		}
		if messages != 3 {
			t.Fatalf("the provider received %d messages, want 3", messages)
		}
		if !slices.ContainsFunc(ex, func(e fakeprovider.Exchange) bool {
			return slices.ContainsFunc(e.Placeholders, func(p string) bool { return strings.HasPrefix(p, "⟦scrim:acme:") })
		}) {
			t.Fatal("the credential in the function_call_output did not arrive as a placeholder")
		}
		if !strings.Contains(reply.Text, note) {
			t.Fatalf("the display value was not restored in the reply: %q", reply.Text)
		}
		if strings.Contains(reply.Text, prod) || !strings.Contains(reply.Text, "scrim:prodnote:") {
			t.Fatalf("the value labelled tier=prod was restored despite the rule: %q", reply.Text)
		}
	})

	t.Run("refused", func(t *testing.T) {
		fake.Reset()
		c := dial(t)
		if _, err := read(c, "session.created"); err != nil {
			t.Fatalf("session.created: %v", err)
		}
		// Not UTF-8: scrim cannot scan it, so it must not forward it.
		write(t, c, websocket.MessageBinary, append([]byte{0xff, 0xfe, 0x00, 0x80}, token...))
		evs, err := read(c)
		if code := websocket.CloseStatus(err); code != websocket.StatusPolicyViolation {
			t.Fatalf("socket ended with %v (close %d), want close 1008", err, code)
		}
		var ce websocket.CloseError
		if !errors.As(err, &ce) || ce.Reason != "unscannable_content" {
			t.Errorf("close reason %q, want unscannable_content", ce.Reason)
		}
		p, perr := fakeprovider.ParseEvents(fakeprovider.OpenAIRealtime, evs)
		if perr != nil || !slices.Equal(p.Errors, []string{"unscannable_content"}) {
			t.Errorf("error events %v (%v) in %q", p.Errors, perr, evs)
		}
		for _, e := range fake.Exchanges() {
			if e.WS != "handshake" {
				t.Fatalf("scrim forwarded a message it refused: exchange %d (%s)", e.Seq, e.WS)
			}
			if fs := checker.Check(e.Capture); len(fs) > 0 {
				t.Fatalf("the provider received a value in the handshake at %s", fs[0].Location)
			}
		}
	})

	for _, v := range []string{token, note, prod} {
		if strings.Contains(h.logs.String(), v) {
			t.Fatal("a value reached the log")
		}
	}
}
