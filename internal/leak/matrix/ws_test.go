// SPDX-License-Identifier: AGPL-3.0-only

package matrix_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/heliopsy/scrim/internal/leak"
	"github.com/heliopsy/scrim/internal/leak/matrix"
	"github.com/heliopsy/scrim/internal/leak/stub"
	fp "github.com/heliopsy/scrim/internal/testing/fakeprovider"
)

// refusing is a stand-in for scrim's WebSocket refusal: it opens the
// upstream socket with the client's headers (so the fake records the
// handshake), reads the first client message and, unless forward is set,
// answers it with a scrim_error event and closes the client socket with
// code. With forward it relays that one message upstream before refusing,
// the way a broken proxy would leak and then refuse.
func refusing(t *testing.T, upstream *url.URL, code websocket.StatusCode, forward bool) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u := *upstream
		u.Path, u.RawQuery = r.URL.Path, r.URL.RawQuery
		h := http.Header{}
		for k, vs := range r.Header {
			if !strings.HasPrefix(k, "Sec-Websocket") && k != "Connection" && k != "Upgrade" {
				h[k] = vs
			}
		}
		ctx := context.Background()
		up, _, err := websocket.Dial(ctx, u.String(), &websocket.DialOptions{HTTPHeader: h})
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer func() { _ = up.CloseNow() }()
		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer func() { _ = c.CloseNow() }()
		c.SetReadLimit(64 << 20)
		typ, msg, err := c.Read(ctx)
		if err != nil {
			return
		}
		relayed := make(chan struct{})
		go func() {
			defer close(relayed)
			if forward {
				// Still in flight when the client sees the close.
				time.Sleep(30 * time.Millisecond)
				_ = up.Write(ctx, typ, msg)
			}
		}()
		_ = c.Write(ctx, websocket.MessageText, []byte(`{"type":"error","error":{"type":"scrim_error","code":"unredactable","message":"scrim: refused"}}`))
		_ = c.Close(code, "unredactable")
		<-relayed
	}))
}

func row(t *testing.T, id string) matrix.Row {
	t.Helper()
	for _, r := range matrix.Rows() {
		if r.ID == id {
			return r
		}
	}
	t.Fatalf("no row %s", id)
	return matrix.Row{}
}

// A refusal on WebSocket is a close with 1008 or 1009 after an error event.
// The runner maps it to a 4xx and, when only the handshake reached the
// provider, to withheld; a value in the handshake or in a message relayed
// before the refusal is still a leak.
func TestWebSocketRefusalOutcomes(t *testing.T) {
	seed := leak.Generate(leak.KindAPIKey)
	for _, tc := range []struct {
		row     string
		code    websocket.StatusCode
		forward bool
		// behind puts the refusing stand-in behind the pass-through
		// stub, which must hand the close code on.
		behind  bool
		status  int
		outcome matrix.Outcome
		pass    bool
	}{
		{"openai-realtime/tool-result/reversed", websocket.StatusPolicyViolation, false, false, http.StatusUnprocessableEntity, matrix.OutcomeWithheld, true},
		{"openai-realtime/tool-result/raw", websocket.StatusPolicyViolation, false, false, http.StatusUnprocessableEntity, matrix.OutcomeWithheld, false},
		{"openai-responses-ws/tool-result/upper", websocket.StatusMessageTooBig, false, false, http.StatusRequestEntityTooLarge, matrix.OutcomeWithheld, true},
		{"openai-realtime/header/raw", websocket.StatusPolicyViolation, false, false, http.StatusUnprocessableEntity, matrix.OutcomeLeaked, false},
		{"openai-realtime/tool-result/upper", websocket.StatusPolicyViolation, true, false, http.StatusUnprocessableEntity, matrix.OutcomeLeaked, false},
		{"openai-realtime/tool-result/lower", websocket.StatusMessageTooBig, false, true, http.StatusRequestEntityTooLarge, matrix.OutcomeWithheld, true},
	} {
		t.Run(tc.row, func(t *testing.T) {
			h := newHarness(t, func(u *url.URL) *httptest.Server {
				px := refusing(t, u, tc.code, tc.forward)
				if !tc.behind {
					return px
				}
				t.Cleanup(px.Close)
				pu, _ := url.Parse(px.URL)
				return httptest.NewServer(stub.PassThrough(pu))
			})
			res := h.runner.RunRow(context.Background(), row(t, tc.row), seed)
			if len(res.Statuses) != 1 || res.Statuses[0] != tc.status || res.Outcome != tc.outcome || res.Pass != tc.pass {
				t.Fatalf("got %s pass=%v", res.Describe(), res.Pass)
			}
		})
	}
}

// A handshake the proxy refuses gets the proxy's status and body; without
// headers of its own a WebSocket row carries the agent's default provider
// authentication, which a provider requiring it accepts.
func TestWebSocketHandshakeStatus(t *testing.T) {
	r := row(t, "openai-realtime/user-text/raw").Placement.Build(fp.OpenAIRealtime, matrix.Content{Value: "x"}, matrix.EscapeMinimal)[0]
	deny := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "upgrade refused", http.StatusForbidden)
	}))
	defer deny.Close()
	status, body, err := matrix.Target{BaseURL: deny.URL}.Send(context.Background(), r)
	if err != nil || status != http.StatusForbidden || !strings.Contains(string(body), "upgrade refused") {
		t.Fatalf("refused handshake: %d %s %v", status, body, err)
	}
	fake := fp.New(fp.Options{RequireAuth: true})
	up := httptest.NewServer(fake)
	defer up.Close()
	status, body, err = matrix.Target{BaseURL: up.URL}.Send(context.Background(), r)
	if err != nil || status != http.StatusOK || !strings.Contains(string(body), `"response.done"`) {
		t.Fatalf("default authentication: %d %s %v", status, body, err)
	}
	if ex := fake.Exchanges(); len(ex) != 3 || ex[0].Header.Get("Authorization") != "Bearer fake-provider-key-not-a-seed" {
		t.Fatalf("exchanges: %+v", ex)
	}
}

// Every WebSocket row, sent straight to the fake provider, arrives as the
// messages it holds, text or binary, and completes with one response per
// response.create.
func TestWebSocketRowsArriveAsSent(t *testing.T) {
	fake := fp.New(fp.Options{})
	up := httptest.NewServer(fake)
	defer up.Close()
	target := matrix.Target{BaseURL: up.URL}
	n := 0
	for _, r := range matrix.Rows() {
		if !r.API.WebSocket() || r.Transform.ID != "raw" {
			continue
		}
		n++
		fake.Reset()
		reqs := r.Placement.Build(r.API, matrix.ContentFor(r.Transform, "a-value-that-is-not-a-secret"), r.Transform.Body)
		if len(reqs) != 1 || !reqs[0].WS {
			t.Fatalf("%s: %d requests, want one conversation", r.ID, len(reqs))
		}
		q := reqs[0]
		status, body, err := target.Send(context.Background(), q)
		if err != nil || status != http.StatusOK {
			t.Errorf("%s: %d %v", r.ID, status, err)
			continue
		}
		ex := fake.Exchanges()
		if len(ex) != len(q.Messages)+1 || ex[0].WS != "handshake" {
			t.Errorf("%s: %d exchanges for %d messages", r.ID, len(ex), len(q.Messages))
			continue
		}
		creates := 0
		for i, m := range q.Messages {
			e := ex[i+1]
			if string(e.Body) != string(m.Data) || (e.WS == "binary") != m.Binary || e.Status != http.StatusOK {
				t.Errorf("%s: message %d arrived as %s %d %q", r.ID, i, e.WS, e.Status, e.Body)
			}
			if strings.Contains(string(m.Data), `"type":"response.create"`) {
				creates++
			}
		}
		if done := strings.Count(string(body), `"type":"response.done"`) + strings.Count(string(body), `"type":"response.completed"`); done != creates || creates == 0 {
			t.Errorf("%s: %d responses completed for %d response.create", r.ID, done, creates)
		}
	}
	if n < 30 {
		t.Errorf("only %d WebSocket placements", n)
	}
}
