// SPDX-License-Identifier: AGPL-3.0-only

package ntfy

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/heliopsy/scrim/internal/notify"
	"github.com/heliopsy/scrim/internal/policy"
	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores"
)

func request(links bool) notify.Request {
	r := notify.Request{
		ApprovalID: "a1b2",
		Agent:      policy.Agent{ID: "claude-laptop", Kind: policy.IdentitySession},
		Summary: policy.Request{Action: policy.ActionInject, Ref: stores.MustParseRef("bao://kv/agents/github"),
			Host: "api.github.com", Method: "POST", Path: "/repos/a/b/issues?access_token=⟦scrim:github:00ff⟧"},
		Rule: "github-write", Reason: "writes need a human", ExpiresAt: time.Date(2026, 11, 20, 12, 2, 0, 0, time.UTC),
	}
	if links {
		r.ApproveURL = "https://scrim.example/v1/approvals/a1b2/decide?t=approve-token"
		r.DenyURL = "https://scrim.example/v1/approvals/a1b2/decide?t=deny-token"
	}
	return r
}

func TestPublishWithButtons(t *testing.T) {
	var got Message
	var auth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth = r.Header.Get("Authorization")
		b, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(b, &got); err != nil {
			t.Error(err)
		}
		_, _ = io.WriteString(w, `{"id":"x"}`)
	}))
	defer srv.Close()
	n, err := New(Options{URL: srv.URL, Topic: "scrim-approvals", Token: secret.FromString("tk_test")})
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Notify(context.Background(), request(true)); err != nil {
		t.Fatal(err)
	}
	if auth != "Bearer tk_test" {
		t.Fatalf("auth %q", auth)
	}
	if got.Topic != "scrim-approvals" || !strings.Contains(got.Title, "claude-laptop") || len(got.Actions) != 3 {
		t.Fatalf("message %+v", got)
	}
	a := got.Actions[0]
	if a.Action != "http" || a.Label != "Approve" || a.Method != "POST" || !strings.HasSuffix(a.URL, "t=approve-token") {
		t.Fatalf("approve action %+v", a)
	}
	if got.Actions[1].Label != "Deny" || !strings.HasSuffix(got.Actions[1].URL, "t=deny-token") {
		t.Fatalf("deny action %+v", got.Actions[1])
	}
	for _, want := range []string{"Agent: claude-laptop", "Secret: bao://kv/agents/github", "Destination: POST api.github.com/repos/a/b/issues", "Rule: github-write"} {
		if !strings.Contains(got.Message, want) {
			t.Errorf("message lacks %q:\n%s", want, got.Message)
		}
	}
	if strings.Contains(got.Message, "access_token") {
		t.Error("query string in notification")
	}
}

func TestNoButtonsWithoutPublicURL(t *testing.T) {
	n, _ := New(Options{URL: "https://ntfy.example", Topic: "t"})
	r := request(false)
	r.ApproveURL, r.DenyURL = "/v1/approvals/a1b2/decide?t=x", "/v1/approvals/a1b2/decide?t=y"
	m := n.Build(r)
	if len(m.Actions) != 0 || !strings.Contains(m.Message, "scrim approve a1b2") {
		t.Fatalf("%+v", m)
	}
}

func TestPublishFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(403) }))
	defer srv.Close()
	n, _ := New(Options{URL: srv.URL, Topic: "t"})
	if err := n.Notify(context.Background(), request(true)); err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("err %v", err)
	}
	srv.Close()
	if err := n.Notify(context.Background(), request(true)); err == nil {
		t.Fatal("unreachable server: no error")
	}
}

func TestValidation(t *testing.T) {
	for _, o := range []Options{{URL: "ntfy.sh", Topic: "t"}, {URL: "https://ntfy.sh", Topic: ""}, {URL: "https://ntfy.sh", Topic: "a/b"}} {
		if _, err := New(o); err == nil {
			t.Errorf("%+v accepted", o)
		}
	}
}
