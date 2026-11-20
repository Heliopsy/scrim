// SPDX-License-Identifier: AGPL-3.0-only

package ntfy

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/heliopsy/scrim/internal/approval"
	"github.com/heliopsy/scrim/internal/gate"
	"github.com/heliopsy/scrim/internal/grant"
	"github.com/heliopsy/scrim/internal/notify"
	"github.com/heliopsy/scrim/internal/policy"
	"github.com/heliopsy/scrim/internal/state"
	"github.com/heliopsy/scrim/internal/state/memstate"
	"github.com/heliopsy/scrim/internal/stores"
)

// TestEndToEndAgainstNtfy runs the whole approval round trip through a real
// ntfy server: an ask decision publishes to ntfy, the test plays the phone by
// reading the message back from ntfy and pressing its action button, and the
// held operation is released (approve) or refused (deny).
//
// It needs a local ntfy; `just e2e-ntfy` starts one in rootless podman and
// sets SCRIM_TEST_NTFY_URL.
func TestEndToEndAgainstNtfy(t *testing.T) {
	base := os.Getenv("SCRIM_TEST_NTFY_URL")
	if base == "" {
		t.Skip("SCRIM_TEST_NTFY_URL not set; run just e2e-ntfy")
	}
	for _, approve := range []bool{true, false} {
		name := "deny"
		if approve {
			name = "approve"
		}
		t.Run(name, func(t *testing.T) { roundTrip(t, base, approve) })
	}
}

func roundTrip(t *testing.T, base string, approve bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	topic := "scrim-e2e-" + hex.EncodeToString(b)

	st := memstate.New()
	// The decision endpoint the phone reaches; its URL is the public URL.
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()
	n, err := New(Options{URL: base, Topic: topic})
	if err != nil {
		t.Fatal(err)
	}
	live, err := policy.NewLive(policy.Config{Rules: []policy.RuleSpec{
		{Name: "github-write", Decision: "ask", When: `dest.method != "GET"`, Reason: "writes to GitHub need a human"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	svc, err := approval.New(approval.Options{State: st, Notifiers: []notify.Notifier{n}, Signer: approval.RandomSigner(),
		PublicURL: srv.URL, Timeout: 20 * time.Second, PollInterval: 20 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	mux.Handle("/", svc.DecisionHandler())
	g := &gate.Gate{Engine: live, Rules: live, Grants: grant.NewService(st, nil), Approvals: svc, State: st}

	// Subscribe before the request so the message cannot be missed.
	sub, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/"+topic+"/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(sub)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	msgs := make(chan Message, 4)
	go func() {
		sc := bufio.NewScanner(resp.Body)
		for sc.Scan() {
			var m struct {
				Event string `json:"event"`
				Message
			}
			if json.Unmarshal(sc.Bytes(), &m) == nil && m.Event == "message" {
				msgs <- m.Message
			}
		}
	}()

	verdict := make(chan gate.Verdict, 1)
	go func() {
		verdict <- g.Check(ctx, policy.Request{
			Agent: policy.Agent{ID: "claude-laptop", Kind: policy.IdentitySession}, Action: policy.ActionInject,
			Ref: stores.MustParseRef("bao://kv/agents/github"), Host: "api.github.com", Method: "POST", Path: "/repos/a/b/issues",
		}, gate.Options{Wait: true})
	}()

	var m Message
	select {
	case m = <-msgs:
	case <-ctx.Done():
		t.Fatal("no message arrived on ntfy")
	}
	if !strings.Contains(m.Title, "claude-laptop") || !strings.Contains(m.Message, "bao://kv/agents/github") || len(m.Actions) != 3 {
		t.Fatalf("message from ntfy: %+v", m)
	}
	button := m.Actions[1]
	if approve {
		button = m.Actions[0]
	}
	// Tap the button: ntfy's http action is a request with the given method.
	tap, _ := http.NewRequestWithContext(ctx, button.Method, button.URL, nil)
	tr, err := http.DefaultClient.Do(tap)
	if err != nil {
		t.Fatal(err)
	}
	_ = tr.Body.Close()
	if tr.StatusCode != 200 {
		t.Fatalf("button answered %d", tr.StatusCode)
	}
	// A second tap changes nothing.
	tap2, _ := http.NewRequestWithContext(ctx, m.Actions[0].Method, m.Actions[0].URL, nil)
	if tr2, err := http.DefaultClient.Do(tap2); err != nil || tr2.StatusCode != http.StatusConflict {
		t.Fatalf("second tap: %v %v", tr2, err)
	}

	v := <-verdict
	if v.Allowed() != approve {
		t.Fatalf("verdict %+v", v)
	}
	want := state.ApprovalDenied
	if approve {
		want = state.ApprovalApproved
		if v.GrantID == "" {
			t.Fatal("approval left no grant")
		}
	}
	if v.ApprovalState != want {
		t.Fatalf("approval state %s, want %s", v.ApprovalState, want)
	}
}
