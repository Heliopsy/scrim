// SPDX-License-Identifier: AGPL-3.0-only

package agenttools_test

import (
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	at "github.com/heliopsy/scrim/internal/agenttools"
	"github.com/heliopsy/scrim/internal/agenttools/agenttoolstest"
	"github.com/heliopsy/scrim/internal/secret"
)

func TestAskHumanStored(t *testing.T) {
	e := env(t)
	dev := agenttoolstest.Agent("dev", 1000)
	notices := e.Notifier.Chan()
	val := "ask-test-value-7e6d5c4b3a29"

	var (
		out at.AskOutput
		err error
		wg  sync.WaitGroup
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		out, err = e.Service.Ask(ctx, dev, at.AskInput{Ref: "bao://kv/agents/hetzner-new", Prompt: "Hetzner API token", WaitSeconds: 10})
	}()
	n := <-notices
	if n.Agent != "dev" || n.Ref != "bao://kv/agents/hetzner-new" || n.Prompt != "Hetzner API token" || !strings.Contains(n.URL, "/entry/") {
		t.Fatalf("notice = %+v", n)
	}
	tok := agenttoolstest.TokenOf(n.URL)
	view, ok := e.Service.Entry(tok)
	if !ok || view.Agent != "dev" || view.Prompt != "Hetzner API token" {
		t.Fatalf("entry view = %+v %v", view, ok)
	}
	if err := e.Service.SubmitAsk(ctx, tok, secret.FromString(val)); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	if err != nil || out.Status != at.AskStored || out.ID != n.AskID || out.Placeholder == "" {
		t.Fatalf("ask = %+v %v", out, err)
	}
	if got, _ := e.Store.Value("bao://kv/agents/hetzner-new"); string(got) != val {
		t.Fatal("value not stored")
	}
	raw, _ := json.Marshal(out)
	agenttoolstest.AssertNoValues(t, "ask result", raw, []byte(val))
	if strings.Contains(string(raw), tok) {
		t.Fatal("ask result contains the entry token")
	}
	audit, _ := json.Marshal(e.Audit.All())
	agenttoolstest.AssertNoValues(t, "audit", audit, []byte(val))
	if strings.Contains(string(audit), tok) {
		t.Fatal("audit contains the entry token")
	}

	// The link is single use.
	if _, ok := e.Service.Entry(tok); ok {
		t.Fatal("entry view still open after submission")
	}
	if err := e.Service.SubmitAsk(ctx, tok, secret.FromString("second")); code(t, err) != at.CodeNotFound {
		t.Fatalf("second submit: %v", err)
	}
	if got, _ := e.Store.Value("bao://kv/agents/hetzner-new"); string(got) != val {
		t.Fatal("second submit changed the value")
	}
	st, err := e.Service.Status(ctx, dev, at.StatusInput{ID: out.ID})
	if err != nil || st.Kind != "ask" || st.Status != at.AskStored {
		t.Fatalf("status = %+v %v", st, err)
	}
}

func TestAskHumanDeclinedAndPending(t *testing.T) {
	e := env(t)
	dev := agenttoolstest.Agent("dev", 1000)
	out, err := e.Service.Ask(ctx, dev, at.AskInput{Ref: "bao://kv/agents/x", Prompt: "token"})
	if err != nil || out.Status != at.AskPending || out.ID == "" {
		t.Fatalf("no wait: %+v %v", out, err)
	}
	if e.Audit.Last().Outcome != at.OutcomePending {
		t.Fatalf("audit = %+v", e.Audit.Last())
	}
	tok := agenttoolstest.TokenOf(e.Notifier.Notices[0].URL)
	if err := e.Service.DeclineAsk(ctx, tok); err != nil {
		t.Fatal(err)
	}
	st, _ := e.Service.Status(ctx, dev, at.StatusInput{ID: out.ID})
	if st.Status != at.AskDeclined {
		t.Fatalf("status = %+v", st)
	}
	if _, ok := e.Store.Value("bao://kv/agents/x"); ok {
		t.Fatal("declined ask stored a value")
	}
	if err := e.Service.SubmitAsk(ctx, tok, secret.FromString("late")); code(t, err) != at.CodeNotFound {
		t.Fatalf("submit after decline: %v", err)
	}
	// Other principals cannot see the ask.
	if _, err := e.Service.Status(ctx, agenttoolstest.Session("dev", "s1", 1000), at.StatusInput{ID: out.ID}); code(t, err) != at.CodeNotFound {
		t.Fatalf("other principal: %v", err)
	}
}

func TestAskHumanTimesOut(t *testing.T) {
	e := agenttoolstest.NewEnv(t)
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	var mu sync.Mutex
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	svc, err := at.New(at.Deps{Policy: e.Policy, Approvals: e.Approvals, Catalog: e.Store, Store: e.Store,
		Auditor: e.Audit, Notifier: e.Notifier, Links: agenttoolstest.Links{Base: "http://127.0.0.1:1"}, Now: clock})
	if err != nil {
		t.Fatal(err)
	}
	dev := agenttoolstest.Agent("dev", 1000)
	out, err := svc.Ask(ctx, dev, at.AskInput{Ref: "bao://kv/agents/x", Prompt: "token", TimeoutSeconds: 60})
	if err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	now = now.Add(61 * time.Second)
	mu.Unlock()
	st, _ := svc.Status(ctx, dev, at.StatusInput{ID: out.ID})
	if st.Status != at.AskTimedOut {
		t.Fatalf("status = %+v", st)
	}
	tok := agenttoolstest.TokenOf(e.Notifier.Notices[0].URL)
	if _, ok := svc.Entry(tok); ok {
		t.Fatal("expired entry still open")
	}
	if err := svc.SubmitAsk(ctx, tok, secret.FromString("late-value")); code(t, err) != at.CodeNotFound {
		t.Fatalf("late submit: %v", err)
	}
	if _, ok := e.Store.Value("bao://kv/agents/x"); ok {
		t.Fatal("timed-out ask stored a value")
	}
	mu.Lock()
	now = now.Add(2 * time.Hour)
	mu.Unlock()
	if _, err := svc.Status(ctx, dev, at.StatusInput{ID: out.ID}); code(t, err) != at.CodeNotFound {
		t.Fatalf("settled ask kept past retention: %v", err)
	}
}

func TestAskHumanRefusals(t *testing.T) {
	e := env(t)
	dev := agenttoolstest.Agent("dev", 1000)
	for _, bad := range []at.AskInput{
		{Ref: "bao://kv/agents/x"},
		{Ref: "bao://kv/agents/x", Prompt: strings.Repeat("p", 1025)},
		{Ref: "bao://kv/agents/x", Prompt: "p", TimeoutSeconds: -1},
		{Ref: "bao://kv/agents/x", Prompt: "p", TimeoutSeconds: 86401},
		{Ref: "bao://kv/agents/x", Prompt: "p", WaitSeconds: 601},
		{Ref: "bao://kv/agents/x", Prompt: "p", Store: "Bad Store"},
	} {
		if _, err := e.Service.Ask(ctx, dev, bad); code(t, err) != at.CodeInvalid {
			t.Errorf("%+v: %v", bad, err)
		}
	}
	if _, err := e.Service.Ask(ctx, dev, at.AskInput{Ref: "bao://kv/prod/x", Prompt: "p"}); code(t, err) != at.CodeDenied {
		t.Fatalf("outside policy: %v", err)
	}
	if len(e.Notifier.Notices) != 0 {
		t.Fatal("a refused ask notified a human")
	}
	e.Notifier.Err = errors.New("ntfy down")
	if _, err := e.Service.Ask(ctx, dev, at.AskInput{Ref: "bao://kv/agents/x", Prompt: "p"}); code(t, err) != at.CodeUnavailable {
		t.Fatalf("notifier down: %v", err)
	}
	svc, _ := at.New(at.Deps{Policy: e.Policy, Approvals: e.Approvals, Catalog: e.Store, Store: e.Store, Auditor: e.Audit})
	if _, err := svc.Ask(ctx, dev, at.AskInput{Ref: "bao://kv/agents/x", Prompt: "p"}); code(t, err) != at.CodeUnavailable {
		t.Fatalf("no notifier: %v", err)
	}
}

func TestAskSubmitRechecksPolicy(t *testing.T) {
	e := env(t)
	dev := agenttoolstest.Agent("dev", 1000)
	out, err := e.Service.Ask(ctx, dev, at.AskInput{Ref: "bao://kv/agents/x", Prompt: "p"})
	if err != nil {
		t.Fatal(err)
	}
	e.Policy.SetRules() // deny everything, as break-glass would
	tok := agenttoolstest.TokenOf(e.Notifier.Notices[0].URL)
	if err := e.Service.SubmitAsk(ctx, tok, secret.FromString("abcdefgh")); code(t, err) != at.CodeDenied {
		t.Fatalf("submit under deny-all: %v", err)
	}
	if _, ok := e.Store.Value("bao://kv/agents/x"); ok {
		t.Fatal("value stored under deny-all")
	}
	st, _ := e.Service.Status(ctx, dev, at.StatusInput{ID: out.ID})
	if st.Status != at.AskDeclined {
		t.Fatalf("status = %+v", st)
	}
}

func TestAskOpenLimit(t *testing.T) {
	e := env(t)
	dev := agenttoolstest.Agent("dev", 1000)
	var err error
	for range 65 {
		_, err = e.Service.Ask(ctx, dev, at.AskInput{Ref: "bao://kv/agents/x", Prompt: "p"})
	}
	if code(t, err) != at.CodeConflict {
		t.Fatalf("65th ask: %v", err)
	}
	if _, err := e.Service.Ask(ctx, agenttoolstest.Agent("ops", 1001), at.AskInput{Ref: "bao://kv/agents/y", Prompt: "p"}); err != nil {
		t.Fatalf("another agent is limited too: %v", err)
	}
}
