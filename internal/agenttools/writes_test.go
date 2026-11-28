// SPDX-License-Identifier: AGPL-3.0-only

package agenttools_test

import (
	"encoding/json"
	"strings"
	"testing"

	at "github.com/heliopsy/scrim/internal/agenttools"
	"github.com/heliopsy/scrim/internal/agenttools/agenttoolstest"
	"github.com/heliopsy/scrim/internal/secret"
)

// Every agent write asks the agent's own store identity after policy
// allowed it, and a refusal stores nothing (specs/agent-identity "Agent
// writes are checked as the agent").
func TestWritesAskTheAgentsStoreIdentity(t *testing.T) {
	e := env(t)
	e.Writes.RefusePrefix = "bao://kv/agents/ro/"
	e.Writes.FailPrefix = "bao://kv/agents/down/"
	dev := agenttoolstest.Agent("dev", 1000)
	val := []byte("put-test-3c2b1a0f9e8d7c6b")

	writes := map[string]func(ref string) error{
		at.ToolSecretGen: func(ref string) error {
			_, err := e.Service.Generate(ctx, dev, at.GenInput{Ref: ref})
			return err
		},
		at.ToolSecretPut: func(ref string) error {
			_, err := e.Service.Put(ctx, dev, at.PutInput{Ref: ref}, secret.New(val))
			return err
		},
		at.ToolSecretCapture: func(ref string) error {
			_, err := e.Service.Put(ctx, dev, at.PutInput{Ref: ref, Origin: at.ToolSecretCapture}, secret.New(val))
			return err
		},
		at.ToolSecretAskHuman: func(ref string) error {
			_, err := e.Service.Ask(ctx, dev, at.AskInput{Ref: ref, Prompt: "token"})
			return err
		},
	}
	for tool, write := range writes {
		ref := "bao://kv/agents/ro/" + tool
		calls := len(e.Writes.Calls)
		err := write(ref)
		if code(t, err) != at.CodeDenied || !strings.Contains(err.Error(), "agent's store identity") || !strings.Contains(err.Error(), ref) {
			t.Fatalf("%s refused by the store identity: %v", tool, err)
		}
		if len(e.Writes.Calls) != calls+1 || e.Writes.Calls[calls].Tool != tool || e.Writes.Calls[calls].Ref != ref {
			t.Fatalf("%s: store identity asked %+v", tool, e.Writes.Calls[calls:])
		}
		if _, ok := e.Store.Value(ref); ok {
			t.Fatalf("%s stored a value the store identity refused", tool)
		}
		last := e.Audit.Last()
		if last.Tool != tool || last.Outcome != at.OutcomeDenied || last.StoreIdentity != "static" || last.WriteCheck != "checked" {
			t.Fatalf("%s audit = %+v", tool, last)
		}

		// A check that fails refuses the write too, as unavailable.
		down := "bao://kv/agents/down/" + tool
		if err := write(down); code(t, err) != at.CodeUnavailable || strings.Contains(err.Error(), "unreachable") {
			t.Fatalf("%s with the check failing: %v", tool, err)
		}
		if _, ok := e.Store.Value(down); ok {
			t.Fatalf("%s stored a value although the check failed", tool)
		}
	}

	// Allowed by both: stored, and the audit says how it was checked.
	if err := writes[at.ToolSecretPut]("bao://kv/agents/rw"); err != nil {
		t.Fatal(err)
	}
	if last := e.Audit.Last(); last.Outcome != at.OutcomeOK || last.StoreIdentity != "static" || last.WriteCheck != "checked" {
		t.Fatalf("allowed write audit = %+v", last)
	}
	audit, _ := json.Marshal(e.Audit.All())
	agenttoolstest.AssertNoValues(t, "audit log", audit, val)

	// Policy runs first: a write it denies never reaches the store identity.
	calls := len(e.Writes.Calls)
	if err := writes[at.ToolSecretGen]("bao://kv/prod/new"); code(t, err) != at.CodeDenied {
		t.Fatalf("outside policy: %v", err)
	}
	if len(e.Writes.Calls) != calls {
		t.Fatal("a write policy denied was checked with the store identity")
	}
}

// The capture pre-check reports the store identity's refusal, so the
// command is not run only to have its output refused.
func TestCheckAsksTheAgentsStoreIdentity(t *testing.T) {
	e := env(t)
	e.Writes.RefusePrefix = "bao://kv/agents/ro/"
	dev := agenttoolstest.Agent("dev", 1000)
	out, err := e.Service.Check(ctx, dev, at.CheckInput{Tool: at.ToolSecretCapture, Ref: "bao://kv/agents/ro/x"})
	if err != nil || out.Allowed || !strings.Contains(out.Reason, "agent's store identity") {
		t.Fatalf("check = %+v %v", out, err)
	}
	if out, err := e.Service.Check(ctx, dev, at.CheckInput{Tool: at.ToolSecretCapture, Ref: "bao://kv/agents/rw"}); err != nil || !out.Allowed {
		t.Fatalf("check rw = %+v %v", out, err)
	}
}
