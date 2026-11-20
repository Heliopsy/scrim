// SPDX-License-Identifier: AGPL-3.0-only

package app_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/heliopsy/scrim/internal/app"
	"github.com/heliopsy/scrim/internal/gate"
	"github.com/heliopsy/scrim/internal/policy"
	"github.com/heliopsy/scrim/internal/stores"
)

func load(t *testing.T, env ...string) *app.App {
	t.Helper()
	var logs bytes.Buffer
	a, err := app.New(context.Background(), isolated(t, env...), &logs)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	return a
}

func TestRulesFileAndDenyAllWired(t *testing.T) {
	p := filepath.Join(t.TempDir(), "policy.yaml")
	rules := "rules:\n  - name: reads\n    decision: allow\n    when: op == \"store.read\"\n"
	if err := os.WriteFile(p, []byte(rules), 0o600); err != nil {
		t.Fatal(err)
	}
	req := policy.Request{Agent: policy.Agent{ID: "a", Kind: policy.IdentitySession}, Action: policy.ActionRead,
		Ref: stores.MustParseRef("bao://kv/x")}
	a := load(t, "SCRIM_POLICY_RULES_FILE="+p)
	if v := a.PolicyParts.Gate.Check(context.Background(), req, gate.Options{}); !v.Allowed() || v.Rule != "reads" {
		t.Fatalf("%+v", v)
	}
	a = load(t, "SCRIM_POLICY_RULES_FILE="+p, "SCRIM_POLICY_DENY_ALL=true")
	if v := a.PolicyParts.Gate.Check(context.Background(), req, gate.Options{}); v.Allowed() {
		t.Fatalf("deny-all from config ignored: %+v", v)
	}
	if d, _ := a.Policy.Decide(context.Background(), req); d.Effect != policy.Deny {
		t.Fatalf("engine under deny-all: %+v", d)
	}
}

func TestBadRulesFileFailsStartup(t *testing.T) {
	p := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(p, []byte("rules:\n  - name: x\n    decision: allow\n    when: op ==\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := app.New(context.Background(), isolated(t, "SCRIM_POLICY_RULES_FILE="+p), &bytes.Buffer{}); err == nil {
		t.Fatal("invalid rules accepted at start-up")
	}
}
