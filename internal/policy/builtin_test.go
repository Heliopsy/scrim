// SPDX-License-Identifier: AGPL-3.0-only

package policy

import (
	"strings"
	"testing"

	"github.com/heliopsy/scrim/internal/config"
)

func builtinCfg(t *testing.T, env ...string) *config.Config {
	t.Helper()
	c, err := config.Build(config.Options{Registry: config.Default, SystemDir: t.TempDir(), Environ: env})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// TestBuiltinInjectRule: with the shipped defaults (policy.default deny, no
// rules) an identified agent's injection is allowed, an unknown caller's is
// not, a deny rule in the file still wins, and the rule can be made an ask or
// switched off.
func TestBuiltinInjectRule(t *testing.T) {
	agent := Agent{ID: "dev", Kind: IdentitySession, Session: "s1"}
	inj := Request{Agent: agent, Action: ActionInject, Host: "api.github.com", Method: "GET"}

	c, err := FromConfig(builtinCfg(t))
	if err != nil {
		t.Fatal(err)
	}
	rs := mustCompile(t, c)
	if r := rs.Evaluate(inj); r.Effect != Allow || r.Rule != BuiltinInjectRule {
		t.Fatalf("default config: %+v", r)
	}
	if r := rs.Evaluate(Request{Action: ActionInject, Host: "api.github.com"}); r.Effect != Deny || !r.Default {
		t.Fatalf("unknown caller: %+v", r)
	}
	if r := rs.Evaluate(Request{Agent: agent, Action: ActionWrite}); r.Effect != Deny || !r.Default {
		t.Fatalf("other operations keep the default: %+v", r)
	}
	// The data plane decides it locally for a known caller, and asks for a
	// caller it cannot place.
	s := rs.Snapshot(1, false)
	if r := s.Evaluate(inj); r.Outcome != OutcomeAllow || r.Rule != BuiltinInjectRule {
		t.Fatalf("data plane: %+v", r)
	}
	if r := s.EvaluateUnknownAgent(inj); r.Outcome != OutcomeControlPlane || r.Ask != AskResidual {
		t.Fatalf("data plane, unplaced caller: %+v", r)
	}

	// A deny rule in the file wins over the built-in allow.
	c, err = WithBuiltins(builtinCfg(t), Config{Default: "deny", Rules: []RuleSpec{
		{Name: "no-admin", Decision: "deny", When: `op == "inject" && dest.path.startsWith("/admin")`},
	}})
	if err != nil {
		t.Fatal(err)
	}
	rs = mustCompile(t, c)
	admin := inj
	admin.Path = "/admin/keys"
	if r := rs.Evaluate(admin); r.Effect != Deny || r.Rule != "no-admin" {
		t.Fatalf("deny rule: %+v", r)
	}

	c, _ = FromConfig(builtinCfg(t, "SCRIM_POLICY_BUILTIN_INJECT=ask"))
	if r := mustCompile(t, c).Evaluate(inj); r.Effect != Ask || r.Rule != BuiltinInjectRule {
		t.Fatalf("ask: %+v", r)
	}
	c, _ = FromConfig(builtinCfg(t, "SCRIM_POLICY_BUILTIN_INJECT=off"))
	if r := mustCompile(t, c).Evaluate(inj); r.Effect != Deny || !r.Default || len(c.Rules) != 0 {
		t.Fatalf("off: %+v", r)
	}

	if _, err := WithBuiltins(builtinCfg(t), Config{Rules: []RuleSpec{{Name: "builtin.mine", Decision: "allow"}}}); err == nil ||
		!strings.Contains(err.Error(), "reserved") {
		t.Fatalf("reserved prefix accepted: %v", err)
	}
}
