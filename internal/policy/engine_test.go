// SPDX-License-Identifier: AGPL-3.0-only

package policy

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/heliopsy/scrim/internal/stores"
)

func mustCompile(t *testing.T, cfg Config) *RuleSet {
	t.Helper()
	rs, err := Compile(cfg)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	return rs
}

func known(id string, labels map[string]string) Agent {
	return Agent{ID: id, Kind: IdentitySession, Session: "s1", Labels: labels}
}

func mustRef(s string) stores.Ref { return stores.MustParseRef(s) }

func TestSpecScenarios(t *testing.T) {
	githubWrites := Config{Rules: []RuleSpec{
		{Name: "github-read", Decision: "allow",
			When: `secret.ref == "bao://kv/agents/github" && dest.host == "api.github.com" && dest.method == "GET"`},
		{Name: "github-write", Decision: "ask",
			When: `secret.ref == "bao://kv/agents/github" && dest.host == "api.github.com" && dest.method != "GET"`},
	}}
	prodDeploy := Config{Rules: []RuleSpec{
		{Name: "prod-deploy-only", Decision: "allow",
			When: `secret.ref.glob("bao://kv/prod/*") && agent.labels.namespace == "deploy"`},
	}}
	gh := mustRef("bao://kv/agents/github")
	tests := []struct {
		name string
		cfg  Config
		req  Request
		want Effect
		rule string
	}{
		{"github GET injected", githubWrites, Request{Action: ActionInject, Agent: known("a", nil),
			Ref: gh, Host: "api.github.com", Method: "GET"}, Allow, "github-read"},
		{"github POST asks", githubWrites, Request{Action: ActionInject, Agent: known("a", nil),
			Ref: gh, Host: "api.github.com", Method: "POST"}, Ask, "github-write"},
		{"prod ref from deploy namespace", prodDeploy, Request{Agent: known("k8s:deploy/x", map[string]string{"namespace": "deploy"}),
			Ref: mustRef("bao://kv/prod/db")}, Allow, "prod-deploy-only"},
		{"prod ref from agents namespace", prodDeploy, Request{Agent: known("k8s:agents/x", map[string]string{"namespace": "agents"}),
			Ref: mustRef("bao://kv/prod/db")}, Deny, DefaultRule},
		{"no rule, no default: deny", Config{}, Request{Agent: known("a", nil)}, Deny, DefaultRule},
		{"no rule, default ask", Config{Default: "ask"}, Request{Agent: known("a", nil)}, Ask, DefaultRule},
		{"deny beats allow", Config{Rules: []RuleSpec{
			{Name: "allow-all", Decision: "allow"},
			{Name: "deny-payments", Decision: "deny", When: `secret.ref == "bao://kv/prod/payments"`},
		}}, Request{Ref: mustRef("bao://kv/prod/payments")}, Deny, "deny-payments"},
		{"ask beats allow", Config{Rules: []RuleSpec{
			{Name: "allow-all", Decision: "allow"},
			{Name: "ask-writes", Decision: "ask", When: `op == "store.write"`},
		}}, Request{Action: ActionWrite}, Ask, "ask-writes"},
		{"deny beats ask", Config{Rules: []RuleSpec{
			{Name: "ask-all", Decision: "ask"},
			{Name: "deny-unknown", Decision: "deny", When: `!agent.known`},
		}}, Request{Action: ActionInject}, Deny, "deny-unknown"},
		{"first of equal precedence reported", Config{Rules: []RuleSpec{
			{Name: "first", Decision: "allow", When: `op == "inject"`},
			{Name: "second", Decision: "allow"},
		}}, Request{Action: ActionInject}, Allow, "first"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rs := mustCompile(t, tt.cfg)
			got := rs.Evaluate(tt.req)
			if got.Effect != tt.want || got.Rule != tt.rule {
				t.Fatalf("got %s by %q, want %s by %q (%+v)", got.Effect, got.Rule, tt.want, tt.rule, got)
			}
			if (tt.rule == DefaultRule) != got.Default {
				t.Fatalf("Default = %v for rule %q", got.Default, got.Rule)
			}
			d, err := rs.Decide(context.Background(), tt.req)
			if err != nil || d.Effect != tt.want || d.Rule != tt.rule {
				t.Fatalf("Decide = %+v, %v", d, err)
			}
		})
	}
}

func TestAttributes(t *testing.T) {
	req := Request{
		Action: ActionExec,
		Agent: Agent{ID: "k8s:agents/builder", Kind: IdentityK8s, Session: "sess-1",
			Labels: map[string]string{"namespace": "agents", "service_account": "builder", "team": "infra",
				"spiffe_id": "spiffe://example.org/agents/builder"}},
		Ref:          mustRef("inf://acme/prod/API_KEY"),
		Name:         "ACME_KEY",
		Store:        "infisical",
		SecretClass:  "credential",
		SecretLabels: map[string]string{"env": "prod"},
		Provider:     "anthropic",
		Host:         "api.hetzner.cloud",
		Method:       "DELETE",
		Path:         "/v1/servers/42",
		Tool:         "bash",
		Command:      "hcloud",
		Time:         time.Date(2026, 11, 20, 23, 30, 0, 0, time.UTC),
	}
	exprs := []string{
		`op == "exec"`,
		`agent.id == "k8s:agents/builder" && agent.kind == "k8s" && agent.session == "sess-1" && agent.known`,
		`agent.labels.namespace == "agents" && agent.labels.service_account == "builder"`,
		`agent.labels.spiffe_id.startsWith("spiffe://example.org/")`,
		`agent.labels.team == "infra" && agent.labels["team"] == "infra" && "team" in agent.labels`,
		`has(agent.labels.team) && !has(agent.labels.other)`,
		`secret.ref.glob("inf://acme/*/API_KEY") && secret.store == "infisical" && secret.class == "credential"`,
		`secret.name == "ACME_KEY" && secret.labels.env == "prod"`,
		`provider == "anthropic"`,
		`dest.host.endsWith(".hetzner.cloud")`,
		`dest.method in ["DELETE", "POST"] && dest.path.glob("/v1/servers/*")`,
		`tool.name == "bash" && tool.command == "hcloud"`,
		`now.getHours() >= 22`,
		`now.getHours("Europe/Berlin") == 0`,
		`dest.path.matches("^/v1/servers/[0-9]+$")`,
		`agent.labels.?team.orValue("") == "infra"`,
		`secret.ref.lowerAscii().contains("api_key")`,
	}
	for _, x := range exprs {
		t.Run(x, func(t *testing.T) {
			rs := mustCompile(t, Config{Rules: []RuleSpec{{Name: "r", Decision: "allow", When: x}}})
			if got := rs.Evaluate(req); got.Effect != Allow || len(got.Errors) > 0 {
				t.Fatalf("expected %s to match: %+v", x, got)
			}
		})
	}
	unknown := mustCompile(t, Config{Rules: []RuleSpec{{Name: "r", Decision: "allow", When: `!agent.known && agent.kind == ""`}}})
	if got := unknown.Evaluate(Request{}); got.Effect != Allow {
		t.Fatalf("unknown caller not seen as unknown: %+v", got)
	}
}

func TestInvalidRulesRejected(t *testing.T) {
	tests := []struct {
		name string
		rule RuleSpec
		want string
	}{
		{"syntax", RuleSpec{Name: "r", Decision: "allow", When: `secret.ref ==`}, "Syntax error"},
		{"unknown field", RuleSpec{Name: "r", Decision: "allow", When: `agent.nmae == "x"`}, "undefined field"},
		{"unknown variable", RuleSpec{Name: "r", Decision: "allow", When: `user == "x"`}, "undeclared reference"},
		{"not bool", RuleSpec{Name: "r", Decision: "allow", When: `secret.ref`}, "bool"},
		{"bad glob", RuleSpec{Name: "r", Decision: "allow", When: `secret.ref.glob("a\\")`}, "glob"},
		{"no decision", RuleSpec{Name: "r"}, "decision is required"},
		{"bad decision", RuleSpec{Name: "r", Decision: "maybe"}, "decision is required"},
		{"no name", RuleSpec{Decision: "allow"}, "name is required"},
		{"bad name", RuleSpec{Name: "Has Space", Decision: "allow"}, "lower-case"},
		{"deny with grant", RuleSpec{Name: "r", Decision: "deny", Grant: GrantSettings{TTL: Duration(time.Minute)}}, "deny rule"},
		{"allow with approval", RuleSpec{Name: "r", Decision: "allow", Approval: ApprovalSettings{Timeout: Duration(time.Minute)}}, "allow rule"},
		{"ttl over max", RuleSpec{Name: "r", Decision: "ask", Grant: GrantSettings{TTL: Duration(time.Hour), MaxTTL: Duration(time.Minute)}}, "exceeds"},
		{"bad scope", RuleSpec{Name: "r", Decision: "ask", Grant: GrantSettings{Scope: "everything"}}, "scope"},
		{"negative uses", RuleSpec{Name: "r", Decision: "ask", Grant: GrantSettings{Uses: -1}}, "uses"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Compile(Config{Rules: []RuleSpec{{Name: "ok", Decision: "allow"}, tt.rule}})
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want it to mention %q", err, tt.want)
			}
		})
	}
	if _, err := Compile(Config{Rules: []RuleSpec{{Name: "a", Decision: "allow"}, {Name: "a", Decision: "deny"}}}); err == nil {
		t.Fatal("duplicate names accepted")
	}
	if _, err := Compile(Config{Default: "permit"}); err == nil {
		t.Fatal("bad default accepted")
	}
}

func TestEvaluationErrorsFailClosed(t *testing.T) {
	// The agent has no "team" label, so indexing it errors.
	req := Request{Agent: known("a", nil)}
	for _, tt := range []struct {
		d    string
		want Effect
	}{{"allow", Deny}, {"ask", Ask}, {"deny", Deny}} {
		rs := mustCompile(t, Config{Rules: []RuleSpec{
			{Name: "r", Decision: tt.d, When: `agent.labels.team == "infra"`},
		}})
		got := rs.Evaluate(req)
		if got.Effect != tt.want || len(got.Errors) != 1 {
			t.Errorf("%s rule erroring: got %+v, want %s", tt.d, got, tt.want)
		}
	}
	// An erroring deny rule still denies under an allow default.
	rs := mustCompile(t, Config{Default: "allow", Rules: []RuleSpec{
		{Name: "deny-non-infra", Decision: "deny", When: `agent.labels.team != "infra"`},
	}})
	if got := rs.Evaluate(req); got.Effect != Deny || got.Rule != "deny-non-infra" {
		t.Errorf("erroring deny rule must deny, got %+v", got)
	}
}

func TestGrantTTLOnDecision(t *testing.T) {
	rs := mustCompile(t, Config{Rules: []RuleSpec{
		{Name: "jit", Decision: "ask", Grant: GrantSettings{TTL: Duration(30 * time.Minute), Uses: 2}},
	}})
	d, _ := rs.Decide(context.Background(), Request{})
	if d.Effect != Ask || d.GrantTTL != 30*time.Minute {
		t.Fatalf("decision %+v", d)
	}
	if g := rs.Evaluate(Request{}).Grant(); g.Uses != 2 {
		t.Fatalf("grant settings %+v", g)
	}
}

func TestLiveKeepsPreviousRulesOnBadReload(t *testing.T) {
	l, err := NewLive(Config{Rules: []RuleSpec{{Name: "allow-all", Decision: "allow"}}})
	if err != nil {
		t.Fatal(err)
	}
	var swaps []uint64
	l.OnSwap(func(_ *RuleSet, v uint64) { swaps = append(swaps, v) })
	err = l.Reload(Config{Rules: []RuleSpec{{Name: "typo", Decision: "allow", When: `secret.reff == "x"`}}})
	if err == nil {
		t.Fatal("bad reload accepted")
	}
	if got := l.Evaluate(Request{}); got.Effect != Allow || got.Rule != "allow-all" {
		t.Fatalf("previous rules not in force: %+v", got)
	}
	if v, lerr := l.Health(); v != 1 || lerr == nil {
		t.Fatalf("health = %d, %v", v, lerr)
	}
	if err := l.Reload(Config{}); err != nil {
		t.Fatal(err)
	}
	if d, _ := l.Decide(context.Background(), Request{}); d.Effect != Deny {
		t.Fatalf("new rules not in force: %+v", d)
	}
	if v, lerr := l.Health(); v != 2 || lerr != nil {
		t.Fatalf("health = %d, %v", v, lerr)
	}
	if len(swaps) != 1 || swaps[0] != 2 {
		t.Fatalf("swaps = %v", swaps)
	}
	if _, err := NewLive(Config{Rules: []RuleSpec{{Name: "x"}}}); err == nil {
		t.Fatal("invalid start-up config accepted")
	}
}

func TestConfigJSON(t *testing.T) {
	src := `{"default":"ask","rules":[{"name":"r","decision":"allow","when":"op == \"inject\"",
		"grant":{"ttl":"30m","max_ttl":"2h","uses":3,"scope":"destination"},"reason":"why"}]}`
	var c Config
	if err := json.Unmarshal([]byte(src), &c); err != nil {
		t.Fatal(err)
	}
	if c.Default != "ask" || c.Rules[0].Grant.TTL.D() != 30*time.Minute || c.Rules[0].Grant.Scope != ScopeDestination {
		t.Fatalf("decoded %+v", c)
	}
	if err := json.Unmarshal([]byte(`{"rules":[{"name":"r","grant":{"ttl":"-1m"}}]}`), &c); err == nil {
		t.Fatal("negative duration accepted")
	}
}
