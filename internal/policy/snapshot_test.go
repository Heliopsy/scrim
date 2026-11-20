// SPDX-License-Identifier: AGPL-3.0-only

package policy

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/heliopsy/scrim/internal/stores"
)

var update = flag.Bool("update", false, "rewrite golden files in testdata")

// atoms is a pool of rule expressions covering every lowering path: local
// conditions, map keys that may be missing, negation, and residual parts.
var atoms = []string{
	`op == "inject"`,
	`op in ["store.write", "secret.gen"]`,
	`"inject" == op`,
	`agent.known`,
	`!agent.known`,
	`agent.known == false`,
	`agent.kind == "k8s"`,
	`agent.labels.namespace == "deploy"`,
	`agent.labels["namespace"] != "agents"`,
	`agent.labels.team == "infra"`,
	`"team" in agent.labels`,
	`has(agent.labels.tier)`,
	`secret.ref.glob("bao://kv/prod/*")`,
	`secret.ref.glob("bao://kv/**")`,
	`secret.ref.startsWith("inf://")`,
	`secret.labels.env in ["prod", "staging"]`,
	`secret.class == "credential"`,
	`dest.host.endsWith(".github.com")`,
	`dest.host == "api.github.com"`,
	`dest.method in ["GET", "HEAD"]`,
	`dest.path.contains("/admin")`,
	`provider == "anthropic"`,
	`tool.name == "bash"`,
	`tool.command.glob("git*")`,
	`true`,
	`false`,
	// Residual: the data plane cannot evaluate these.
	`now.getHours() >= 22`,
	`size(tool.command) > 3`,
	`dest.path.matches("^/repos/[^/]+/[^/]+/git")`,
	`secret.ref.lowerAscii() == "bao://kv/prod/db"`,
	`dest.host == agent.labels.host`,
	`agent.labels.?team.orValue("") == "infra"`,
}

// randomRules builds a rule set of 1 to max rules from the atom pool, with
// all three decisions, conjunctions, disjunctions, negations and some allow
// rules with side effects.
func randomRules(r *rand.Rand, maxRules int) []RuleSpec {
	shapes := []string{"%[1]s", "%[1]s && %[2]s", "%[1]s || %[2]s", "!(%[1]s && %[2]s)", "!(%[1]s) || %[2]s",
		"(%[1]s || %[2]s) && %[3]s", "%[1]s && !(%[2]s || %[3]s)"}
	n := 1 + r.IntN(maxRules)
	rules := make([]RuleSpec, 0, n)
	for i := range n {
		when := fmt.Sprintf(shapes[r.IntN(len(shapes))],
			atoms[r.IntN(len(atoms))], atoms[r.IntN(len(atoms))], atoms[r.IntN(len(atoms))])
		rule := RuleSpec{Name: fmt.Sprintf("r%d", i), Decision: []string{"allow", "ask", "deny"}[r.IntN(3)], When: when}
		if rule.Decision == "allow" && r.IntN(4) == 0 {
			rule.Grant.TTL = Duration(time.Minute)
		}
		rules = append(rules, rule)
	}
	return rules
}

// pool values for generated requests.
var (
	poolActions = []Action{ActionInject, ActionWrite, ActionRead, ActionGenerate, ""}
	poolKinds   = []IdentityKind{IdentitySession, IdentityK8s, IdentityUnknown}
	poolLabels  = []map[string]string{nil, {"team": "infra", "namespace": "deploy"}, {"team": "web", "tier": "1", "namespace": "agents"}, {"host": "api.github.com"}}
	poolRefs    = []string{"bao://kv/prod/db", "bao://kv/prod/a/b", "inf://acme/prod/API_KEY", "bao://kv/agents/github", ""}
	poolSLabels = []map[string]string{nil, {"env": "prod"}, {"env": "dev"}}
	poolClasses = []string{"credential", "display", ""}
	poolHosts   = []string{"api.github.com", "uploads.github.com", "api.hetzner.cloud", ""}
	poolMethods = []string{"GET", "POST", "DELETE", ""}
	poolPaths   = []string{"/repos/a/b/git/refs", "/admin/users", "/", ""}
	poolProv    = []string{"anthropic", "openai", ""}
	poolTools   = []string{"bash", "git", ""}
	poolCmds    = []string{"git", "git-lfs", "curl", ""}
	poolHours   = []int{3, 23}
)

func pick[T any](b []byte, i int, pool []T) T {
	if i < len(b) {
		return pool[int(b[i])%len(pool)]
	}
	return pool[0]
}

func randomRequest(r *rand.Rand) Request {
	b := make([]byte, 15)
	for i := range b {
		b[i] = byte(r.UintN(256))
	}
	return requestFrom(b)
}

func requestFrom(b []byte) Request {
	req := Request{
		Action:       pick(b, 0, poolActions),
		Agent:        Agent{ID: "a", Kind: pick(b, 1, poolKinds), Labels: pick(b, 2, poolLabels)},
		SecretLabels: pick(b, 4, poolSLabels),
		SecretClass:  pick(b, 5, poolClasses),
		Provider:     pick(b, 6, poolProv),
		Host:         pick(b, 7, poolHosts),
		Method:       pick(b, 9, poolMethods),
		Path:         pick(b, 10, poolPaths),
		Tool:         pick(b, 11, poolTools),
		Command:      pick(b, 12, poolCmds),
		Time:         time.Date(2026, 11, 20, pick(b, 14, poolHours), 0, 0, 0, time.UTC),
	}
	if s := pick(b, 3, poolRefs); s != "" {
		req.Ref = stores.MustParseRef(s)
	}
	return req
}

// agree checks the soundness contract between the data plane and the
// control plane: whenever the data plane decides on its own, the full CEL
// evaluation reaches the same decision through the same rule.
func agree(t *testing.T, e *RuleSet, s *Snapshot, req Request) LocalResult {
	t.Helper()
	full := e.Evaluate(req)
	local := s.Evaluate(req)
	fail := func() {
		t.Helper()
		b, _ := json.Marshal(req)
		t.Fatalf("data plane %+v disagrees with control plane %+v for %s", local, full, b)
	}
	switch local.Outcome {
	case OutcomeDeny:
		if full.Effect != Deny || full.Rule != local.Rule || full.Default != local.Default {
			fail()
		}
	case OutcomeAllow:
		if full.Effect != Allow || full.Rule != local.Rule || full.Default != local.Default {
			fail()
		}
	case OutcomeControlPlane:
		switch local.Ask {
		case AskRule:
			if full.Effect != Ask || full.Rule != local.Rule {
				fail()
			}
		case AskSideEffect:
			if full.Effect != Allow || full.Rule != local.Rule {
				fail()
			}
		case AskResidual:
		default:
			fail()
		}
	default:
		fail()
	}
	return local
}

func TestSnapshotAgreesWithCEL(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	outcomes := map[string]int{}
	for range 3000 {
		e := mustCompile(t, Config{Default: []string{"allow", "ask", "deny"}[r.IntN(3)], Rules: randomRules(r, 6)})
		s := e.Snapshot(1, false)
		for range 40 {
			res := agree(t, e, &s, randomRequest(r))
			outcomes[res.Outcome.String()+"/"+string(res.Ask)]++
		}
	}
	t.Logf("outcomes: %v", outcomes)
	for _, k := range []string{"allow/", "deny/", "control_plane/ask", "control_plane/residual", "control_plane/side_effect"} {
		if outcomes[k] < 1000 {
			t.Errorf("outcome %s seen only %d times; the generator no longer covers it", k, outcomes[k])
		}
	}
}

func FuzzSnapshotAgreesWithCEL(f *testing.F) {
	f.Add([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14}, uint64(0), uint64(1))
	f.Add([]byte{3, 0, 1, 1, 0, 1, 0, 0, 0, 1, 1, 0, 1, 1, 1}, uint64(0xdeadbeef), uint64(2))
	f.Fuzz(func(t *testing.T, reqBytes []byte, s1, s2 uint64) {
		r := rand.New(rand.NewPCG(s1, s2))
		e, err := Compile(Config{Default: []string{"allow", "ask", "deny"}[r.IntN(3)], Rules: randomRules(r, 8)})
		if err != nil {
			t.Fatalf("generated rule failed to compile: %v", err)
		}
		s := e.Snapshot(1, false)
		agree(t, e, &s, requestFrom(reqBytes))
	})
}

func TestSnapshotLowering(t *testing.T) {
	cases := []struct {
		when    string
		clauses []Clause
	}{
		{``, []Clause{{}}},
		{`true`, []Clause{{}}},
		{`false`, []Clause{}},
		{`!false`, []Clause{{}}},
		{`agent.known`, []Clause{{Conditions: []Condition{{Field: "agent.known", Op: OpIn, Values: []string{"true"}}}}}},
		{`!agent.known`, []Clause{{Conditions: []Condition{{Field: "agent.known", Op: OpIn, Values: []string{"true"}, Negate: true}}}}},
		{`agent.known == true`, []Clause{{Conditions: []Condition{{Field: "agent.known", Op: OpIn, Values: []string{"true"}}}}}},
		{`"api.github.com" != dest.host`, []Clause{{Conditions: []Condition{{Field: "dest.host", Op: OpIn, Values: []string{"api.github.com"}, Negate: true}}}}},
		{`agent.labels["team"] == "x"`, []Clause{{Conditions: []Condition{{Field: "agent.labels", Key: "team", Op: OpIn, Values: []string{"x"}}}}}},
		{`"team" in secret.labels`, []Clause{{Conditions: []Condition{{Field: "secret.labels", Key: "team", Op: OpHasKey, Values: []string{}}}}}},
		{`has(agent.labels.team)`, []Clause{{Conditions: []Condition{{Field: "agent.labels", Key: "team", Op: OpHasKey, Values: []string{}}}}}},
		{`now.getHours() > 1`, []Clause{{Residual: true}}},
		{`!(now.getHours() > 1)`, []Clause{{Residual: true}}},
		{`op == "a" && now.getHours() > 1`, []Clause{{Conditions: []Condition{{Field: "op", Op: OpIn, Values: []string{"a"}}}, Residual: true}}},
		{`op == "a" || op == "b"`, []Clause{
			{Conditions: []Condition{{Field: "op", Op: OpIn, Values: []string{"a"}}}},
			{Conditions: []Condition{{Field: "op", Op: OpIn, Values: []string{"b"}}}},
		}},
		{`!(op == "a" || op == "b")`, []Clause{{Conditions: []Condition{
			{Field: "op", Op: OpIn, Values: []string{"a"}, Negate: true},
			{Field: "op", Op: OpIn, Values: []string{"b"}, Negate: true},
		}}}},
		{`(op == "a" || op == "b") && dest.host.glob("*.x")`, []Clause{
			{Conditions: []Condition{{Field: "op", Op: OpIn, Values: []string{"a"}}, {Field: "dest.host", Op: OpGlob, Values: []string{"*.x"}}}},
			{Conditions: []Condition{{Field: "op", Op: OpIn, Values: []string{"b"}}, {Field: "dest.host", Op: OpGlob, Values: []string{"*.x"}}}},
		}},
		{`op == "a" && false`, []Clause{}},
	}
	for _, c := range cases {
		t.Run(c.when, func(t *testing.T) {
			e := mustCompile(t, Config{Rules: []RuleSpec{{Name: "r", Decision: "deny", When: c.when}}})
			got, _ := json.Marshal(e.Snapshot(1, false).Rules[0].Clauses)
			want, _ := json.Marshal(c.clauses)
			if !bytes.Equal(got, want) {
				t.Fatalf("lowered to\n%s\nwant\n%s", got, want)
			}
		})
	}
}

func TestSnapshotClauseLimit(t *testing.T) {
	// (a1||b1) && ... && (a7||b7) expands to 128 clauses.
	when := ""
	for i := range 7 {
		if i > 0 {
			when += " && "
		}
		when += fmt.Sprintf(`(op == "a%d" || dest.host == "h%d")`, i, i)
	}
	e := mustCompile(t, Config{Rules: []RuleSpec{{Name: "big", Decision: "allow", When: when}}})
	s := e.Snapshot(1, false)
	if got := s.Rules[0].Clauses; len(got) != 1 || !got[0].Residual || len(got[0].Conditions) != 0 {
		t.Fatalf("oversized rule not shipped as residual: %d clauses", len(got))
	}
	if r := s.Evaluate(Request{}); r.Outcome != OutcomeControlPlane || r.Ask != AskResidual {
		t.Fatalf("residual allow rule decided locally: %+v", r)
	}
}

func TestSnapshotDenyAll(t *testing.T) {
	e := mustCompile(t, Config{Default: "allow", Rules: []RuleSpec{{Name: "allow-all", Decision: "allow"}}})
	s := e.Snapshot(7, true)
	if r := s.Evaluate(Request{}); r.Outcome != OutcomeDeny || !r.DenyAll {
		t.Fatalf("deny-all not honoured: %+v", r)
	}
	if s.Version != 7 || s.Format != SnapshotFormat {
		t.Fatalf("header: %+v", s)
	}
}

// conformance is the vector file the Rust data plane tests against.
type conformance struct {
	Comment  string           `json:"$comment"`
	Snapshot Snapshot         `json:"snapshot"`
	Cases    []conformanceRow `json:"cases"`
}

type conformanceRow struct {
	Request vectorRequest `json:"request"`
	Want    LocalResult   `json:"want"`
}

// vectorRequest is the request in the field names rules and the snapshot
// use, which is also what the data plane holds.
type vectorRequest struct {
	Op       string     `json:"op,omitempty"`
	Agent    RuleAgent  `json:"agent"`
	Secret   RuleSecret `json:"secret"`
	Provider string     `json:"provider,omitempty"`
	Dest     RuleDest   `json:"dest"`
	Tool     RuleTool   `json:"tool"`
}

func toVector(r Request) vectorRequest {
	v := newView(&r)
	return vectorRequest{Op: v.op, Agent: v.agent, Secret: v.secret, Provider: v.provider, Dest: v.dest, Tool: v.tool}
}

func fromVector(t *testing.T, v vectorRequest) Request {
	t.Helper()
	r := Request{
		Action: Action(v.Op), Agent: Agent{ID: v.Agent.ID, Kind: IdentityKind(v.Agent.Kind), Session: v.Agent.Session, Labels: v.Agent.Labels},
		Name: v.Secret.Name, Store: v.Secret.Store, SecretClass: v.Secret.Class, SecretLabels: v.Secret.Labels,
		Provider: v.Provider, Host: v.Dest.Host, Method: v.Dest.Method, Path: v.Dest.Path, Tool: v.Tool.Name, Command: v.Tool.Command,
	}
	if v.Secret.Ref != "" {
		var err error
		if r.Ref, err = stores.ParseRef(v.Secret.Ref); err != nil {
			t.Fatal(err)
		}
	}
	if v.Agent.Known != (r.Agent.Kind != IdentityUnknown) {
		t.Fatalf("vector agent.known inconsistent with kind: %+v", v.Agent)
	}
	return r
}

// TestConformanceVectors keeps testdata/conformance.json in step with the
// reference evaluator. Run with -update to regenerate after an intended
// change; the data plane's own tests read the same file.
func TestConformanceVectors(t *testing.T) {
	cfg := Config{Default: "deny", Rules: []RuleSpec{
		{Name: "unknown-callers", Decision: "deny", When: `!agent.known`},
		{Name: "no-payments", Decision: "deny", When: `secret.ref == "bao://kv/prod/payments"`},
		{Name: "infra-only-prod", Decision: "deny", When: `secret.ref.glob("bao://kv/prod/**") && agent.labels.team != "infra"`},
		{Name: "night-writes", Decision: "ask", When: `op == "store.write" && now.getHours() >= 22`},
		{Name: "github-write", Decision: "ask",
			When: `secret.ref == "bao://kv/agents/github" && dest.host == "api.github.com" && !(dest.method in ["GET", "HEAD"])`},
		{Name: "lfs", Decision: "ask", When: `tool.command.glob("git*") && size(tool.command) > 3`},
		{Name: "github-read", Decision: "allow",
			When: `secret.ref == "bao://kv/agents/github" && dest.host.endsWith("github.com")`},
		{Name: "secret-read", Decision: "allow", When: `op == "store.read" && has(secret.labels.env)`,
			Grant: GrantSettings{TTL: Duration(10 * time.Minute)}},
		{Name: "deploy-prod", Decision: "allow", When: `agent.labels.namespace == "deploy" && secret.labels.env in ["prod", "staging"]`},
		{Name: "providers", Decision: "allow", When: `op == "" && provider in ["anthropic", "openai"]`},
		{Name: "admin-paths", Decision: "ask", When: `dest.path.contains("/admin") && (dest.host == "api.hetzner.cloud" || dest.path.matches("^/admin/keys"))`},
	}}
	e := mustCompile(t, cfg)
	s := e.Snapshot(1, false)
	c := conformance{
		Comment:  "Generated by internal/policy TestConformanceVectors -update. The data plane must return want for every request.",
		Snapshot: s,
	}
	r := rand.New(rand.NewPCG(3, 4))
	seen := map[string]int{}
	for i := 0; len(c.Cases) < 300 && i < 100000; i++ {
		req := randomRequest(r)
		got := agree(t, e, &s, req)
		key := fmt.Sprintf("%s/%s/%s/%v", got.Outcome, got.Ask, got.Rule, got.Default)
		if seen[key] >= 12 {
			continue
		}
		seen[key]++
		c.Cases = append(c.Cases, conformanceRow{Request: toVector(req), Want: got})
	}
	c.Cases = append(c.Cases, conformanceRow{Request: toVector(Request{}), Want: s.Evaluate(Request{})})
	out, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	out = append(out, '\n')
	path := filepath.Join("testdata", "conformance.json")
	if *update {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, out, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run go test -run TestConformanceVectors -update)", err)
	}
	if !bytes.Equal(out, want) {
		t.Fatalf("%s is stale; run go test ./internal/policy -run TestConformanceVectors -update", path)
	}
	// Re-read the file and evaluate it the way the data plane will.
	var back conformance
	if err := json.Unmarshal(want, &back); err != nil {
		t.Fatal(err)
	}
	kinds := map[string]int{}
	for _, row := range back.Cases {
		if got := back.Snapshot.Evaluate(fromVector(t, row.Request)); got != row.Want {
			t.Fatalf("vector %+v: got %+v", row.Request, got)
		}
		kinds[row.Want.Outcome.String()+"/"+string(row.Want.Ask)]++
	}
	for _, k := range []string{"allow/", "deny/", "control_plane/ask", "control_plane/residual", "control_plane/side_effect"} {
		if kinds[k] == 0 {
			t.Errorf("vectors do not cover %s: %v", k, kinds)
		}
	}
}
