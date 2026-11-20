// SPDX-License-Identifier: AGPL-3.0-only

package agentapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/heliopsy/scrim/internal/agenttools"
	"github.com/heliopsy/scrim/internal/agenttools/agenttoolstest"
	"github.com/heliopsy/scrim/internal/app"
	"github.com/heliopsy/scrim/internal/audit"
	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/identity"
	"github.com/heliopsy/scrim/internal/localapi"
	"github.com/heliopsy/scrim/internal/policy"
	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/state"
	"github.com/heliopsy/scrim/internal/state/memstate"
	"github.com/heliopsy/scrim/internal/stores"
	"github.com/heliopsy/scrim/internal/stores/memstore"
)

var ctx = context.Background()

func rules(list ...policy.Rule) policy.Engine {
	return policy.Rules{List: list, Default: policy.Static{Effect: policy.Deny}}
}

func under(prefix string) func(policy.Request) bool {
	return func(r policy.Request) bool { return strings.HasPrefix(r.Ref.String(), prefix) }
}

func TestPolicyAdapter(t *testing.T) {
	var seen []policy.Request
	eng := policyFunc(func(r policy.Request) policy.Decision {
		seen = append(seen, r)
		if strings.HasPrefix(r.Ref.Path, "agents/") {
			return policy.Decision{Effect: policy.Allow, Rule: "agents"}
		}
		return policy.Decision{Effect: policy.Ask, Rule: "ask"}
	})
	p := Policy{Engine: eng}
	id := agenttoolstest.Session("dev", "s1", 1000)
	d, err := p.Decide(ctx, id, agenttools.Operation{Tool: agenttools.ToolSecretGen, Ref: "bao://agents/x"})
	if err != nil || d.Effect != agenttools.EffectAllow || d.Rule != "agents" {
		t.Fatalf("%+v %v", d, err)
	}
	r := seen[0]
	if r.Action != policy.ActionGenerate || r.Agent.ID != "dev" || r.Agent.Session != "s1" || r.Agent.Kind != policy.IdentitySession ||
		r.Store != "bao" || r.Tool != agenttools.ToolSecretGen || r.Agent.Labels["uid"] != "1000" {
		t.Fatalf("request = %+v", r)
	}
	d, _ = p.Decide(ctx, id, agenttools.Operation{Tool: agenttools.ToolSecretCapture, Ref: "bao://prod/x"})
	if d.Effect != agenttools.EffectAsk || seen[1].Action != policy.ActionWrite {
		t.Fatalf("ask: %+v %+v", d, seen[1])
	}
	d, _ = p.Decide(ctx, id, agenttools.Operation{Tool: agenttools.ToolSecretPut, Ref: "not-a-ref"})
	if d.Effect != agenttools.EffectDeny || len(seen) != 2 {
		t.Fatalf("invalid ref reached the engine or was allowed: %+v", d)
	}
	d, _ = p.Decide(ctx, id, agenttools.Operation{Tool: agenttools.ToolSecretAskHuman, Ref: "agents/y", Store: "bao"})
	if d.Effect != agenttools.EffectAllow || seen[2].Ref.String() != "bao://agents/y" || seen[2].Action != policy.ActionAskHuman {
		t.Fatalf("name with store: %+v %+v", d, seen[2])
	}
	if _, err := (Policy{Engine: errEngine{}}).Decide(ctx, id, agenttools.Operation{Tool: agenttools.ToolSecretGen, Ref: "bao://a"}); err == nil {
		t.Fatal("engine error swallowed")
	}
}

type policyFunc func(policy.Request) policy.Decision

func (f policyFunc) Decide(_ context.Context, r policy.Request) (policy.Decision, error) {
	return f(r), nil
}

type errEngine struct{}

func (errEngine) Decide(context.Context, policy.Request) (policy.Decision, error) {
	return policy.Decision{}, errors.New("engine down")
}

func storeSet(t *testing.T) (*stores.Set, *memstore.Store) {
	t.Helper()
	m := memstore.New("bao")
	set := stores.NewSet()
	if err := set.Add(m); err != nil {
		t.Fatal(err)
	}
	return set, m
}

func TestStoresAdapter(t *testing.T) {
	set, m := storeSet(t)
	s := Stores{Set: set}
	id := agenttoolstest.Agent("dev", 1000)
	w, err := s.Write(ctx, id, agenttools.Write{Ref: "bao://kv/agents/app", Value: secret.FromString("store-test-value-1")})
	if err != nil || w.Ref != "bao://kv/agents/app#value" || w.Store != "bao" {
		t.Fatalf("%+v %v", w, err)
	}
	got, err := m.Read(ctx, stores.MustParseRef("bao://kv/agents/app#value"))
	if err != nil {
		t.Fatal(err)
	}
	v, _ := got.Field("value")
	if !v.Equal(secret.FromString("store-test-value-1")) {
		t.Fatal("value differs")
	}
	if _, err := s.Write(ctx, id, agenttools.Write{Ref: "bao://kv/agents/app", Value: secret.FromString("x")}); !errors.Is(err, agenttools.ErrExists) {
		t.Fatalf("create-only: %v", err)
	}
	if _, err := s.Write(ctx, id, agenttools.Write{Ref: "bao://kv/agents/app", Value: secret.FromString("x"), Overwrite: true}); err != nil {
		t.Fatalf("overwrite: %v", err)
	}
	src := secret.FromString("kept-test-value")
	if _, err := s.Write(ctx, id, agenttools.Write{Ref: "bao://kv/agents/db#password", Value: src}); err != nil {
		t.Fatal(err)
	}
	if src.Wiped() {
		t.Fatal("the adapter wiped the caller's value")
	}
	if _, err := s.Write(ctx, id, agenttools.Write{Ref: "vault://kv/x", Value: src}); !errors.Is(err, stores.ErrUnknownStore) {
		t.Fatalf("unknown store: %v", err)
	}
	if _, err := s.Write(ctx, id, agenttools.Write{Ref: "bao://kv/x", Store: "other", Value: src}); !errors.Is(err, stores.ErrInvalidRef) {
		t.Fatalf("store mismatch: %v", err)
	}

	m.Seed(stores.MustParseRef("bao://kv/agents/github"), map[string]secret.Value{"token": secret.FromString("ghp_TESTx")})
	_, _ = m.Write(ctx, stores.MustParseRef("bao://kv/agents/hetzner"), map[string]secret.Value{"value": secret.FromString("y")},
		stores.WriteOptions{Labels: map[string]string{bindingsLabel: "api.hetzner.cloud, dns.hetzner.com", "team": "infra"}})
	list, err := s.List(ctx, id, agenttools.ListInput{})
	if err != nil || len(list) != 4 {
		t.Fatalf("list: %+v %v", list, err)
	}
	var hz agenttools.SecretInfo
	for _, i := range list {
		if i.Ref == "bao://kv/agents/hetzner" {
			hz = i
		}
	}
	if len(hz.Bindings) != 2 || hz.Bindings[1] != "dns.hetzner.com" || hz.Metadata["team"] != "infra" || hz.Store != "bao" {
		t.Fatalf("hetzner = %+v", hz)
	}
	list, _ = s.List(ctx, id, agenttools.ListInput{Prefix: "bao://kv/agents/h"})
	raw, _ := json.Marshal(list)
	agenttoolstest.AssertNoValues(t, "list", raw, []byte("ghp_TESTx"), []byte("kept-test-value"))
}

func TestAuditAdapter(t *testing.T) {
	st := memstate.New()
	a := Audit{State: st}
	e := agenttools.AuditEntry{Time: time.Now(), Agent: "dev", Principal: "dev/s1", Source: "session", SessionID: "s1",
		UID: 1000, PID: 42, Tool: agenttools.ToolSecretGen, Ref: "bao://kv/agents/x", Store: "bao",
		Decision: "allow", Rule: "r1", Outcome: agenttools.OutcomeOK}
	if err := a.Record(ctx, e); err != nil {
		t.Fatal(err)
	}
	err := st.View(ctx, func(tx state.Tx) error {
		es, err := tx.QueryAudit(ctx, state.AuditQuery{AgentID: "dev"})
		if err != nil {
			return err
		}
		if len(es) != 1 {
			t.Fatalf("%d entries", len(es))
		}
		x := es[0]
		if x.Action != "tool.secret_gen" || x.Actor != "dev/s1" || x.Agent.Session != "s1" || x.Ref.String() != "bao://kv/agents/x" ||
			x.Effect != policy.Allow || x.Subject != "s1" || x.Attrs["outcome"] != "ok" || x.Outcome != audit.OutcomeOK || x.Attrs["pid"] != "42" {
			t.Fatalf("entry = %+v", x)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	u := Entry(agenttools.AuditEntry{Source: "unknown", UID: 7, Tool: "auth", Ref: "not a ref", Outcome: "refused"})
	if u.Outcome != audit.OutcomeRefused || u.Actor != "uid:7" || u.Agent.Kind != policy.IdentityUnknown || u.Attrs["ref"] != "not a ref" {
		t.Fatalf("unknown entry = %+v", u)
	}
}

func TestApprovalsAdapter(t *testing.T) {
	st := memstate.New()
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	ap := Approvals{
		Engine: rules(
			policy.Rule{Name: "agents", Match: under("bao://kv/agents/"), Effect: policy.Allow, GrantTTL: time.Hour},
			policy.Rule{Name: "github", Match: under("bao://kv/ask/"), Effect: policy.Ask},
		),
		State: st, DefaultTTL: 15 * time.Minute, MaxTTL: 8 * time.Hour, ApprovalTimeout: 10 * time.Minute,
		Now: func() time.Time { return now },
	}
	a := agenttoolstest.Session("dev", "s1", 1000)
	b := agenttoolstest.Session("dev", "s2", 1000)

	g, err := ap.Request(ctx, a, agenttools.GrantRequest{Ref: "bao://kv/agents/x", Duration: 2 * time.Hour, Reason: "r"})
	if err != nil || g.Status != agenttools.StatusGranted || !g.Capped || g.Duration != time.Hour || !g.ExpiresAt.Equal(now.Add(time.Hour)) {
		t.Fatalf("grant: %+v %v", g, err)
	}
	g2, _ := ap.Request(ctx, a, agenttools.GrantRequest{Ref: "bao://kv/agents/y", Reason: "r"})
	if g2.Duration != 15*time.Minute || g2.Capped {
		t.Fatalf("default ttl: %+v", g2)
	}
	gs, _ := ap.Grants(ctx, a)
	if len(gs) != 2 {
		t.Fatalf("A grants = %+v", gs)
	}
	if gs, _ := ap.Grants(ctx, b); len(gs) != 0 {
		t.Fatalf("B sees A's grants: %+v", gs)
	}

	p, err := ap.Request(ctx, a, agenttools.GrantRequest{Ref: "bao://kv/ask/github", Reason: "PR"})
	if err != nil || p.Status != agenttools.StatusPending || p.ApprovalID == "" {
		t.Fatalf("ask: %+v %v", p, err)
	}
	s, err := ap.Approval(ctx, a, p.ApprovalID)
	if err != nil || s.Status != agenttools.ApprovalPending || s.Ref != "bao://kv/ask/github" {
		t.Fatalf("status: %+v %v", s, err)
	}
	if _, err := ap.Approval(ctx, b, p.ApprovalID); !errors.Is(err, agenttools.ErrNotFound) {
		t.Fatalf("B reads A's approval: %v", err)
	}
	if _, err := ap.Approval(ctx, a, "apr_nope"); !errors.Is(err, agenttools.ErrNotFound) {
		t.Fatalf("unknown approval: %v", err)
	}
	now = now.Add(11 * time.Minute)
	if s, _ := ap.Approval(ctx, a, p.ApprovalID); s.Status != agenttools.ApprovalExpired {
		t.Fatalf("after timeout: %+v", s)
	}
	d, _ := ap.Request(ctx, a, agenttools.GrantRequest{Ref: "bao://kv/prod/x", Reason: "r"})
	if d.Status != agenttools.StatusDenied {
		t.Fatalf("deny: %+v", d)
	}
	d, _ = ap.Request(ctx, a, agenttools.GrantRequest{Ref: "nope", Reason: "r"})
	if d.Status != agenttools.StatusDenied {
		t.Fatalf("invalid ref: %+v", d)
	}
	now = now.Add(2 * time.Hour)
	if gs, _ := ap.Grants(ctx, a); len(gs) != 0 {
		t.Fatalf("expired grants listed: %+v", gs)
	}
}

func TestTerminalNotifier(t *testing.T) {
	var buf bytes.Buffer
	n := &TerminalNotifier{W: &buf}
	if err := n.NotifyAsk(ctx, agenttools.Notice{Agent: "dev", Ref: "bao://x", Prompt: "token", URL: "http://127.0.0.1:1/entry/t", ExpiresAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "http://127.0.0.1:1/entry/t") || !strings.Contains(buf.String(), "agent dev") {
		t.Fatalf("%q", buf.String())
	}
}

// TestRuntimeEndToEnd builds the runtime from the composition root, as
// `scrim api serve` does, and calls it over its socket.
func TestRuntimeEndToEnd(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("peer credentials are implemented on Linux and macOS")
	}
	dir, err := os.MkdirTemp("", "scrim")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	sock := filepath.Join(dir, "api.sock")
	home := t.TempDir()
	opts := config.Options{Registry: config.Default, SystemDir: home, Environ: []string{"HOME=" + home,
		"XDG_CONFIG_HOME=" + home, "XDG_STATE_HOME=" + home, "SCRIM_API_SOCKET=" + sock, "SCRIM_API_PERMISSIONS=0660"}}
	var logs bytes.Buffer
	a, err := app.New(ctx, opts, &logs)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = a.Close() }()
	set, _ := storeSet(t)
	a.Stores = set
	a.Policy = rules(policy.Rule{Name: "agents", Match: under("bao://kv/agents/"), Effect: policy.Allow})

	var notices bytes.Buffer
	rt, err := New(a, Options{Stderr: &notices})
	if err != nil {
		t.Fatal(err)
	}
	if rt.Socket != sock || !strings.HasPrefix(rt.EntryURL, "http://127.0.0.1:") {
		t.Fatalf("runtime = %s %s", rt.Socket, rt.EntryURL)
	}
	fi, _ := os.Stat(sock)
	if fi.Mode().Perm() != 0o660 {
		t.Fatalf("socket mode %v", fi.Mode().Perm())
	}
	sctx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- rt.Serve(sctx) }()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("serve: %v", err)
		}
	}()

	c := localapi.NewClient(sock, secret.Value{})
	defer c.Close()
	who, err := c.WhoAmI(ctx)
	if err != nil || who.Source != identity.SourcePeer || !who.Known() {
		t.Fatalf("whoami: %+v %v", who, err)
	}
	out, err := c.Generate(ctx, agenttools.GenInput{Ref: "bao://kv/agents/db#password"})
	if err != nil || out.Ref != "bao://kv/agents/db#password" {
		t.Fatalf("gen: %+v %v", out, err)
	}
	if _, err := c.Generate(ctx, agenttools.GenInput{Ref: "bao://kv/prod/db"}); agenttools.CodeOf(err) != agenttools.CodeDenied {
		t.Fatalf("default deny: %v", err)
	}
	g, err := c.Request(ctx, agenttools.RequestInput{Ref: "bao://kv/agents/db", Reason: "migrate"})
	if err != nil || g.Status != agenttools.StatusGranted {
		t.Fatalf("request: %+v %v", g, err)
	}
	gs, err := c.Grants(ctx)
	if err != nil || len(gs.Grants) != 1 {
		t.Fatalf("grants: %+v %v", gs, err)
	}
	ask, err := c.Ask(ctx, agenttools.AskInput{Ref: "bao://kv/agents/key", Prompt: "the key"})
	if err != nil || ask.Status != agenttools.AskPending {
		t.Fatalf("ask: %+v %v", ask, err)
	}
	if !strings.Contains(notices.String(), rt.EntryURL+"/entry/") {
		t.Fatalf("entry link not printed: %q", notices.String())
	}
	err = a.State.View(ctx, func(tx state.Tx) error {
		es, err := tx.QueryAudit(ctx, state.AuditQuery{})
		if err != nil {
			return err
		}
		if len(es) < 5 {
			t.Errorf("%d audit entries", len(es))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestSettings(t *testing.T) {
	cfg, err := config.Load(config.Default, config.EnvLayer([]string{`SCRIM_IDENTITY_PEERS={"claude":"user:root"}`, "SCRIM_SESSION_TTL=1h"}))
	if err != nil {
		t.Fatal(err)
	}
	if Peers.Get(cfg)["claude"] != "user:root" || SessionTTL.Get(cfg) != time.Hour {
		t.Fatal("settings not read from the environment")
	}
	for _, bad := range []string{"SCRIM_API_PERMISSIONS=999", "SCRIM_API_PERMISSIONS=0", "SCRIM_SESSION_TTL=-1h"} {
		if _, err := config.Load(config.Default, config.EnvLayer([]string{bad})); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}
