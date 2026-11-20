// SPDX-License-Identifier: AGPL-3.0-only

package agenttools_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"testing"
	"time"

	at "github.com/heliopsy/scrim/internal/agenttools"
	"github.com/heliopsy/scrim/internal/agenttools/agenttoolstest"
	"github.com/heliopsy/scrim/internal/identity"
	"github.com/heliopsy/scrim/internal/secret"
)

// Generated test values, never real secrets.
var (
	seedHetzner = []byte("hz-test-6f1d0c9a7b2e4d58a3c1")
	seedProd    = []byte("prod-test-0a9b8c7d6e5f4a3b2c1d")
)

func env(t *testing.T) *agenttoolstest.Env {
	t.Helper()
	e := agenttoolstest.NewEnv(t)
	e.Store.Seed(at.SecretInfo{Ref: "bao://kv/agents/hetzner", Name: "hetzner", Bindings: []string{"api.hetzner.cloud"}}, seedHetzner)
	e.Store.Seed(at.SecretInfo{Ref: "bao://kv/prod/db", Name: "prod-db"}, seedProd)
	return e
}

func code(t *testing.T, err error) at.Code {
	t.Helper()
	if err == nil {
		t.Fatal("want an error")
	}
	var e *at.Error
	if !errors.As(err, &e) {
		t.Fatalf("error %v is not an *agenttools.Error", err)
	}
	return e.Code
}

var ctx = context.Background()

func TestUnknownCallerIsRefusedAndAudited(t *testing.T) {
	e := env(t)
	unknown := identity.Unknown(identity.Peer{UID: 4000})
	_, err := e.Service.List(ctx, unknown, at.ListInput{})
	if code(t, err) != at.CodeUnauthenticated {
		t.Fatalf("err = %v", err)
	}
	if last := e.Audit.Last(); last.Outcome != at.OutcomeRefused || last.Tool != at.ToolSecretsList || last.UID != 4000 {
		t.Fatalf("audit = %+v", last)
	}
}

func TestScopesAreEnforced(t *testing.T) {
	e := env(t)
	ro := agenttoolstest.Agent("reader", 1000)
	ro.Scopes = []identity.Scope{identity.ScopeSecretsList}
	if _, err := e.Service.List(ctx, ro, at.ListInput{}); err != nil {
		t.Fatal(err)
	}
	_, err := e.Service.Generate(ctx, ro, at.GenInput{Ref: "bao://kv/agents/x"})
	if code(t, err) != at.CodeForbidden {
		t.Fatalf("gen without write scope: %v", err)
	}
	_, err = e.Service.Request(ctx, ro, at.RequestInput{Ref: "bao://kv/agents/x", Reason: "r"})
	if code(t, err) != at.CodeForbidden {
		t.Fatalf("request without request scope: %v", err)
	}
}

func TestListShowsOnlyWhatPolicyAllows(t *testing.T) {
	e := env(t)
	out, err := e.Service.List(ctx, agenttoolstest.Agent("dev", 1000), at.ListInput{})
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Secrets) != 1 || out.Secrets[0].Ref != "bao://kv/agents/hetzner" {
		t.Fatalf("secrets = %+v", out.Secrets)
	}
	if out.Secrets[0].Placeholder == "" {
		t.Error("no placeholder")
	}
	for _, f := range []at.ListInput{{Binding: "api.github.com"}, {Prefix: "bao://kv/other/"}, {Store: "infisical"}} {
		out, err := e.Service.List(ctx, agenttoolstest.Agent("dev", 1000), f)
		if err != nil || len(out.Secrets) != 0 {
			t.Errorf("filter %+v: %+v %v", f, out.Secrets, err)
		}
	}
	out, _ = e.Service.List(ctx, agenttoolstest.Agent("dev", 1000), at.ListInput{Binding: "API.hetzner.cloud"})
	if len(out.Secrets) != 1 {
		t.Errorf("binding filter is case sensitive")
	}
	e.Policy.Err = errors.New("engine down")
	if _, err := e.Service.List(ctx, agenttoolstest.Agent("dev", 1000), at.ListInput{}); code(t, err) != at.CodeUnavailable {
		t.Errorf("policy error: %v", err)
	}
}

func TestRequestFlows(t *testing.T) {
	e := env(t)
	dev := agenttoolstest.Agent("dev", 1000)

	g, err := e.Service.Request(ctx, dev, at.RequestInput{Ref: "bao://kv/agents/hetzner", Duration: "30m", Reason: "deploy"})
	if err != nil || g.Status != at.StatusGranted || g.GrantID == "" || g.Capped || g.Duration != "30m0s" {
		t.Fatalf("granted: %+v %v", g, err)
	}

	c, err := e.Service.Request(ctx, dev, at.RequestInput{Ref: "bao://kv/agents/hetzner", Duration: "5h", Reason: "long job"})
	if err != nil || !c.Capped || c.Duration != "2h0m0s" {
		t.Fatalf("capped: %+v %v", c, err)
	}

	p, err := e.Service.Request(ctx, dev, at.RequestInput{Ref: "bao://kv/agents/ask/github", Duration: "30m", Reason: "open a PR"})
	if err != nil || p.Status != at.StatusPending || p.ApprovalID == "" || p.GrantID != "" {
		t.Fatalf("pending: %+v %v", p, err)
	}
	if last := e.Audit.Last(); last.Outcome != at.OutcomePending || last.ApprovalID != p.ApprovalID {
		t.Fatalf("audit = %+v", last)
	}
	st, err := e.Service.Status(ctx, dev, at.StatusInput{ID: p.ApprovalID})
	if err != nil || st.Status != at.ApprovalPending || st.Kind != "approval" {
		t.Fatalf("status: %+v %v", st, err)
	}
	gs, _ := e.Service.Grants(ctx, dev)
	before := len(gs.Grants)
	if err := e.Approvals.Settle(p.ApprovalID, true); err != nil {
		t.Fatal(err)
	}
	st, _ = e.Service.Status(ctx, dev, at.StatusInput{ID: p.ApprovalID})
	if st.Status != at.ApprovalApproved || st.GrantID == "" {
		t.Fatalf("after approval: %+v", st)
	}
	gs, _ = e.Service.Grants(ctx, dev)
	if len(gs.Grants) != before+1 || gs.Grants[len(gs.Grants)-1].Ref != "bao://kv/agents/ask/github" {
		t.Fatalf("grants = %+v", gs.Grants)
	}

	d, err := e.Service.Request(ctx, dev, at.RequestInput{Ref: "bao://kv/agents/deny/x", Reason: "r"})
	if err != nil || d.Status != at.StatusDenied || d.Reason == "" {
		t.Fatalf("denied: %+v %v", d, err)
	}
	if e.Audit.Last().Outcome != at.OutcomeDenied {
		t.Fatalf("audit = %+v", e.Audit.Last())
	}

	for _, bad := range []at.RequestInput{
		{Ref: "bao://kv/agents/hetzner", Duration: "soon", Reason: "r"},
		{Ref: "bao://kv/agents/hetzner", Duration: "-5m", Reason: "r"},
		{Ref: "bao://kv/agents/hetzner", Duration: "10000h", Reason: "r"},
		{Ref: "bao://kv/agents/hetzner", Reason: " "},
		{Ref: "has space", Reason: "r"},
		{Ref: "", Reason: "r"},
	} {
		if _, err := e.Service.Request(ctx, dev, bad); code(t, err) != at.CodeInvalid {
			t.Errorf("%+v: %v", bad, err)
		}
	}
}

// TestAgentsCannotSeeEachOthersApprovalsOrGrants covers the spec scenario
// "Another agent's approval" and the identity requirement that grants
// belong to one identity, including two sessions of the same agent.
func TestAgentsCannotSeeEachOthersApprovalsOrGrants(t *testing.T) {
	e := env(t)
	a := agenttoolstest.Session("dev", "sessa", 1000)
	b := agenttoolstest.Session("dev", "sessb", 1000)
	other := agenttoolstest.Agent("ops", 1001)

	p, err := e.Service.Request(ctx, a, at.RequestInput{Ref: "bao://kv/agents/ask/github", Reason: "r"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.Service.Request(ctx, a, at.RequestInput{Ref: "bao://kv/agents/hetzner", Reason: "r"}); err != nil {
		t.Fatal(err)
	}
	for _, who := range []identity.Identity{b, other, agenttoolstest.Agent("dev", 1000)} {
		_, err := e.Service.Status(ctx, who, at.StatusInput{ID: p.ApprovalID})
		if code(t, err) != at.CodeNotFound {
			t.Errorf("%s sees A's approval: %v", who, err)
		}
		gs, err := e.Service.Grants(ctx, who)
		if err != nil || len(gs.Grants) != 0 {
			t.Errorf("%s sees grants %+v", who, gs.Grants)
		}
	}
	gs, _ := e.Service.Grants(ctx, a)
	if len(gs.Grants) != 1 {
		t.Fatalf("A's grants = %+v", gs.Grants)
	}
}

func TestGenerateStoresAndReturnsOnlyTheReference(t *testing.T) {
	e := env(t)
	dev := agenttoolstest.Agent("dev", 1000)
	out, err := e.Service.Generate(ctx, dev, at.GenInput{Ref: "bao://kv/agents/app-db#password", Length: 32})
	if err != nil {
		t.Fatal(err)
	}
	v, ok := e.Store.Value("bao://kv/agents/app-db#password")
	if !ok || len(v) != 32 {
		t.Fatalf("stored %d bytes", len(v))
	}
	if out.Status != at.StatusStored || out.Ref != "bao://kv/agents/app-db#password" || out.Store != "bao" || out.Length != 32 || out.Placeholder == "" {
		t.Fatalf("out = %+v", out)
	}
	raw, _ := json.Marshal(out)
	agenttoolstest.AssertNoValues(t, "secret_gen result", raw, v)
	audit, _ := json.Marshal(e.Audit.All())
	agenttoolstest.AssertNoValues(t, "audit log", audit, v)
	last := e.Audit.Last()
	if last.Tool != at.ToolSecretGen || last.Agent != "dev" || last.Ref != out.Ref || last.Store != "bao" || last.Outcome != at.OutcomeOK || last.Time.IsZero() {
		t.Fatalf("audit = %+v", last)
	}

	_, err = e.Service.Generate(ctx, dev, at.GenInput{Ref: "bao://kv/agents/app-db#password"})
	if code(t, err) != at.CodeConflict {
		t.Fatalf("second gen without overwrite: %v", err)
	}
	if _, err := e.Service.Generate(ctx, dev, at.GenInput{Ref: "bao://kv/agents/app-db#password", Overwrite: true, Format: at.FormatUUID}); err != nil {
		t.Fatal(err)
	}
	if v2, _ := e.Store.Value("bao://kv/agents/app-db#password"); len(v2) != 36 || bytes.Equal(v, v2) {
		t.Fatal("overwrite did not store a new uuid")
	}

	_, err = e.Service.Generate(ctx, dev, at.GenInput{Ref: "bao://kv/prod/new"})
	if code(t, err) != at.CodeDenied {
		t.Fatalf("outside policy: %v", err)
	}
	if _, ok := e.Store.Value("bao://kv/prod/new"); ok {
		t.Fatal("denied generate stored a value")
	}
}

// valueEchoingError is a store error that carries the value, as a careless
// adapter might produce.
type valueEchoingError struct{ v []byte }

func (e valueEchoingError) Error() string { return "write rejected: " + string(e.v) }

func TestStoreWriteFailureReturnsNothingAboutTheValue(t *testing.T) {
	e := env(t)
	dev := agenttoolstest.Agent("dev", 1000)
	val := []byte("put-test-value-9d8c7b6a5f4e")
	e.Store.WriteErr = valueEchoingError{v: val}
	var logs bytes.Buffer
	svc, err := at.New(at.Deps{Policy: e.Policy, Approvals: e.Approvals, Catalog: e.Store, Store: e.Store,
		Auditor: e.Audit, Logger: newLogger(&logs)})
	if err != nil {
		t.Fatal(err)
	}
	_, err = svc.Put(ctx, dev, at.PutInput{Ref: "bao://kv/agents/new"}, secret.New(val))
	if code(t, err) != at.CodeUnavailable {
		t.Fatalf("err = %v", err)
	}
	agenttoolstest.AssertNoValues(t, "error", []byte(err.Error()), val)
	agenttoolstest.AssertNoValues(t, "log", logs.Bytes(), val)
	if !strings.Contains(logs.String(), "withheld") {
		t.Errorf("log does not say the error was withheld: %s", logs.String())
	}
	_, err = svc.Generate(ctx, dev, at.GenInput{Ref: "bao://kv/agents/gen"})
	if code(t, err) != at.CodeUnavailable {
		t.Fatalf("gen: %v", err)
	}
	if last := e.Audit.Last(); last.Outcome != at.OutcomeError {
		t.Fatalf("audit = %+v", last)
	}
}

func TestPutWipesTheValue(t *testing.T) {
	e := env(t)
	dev := agenttoolstest.Agent("dev", 1000)
	v := secret.FromString("put-test-value-1a2b3c4d5e6f")
	out, err := e.Service.Put(ctx, dev, at.PutInput{Ref: "bao://kv/agents/new-token"}, v)
	if err != nil || out.Status != at.StatusStored {
		t.Fatalf("%+v %v", out, err)
	}
	if !v.Wiped() {
		t.Fatal("value not wiped after Put")
	}
	if got, _ := e.Store.Value("bao://kv/agents/new-token"); string(got) != "put-test-value-1a2b3c4d5e6f" {
		t.Fatal("stored value differs")
	}
	if e.Audit.Last().Tool != at.ToolSecretPut {
		t.Fatalf("audit tool = %s", e.Audit.Last().Tool)
	}
	v2 := secret.FromString("x")
	_, err = e.Service.Put(ctx, dev, at.PutInput{Ref: "bao://kv/prod/x", Origin: at.ToolSecretCapture}, v2)
	if code(t, err) != at.CodeDenied || !v2.Wiped() {
		t.Fatalf("denied put: %v, wiped %v", err, v2.Wiped())
	}
	if e.Audit.Last().Tool != at.ToolSecretCapture {
		t.Fatalf("audit tool = %s", e.Audit.Last().Tool)
	}
	if _, err := e.Service.Put(ctx, dev, at.PutInput{Ref: "bao://kv/agents/e"}, secret.Value{}); code(t, err) != at.CodeInvalid {
		t.Fatalf("empty: %v", err)
	}
	big := secret.New(bytes.Repeat([]byte("a"), at.MaxValueSize+1))
	if _, err := e.Service.Put(ctx, dev, at.PutInput{Ref: "bao://kv/agents/e"}, big); code(t, err) != at.CodeInvalid {
		t.Fatalf("too big: %v", err)
	}
	if _, err := e.Service.Put(ctx, dev, at.PutInput{Ref: "bao://kv/agents/e", Origin: "secret_gen"}, secret.FromString("abcdefgh")); code(t, err) != at.CodeInvalid {
		t.Fatalf("bad origin: %v", err)
	}
}

func TestAskPolicyNeedsAGrant(t *testing.T) {
	e := env(t)
	dev := agenttoolstest.Agent("dev", 1000)
	e.Policy.SetRules(agenttoolstest.Rule{Prefix: "bao://kv/agents/", Effect: at.EffectAsk})
	_, err := e.Service.Put(ctx, dev, at.PutInput{Ref: "bao://kv/agents/x"}, secret.FromString("abcdefgh"))
	if code(t, err) != at.CodeNeedsApproval {
		t.Fatalf("err = %v", err)
	}
	if !strings.Contains(err.Error(), "secret_request") {
		t.Errorf("message does not point at secret_request: %v", err)
	}
	if _, err := e.Service.Request(ctx, dev, at.RequestInput{Ref: "bao://kv/agents/x", Reason: "r"}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Service.Put(ctx, dev, at.PutInput{Ref: "bao://kv/agents/x"}, secret.FromString("abcdefgh")); err != nil {
		t.Fatalf("after grant: %v", err)
	}
}

func TestCheck(t *testing.T) {
	e := env(t)
	dev := agenttoolstest.Agent("dev", 1000)
	ok, err := e.Service.Check(ctx, dev, at.CheckInput{Tool: at.ToolSecretCapture, Ref: "bao://kv/agents/x"})
	if err != nil || !ok.Allowed {
		t.Fatalf("%+v %v", ok, err)
	}
	no, err := e.Service.Check(ctx, dev, at.CheckInput{Tool: at.ToolSecretCapture, Ref: "bao://kv/prod/x"})
	if err != nil || no.Allowed || no.Reason == "" {
		t.Fatalf("%+v %v", no, err)
	}
	if _, err := e.Service.Check(ctx, dev, at.CheckInput{Tool: at.ToolSecretsList, Ref: "x"}); code(t, err) != at.CodeInvalid {
		t.Fatalf("list check: %v", err)
	}
	if _, err := e.Service.Check(ctx, identity.Unknown(identity.Peer{}), at.CheckInput{Tool: at.ToolSecretPut, Ref: "bao://kv/agents/x"}); code(t, err) != at.CodeUnauthenticated {
		t.Fatalf("unknown check: %v", err)
	}
}

func TestAuditFailureFailsTheCall(t *testing.T) {
	e := env(t)
	e.Audit.Err = errors.New("disk full")
	_, err := e.Service.List(ctx, agenttoolstest.Agent("dev", 1000), at.ListInput{})
	if code(t, err) != at.CodeUnavailable {
		t.Fatalf("err = %v", err)
	}
}

func TestErrorsArePublic(t *testing.T) {
	if got := at.Public(errors.New("dependency said something")); got.Code != at.CodeInternal || strings.Contains(got.Message, "dependency") {
		t.Fatalf("Public = %+v", got)
	}
	wrapped := fmt.Errorf("ctx: %w", at.Errorf(at.CodeDenied, "no"))
	if at.CodeOf(wrapped) != at.CodeDenied {
		t.Fatal("CodeOf does not unwrap")
	}
}

func TestNewRequiresDependencies(t *testing.T) {
	if _, err := at.New(at.Deps{}); err == nil || !strings.Contains(err.Error(), "policy") {
		t.Fatalf("err = %v", err)
	}
}

func TestGenerateFormats(t *testing.T) {
	for _, tc := range []struct {
		in   at.GenInput
		re   string
		size int
	}{
		{at.GenInput{}, `^[A-Za-z0-9]{32}$`, 32},
		{at.GenInput{Length: 8, Charset: at.CharsetDigits}, `^[0-9]{8}$`, 8},
		{at.GenInput{Length: 64, Charset: at.CharsetLower}, `^[a-z]{64}$`, 64},
		{at.GenInput{Length: 40, Charset: at.CharsetAlnumSymbols}, `^[A-Za-z0-9!#%+\-.:=@^_~]{40}$`, 40},
		{at.GenInput{Length: 20, Charset: at.CharsetAlpha}, `^[A-Za-z]{20}$`, 20},
		{at.GenInput{Format: at.FormatHex, Length: 64}, `^[0-9a-f]{64}$`, 64},
		{at.GenInput{Format: at.FormatBase64, Length: 44}, `^[A-Za-z0-9+/]{44}$`, 44},
		{at.GenInput{Format: at.FormatBase64URL, Length: 43}, `^[A-Za-z0-9_-]{43}$`, 43},
		{at.GenInput{Format: at.FormatUUID}, `^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`, 36},
		{at.GenInput{Format: at.FormatPassphrase, Words: 5, Separator: "."}, `^[a-z-]+(\.[a-z-]+){4}$`, 0},
	} {
		spec, err := at.NormalizeGen(tc.in)
		if err != nil {
			t.Fatalf("%+v: %v", tc.in, err)
		}
		v, err := at.Generate(spec, nil)
		if err != nil {
			t.Fatal(err)
		}
		_ = v.Expose(func(b []byte) error {
			if !regexp.MustCompile(tc.re).Match(b) || tc.size > 0 && len(b) != tc.size {
				t.Errorf("%+v: generated value does not match %s (len %d)", tc.in, tc.re, len(b))
			}
			return nil
		})
		v2, _ := at.Generate(spec, nil)
		if v.Equal(v2) {
			t.Errorf("%+v: two generations are equal", tc.in)
		}
	}
	for _, bad := range []at.GenInput{
		{Length: 7}, {Length: at.MaxLength + 1}, {Format: "rot13"}, {Charset: "emoji"}, {Charset: at.FormatHex},
		{Format: at.FormatHex, Charset: at.CharsetAlnum}, {Format: at.FormatUUID, Length: 10},
		{Format: at.FormatPassphrase, Length: 10}, {Format: at.FormatPassphrase, Words: 3},
		{Format: at.FormatPassphrase, Separator: "\n"}, {Words: 6},
	} {
		if _, err := at.NormalizeGen(bad); code(t, err) != at.CodeInvalid {
			t.Errorf("%+v accepted", bad)
		}
	}
}

func TestGenerateHasNoVisibleBias(t *testing.T) {
	spec, _ := at.NormalizeGen(at.GenInput{Length: 4096, Charset: at.CharsetDigits})
	counts := map[byte]int{}
	for range 10 {
		v, _ := at.Generate(spec, nil)
		_ = v.Expose(func(b []byte) error {
			for _, c := range b {
				counts[c]++
			}
			return nil
		})
	}
	for c, n := range counts {
		// 4096 draws per digit expected; 5 sigma is about 300.
		if n < 4096-400 || n > 4096+400 {
			t.Errorf("digit %c drawn %d times", c, n)
		}
	}
}

func TestStatusRejectsEmptyID(t *testing.T) {
	e := env(t)
	if _, err := e.Service.Status(ctx, agenttoolstest.Agent("dev", 1000), at.StatusInput{}); code(t, err) != at.CodeInvalid {
		t.Fatal(err)
	}
	if _, err := e.Service.Status(ctx, agenttoolstest.Agent("dev", 1000), at.StatusInput{ID: "ask_nothing"}); code(t, err) != at.CodeNotFound {
		t.Fatal(err)
	}
}

func TestRequestDeadlineFree(t *testing.T) {
	// Request outputs carry UTC times, so JSON is stable across zones.
	e := env(t)
	out, err := e.Service.Request(ctx, agenttoolstest.Agent("dev", 1000), at.RequestInput{Ref: "bao://kv/agents/hetzner", Reason: "r"})
	if err != nil {
		t.Fatal(err)
	}
	if out.ExpiresAt.Location() != time.UTC {
		t.Fatalf("expires_at in %v", out.ExpiresAt.Location())
	}
}

func newLogger(w *bytes.Buffer) *slog.Logger { return slog.New(slog.NewTextHandler(w, nil)) }
