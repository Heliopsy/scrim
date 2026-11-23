// SPDX-License-Identifier: AGPL-3.0-only

package agentstore

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/identity"
	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores"
	"github.com/heliopsy/scrim/internal/stores/memstore"
)

// fakeStore is a memory store that answers AgentCan from a table of what
// each credential may read.
type fakeStore struct {
	stores.Adapter
	// allow maps "<role or token>" to the path prefix it may read.
	allow map[string]string
	got   []stores.AgentCredential
	jwts  []string
}

func (f *fakeStore) AgentCan(_ context.Context, c stores.AgentCredential, op stores.Op, ref stores.Ref) error {
	f.got = append(f.got, c)
	key := c.Role
	_ = c.KubernetesJWT.Expose(func(b []byte) error { f.jwts = append(f.jwts, string(b)); return nil })
	if !c.Token.IsZero() {
		_ = c.Token.Expose(func(b []byte) error { key = string(b); return nil })
	}
	if p, ok := f.allow[key]; ok && strings.HasPrefix(ref.Path, p) {
		return nil
	}
	return stores.NewError(f.Name(), op, ref, stores.ErrPermission, nil)
}

func newChecker(t *testing.T, login, creds map[string]string, f *fakeStore) *Checker {
	t.Helper()
	set := stores.NewSet()
	if err := set.Add(f); err != nil {
		t.Fatal(err)
	}
	plain := stores.NewSet()
	if err := plain.Add(memstore.New("plain")); err != nil {
		t.Fatal(err)
	}
	c, err := New(Options{Login: login, Credentials: creds,
		Lookup: func(r stores.Ref) (stores.Adapter, error) {
			if a, err := set.Lookup(r); err == nil {
				return a, nil
			}
			return plain.Lookup(r)
		},
		Resolve: func(_ context.Context, r config.SecretRef) (secret.Value, error) {
			v, ok := strings.CutPrefix(string(r), "env:")
			if !ok {
				return secret.Value{}, errors.New("unexpected reference")
			}
			return secret.FromString("tok-" + v), nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func pod(ns, sa string) identity.Identity {
	return identity.Identity{Agent: ns + "/" + sa, Source: identity.SourceKubernetes,
		Labels: map[string]string{identity.LabelNamespace: ns, identity.LabelServiceAccount: sa}}
}

func ref(t *testing.T, s string) stores.Ref {
	t.Helper()
	r, err := stores.ParseRef(s)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestPassthroughStaticAndShared(t *testing.T) {
	f := &fakeStore{Adapter: memstore.New("bao"), allow: map[string]string{
		"agents-agent-a": "kv/agents/a/", "agents-agent-b": "kv/agents/b/", "tok-LAPTOP": "kv/laptop/",
	}}
	c := newChecker(t, map[string]string{"bao": "kubernetes role:{namespace}-{service_account} mount:k8s-agents"},
		map[string]string{"bao/laptop": "env:LAPTOP"}, f)
	ctx := context.Background()
	jwt := []byte("eyJ.a.b")

	if src, err := c.Check(ctx, pod("agents", "agent-a"), jwt, stores.OpRead, ref(t, "bao://kv/agents/a/x")); err != nil || src != SourceKubernetes {
		t.Fatalf("agent-a own path: %s %v", src, err)
	}
	if got := f.got[0]; got.Role != "agents-agent-a" || got.Mount != "k8s-agents" || f.jwts[0] != string(jwt) {
		t.Fatalf("credential %+v", got)
	}
	if f.got[0].KubernetesJWT.Len() != 0 {
		t.Fatal("the JWT copy was not wiped after the check")
	}
	_, err := c.Check(ctx, pod("agents", "agent-a"), jwt, stores.OpRead, ref(t, "bao://kv/agents/b/x"))
	if !errors.Is(err, stores.ErrPermission) {
		t.Fatalf("agent-a reading b's path: %v", err)
	}
	if _, err := c.Check(ctx, pod("agents", "agent-b"), jwt, stores.OpRead, ref(t, "bao://kv/agents/b/x")); err != nil {
		t.Fatal(err)
	}
	// A peer agent with a static credential uses it.
	laptop := identity.Identity{Agent: "laptop", Source: identity.SourcePeer}
	if src, err := c.Check(ctx, laptop, nil, stores.OpRead, ref(t, "bao://kv/laptop/k")); err != nil || src != SourceStatic {
		t.Fatalf("laptop: %s %v", src, err)
	}
	// An agent with neither is refused for the governed store...
	other := identity.Identity{Agent: "other", Source: identity.SourcePeer}
	if src, err := c.Check(ctx, other, nil, stores.OpRead, ref(t, "bao://kv/laptop/k")); !errors.Is(err, ErrNoIdentity) || src != SourceNone {
		t.Fatalf("other: %s %v", src, err)
	}
	// ...and a Kubernetes caller whose token is missing too.
	if _, err := c.Check(ctx, pod("agents", "agent-a"), nil, stores.OpRead, ref(t, "bao://kv/agents/a/x")); !errors.Is(err, ErrNoIdentity) {
		t.Fatalf("no token: %v", err)
	}
	// An ungoverned store is shared.
	if src, err := c.Check(ctx, other, nil, stores.OpRead, ref(t, "plain://x")); err != nil || src != SourceShared {
		t.Fatalf("plain: %s %v", src, err)
	}
	if g := c.Governed(); len(g) != 1 || g[0] != "bao" {
		t.Fatalf("governed %v", g)
	}
}

func TestSettingsValidation(t *testing.T) {
	for name, o := range map[string]Options{
		"no method":         {Login: map[string]string{"bao": "role:x"}},
		"no role":           {Login: map[string]string{"bao": "kubernetes mount:k"}},
		"bad placeholder":   {Login: map[string]string{"bao": "kubernetes role:{pod}"}},
		"unknown option":    {Login: map[string]string{"bao": "kubernetes role:x ttl:1h"}},
		"literal":           {Credentials: map[string]string{"bao/a": "hvs.literal-token-value"}},
		"key without slash": {Credentials: map[string]string{"bao": "env:X"}},
	} {
		_, err := New(o)
		if err == nil {
			t.Errorf("%s: accepted", name)
		} else if strings.Contains(err.Error(), "hvs.literal") {
			t.Errorf("%s: the error echoes the literal", name)
		}
	}
}

func TestReport(t *testing.T) {
	f := &fakeStore{Adapter: memstore.New("bao")}
	c := newChecker(t, map[string]string{"bao": "kubernetes role:{service_account}"}, map[string]string{"vw/laptop": "env:X"}, f)
	rows := c.Report([]string{"bao", "vw", "env"}, []string{"laptop", "ci"})
	var lines []string
	for _, r := range rows {
		lines = append(lines, r.Store+" "+r.Agent+" "+r.Source)
	}
	got := strings.Join(lines, "\n")
	for _, want := range []string{"bao * kubernetes", "bao ci none", "vw laptop static", "vw ci none", "vw * none", "env * shared"} {
		if !strings.Contains(got, want) {
			t.Errorf("report lacks %q:\n%s", want, got)
		}
	}
}

// fedStore records the federation it is asked with and mints the token, as
// a store adapter would, answering from a table of role -> readable prefix.
type fedStore struct {
	stores.Adapter
	methods []string
	allow   map[string]string
	got     []stores.Federation
	tokens  []string
}

func (f *fedStore) FederationMethods() []string { return f.methods }

func (f *fedStore) AgentCan(_ context.Context, c stores.AgentCredential, op stores.Op, ref stores.Ref) error {
	if c.Federation == nil {
		return stores.NewError(f.Name(), op, ref, stores.ErrUnsupported, nil)
	}
	f.got = append(f.got, *c.Federation)
	tok, err := c.Federation.Token()
	if err != nil {
		return stores.NewError(f.Name(), op, ref, stores.ErrPermission, err)
	}
	_ = tok.Expose(func(b []byte) error { f.tokens = append(f.tokens, string(b)); return nil })
	tok.Wipe()
	role := c.Federation.Params["role"] + c.Federation.Params["role-arn"]
	if p, ok := f.allow[role]; ok && strings.HasPrefix(ref.Path, p) {
		return nil
	}
	return stores.NewError(f.Name(), op, ref, stores.ErrPermission, nil)
}

// fakeIssuer mints "<agent>|<audience>|<session>" tokens.
type fakeIssuer struct{ minted int }

func (i *fakeIssuer) Mint(id identity.Identity, aud string) (secret.Value, time.Time, error) {
	if !id.Known() {
		return secret.Value{}, time.Time{}, errors.New("unknown")
	}
	i.minted++
	return secret.FromString(id.Agent + "|" + aud + "|" + id.SessionID), time.Now().Add(time.Minute), nil
}

func session(agent, sid string) identity.Identity {
	return identity.Identity{Agent: agent, Source: identity.SourceSession, SessionID: sid, Scopes: identity.AgentScopes}
}

// TestTokenExchange: a store with a token exchange login gets, per agent,
// the rendered options, the audience, a session name the store's audit can
// show, a cache key per identity and options, and a minter that signs for
// that agent only when the store needs a token. The store's answer
// decides: two agents with the same scrim permission get different store
// outcomes (the intersection).
func TestTokenExchange(t *testing.T) {
	f := &fedStore{Adapter: memstore.New("bao"), methods: []string{stores.FederationJWT},
		allow: map[string]string{"agent-claude-laptop": "kv/agents/claude-laptop/"}}
	iss := &fakeIssuer{}
	set := stores.NewSet()
	if err := set.Add(f); err != nil {
		t.Fatal(err)
	}
	c, err := New(Options{Login: map[string]string{"bao": "jwt role:agent-{agent_slug} audience:openbao mount:/jwt-agents/"},
		Lookup: set.Lookup, Issuer: iss, RequireIssuer: true,
		Adapter: func(n string) (stores.Adapter, bool) { return f, n == "bao" }})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	laptop := session("claude-laptop", "s1")
	if src, err := c.Check(ctx, laptop, nil, stores.OpRead, ref(t, "bao://kv/agents/claude-laptop/db")); err != nil || src != SourceFederated {
		t.Fatalf("claude-laptop: %s %v", src, err)
	}
	g := f.got[0]
	if g.Method != "jwt" || g.Params["role"] != "agent-claude-laptop" || g.Params["mount"] != "jwt-agents" || g.Audience != "openbao" ||
		g.SessionName != "claude-laptop.s1" || g.Session != "s1" || f.tokens[0] != "claude-laptop|openbao|s1" {
		t.Fatalf("federation %+v token %q", g, f.tokens[0])
	}
	// Same scrim rules, another agent: the store refuses it.
	if _, err := c.Check(ctx, session("intruder", "s2"), nil, stores.OpRead, ref(t, "bao://kv/agents/claude-laptop/db")); !errors.Is(err, stores.ErrPermission) {
		t.Fatalf("intruder: %v", err)
	}
	// A Kubernetes agent's role renders from its slug, and each pod is its
	// own cache key.
	p := pod("agents", "agent-a")
	p.Labels[identity.LabelPod] = "agent-a-0"
	_, _ = c.Check(ctx, p, nil, stores.OpRead, ref(t, "bao://kv/x"))
	p.Labels[identity.LabelPod] = "agent-a-1"
	_, _ = c.Check(ctx, p, nil, stores.OpRead, ref(t, "bao://kv/x"))
	if n := len(f.got); f.got[n-1].Params["role"] != "agent-agents-agent-a" || f.got[n-1].SessionName != "k8s.agents.agent-a" ||
		f.got[n-1].Key == f.got[n-2].Key || f.got[0].Key == f.got[1].Key {
		t.Fatalf("kubernetes federation %+v", f.got[n-1])
	}
	// An unknown caller has no identity for the store.
	if _, err := c.Check(ctx, identity.Unknown(identity.Peer{}), nil, stores.OpRead, ref(t, "bao://kv/x")); !errors.Is(err, ErrNoIdentity) {
		t.Fatalf("unknown: %v", err)
	}
	if rows := c.Report([]string{"bao"}, []string{"claude-laptop"}); len(rows) != 2 || rows[0].Source != SourceFederated ||
		!strings.Contains(rows[0].Detail, "role:agent-{agent_slug}") {
		t.Fatalf("report %+v", rows)
	}
}

func TestTokenExchangeSettings(t *testing.T) {
	f := &fedStore{Adapter: memstore.New("bao"), methods: []string{stores.FederationJWT}}
	adapter := func(n string) (stores.Adapter, bool) {
		if n == "plain" {
			return memstore.New("plain"), true
		}
		return f, n == "bao"
	}
	iss := &fakeIssuer{}
	for name, login := range map[string]string{
		"jwt without audience":    "jwt role:x",
		"aws without role":        "aws-web-identity audience:sts.amazonaws.com",
		"aws short duration":      "aws-web-identity role-arn:arn:aws:iam::000000000000:role/x duration:5m",
		"gcp bad provider":        "gcp-workload-identity provider:projects/1/x",
		"azure without client":    "azure-federated tenant:t",
		"azure http authority":    "azure-federated tenant:t client-id:c authority:http://login.example",
		"infisical no audience":   "infisical-oidc identity-id:abc",
		"placeholder in audience": "jwt role:x audience:{agent}",
		"unknown method":          "oidc role:x",
		"option twice":            "jwt role:x role:y audience:a",
	} {
		if _, err := New(Options{Login: map[string]string{"bao": login}, Issuer: iss}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// The store must take the method, and an issuer must exist.
	if _, err := New(Options{Login: map[string]string{"bao": "aws-web-identity role-arn:arn:aws:iam::000000000000:role/x"}, Issuer: iss, Adapter: adapter}); err == nil ||
		!strings.Contains(err.Error(), "does not take method aws-web-identity") {
		t.Errorf("unsupported method: %v", err)
	}
	if _, err := New(Options{Login: map[string]string{"plain": "jwt role:x audience:a"}, Issuer: iss, Adapter: adapter}); err == nil {
		t.Error("a store without token exchange accepted a jwt login")
	}
	if _, err := New(Options{Login: map[string]string{"nope": "jwt role:x audience:a"}, Issuer: iss, Adapter: adapter}); err == nil {
		t.Error("a login for a store that does not exist accepted")
	}
	if _, err := New(Options{Login: map[string]string{"bao": "jwt role:x audience:a"}, RequireIssuer: true}); err == nil ||
		!strings.Contains(err.Error(), "identity.issuer.url") {
		t.Errorf("no issuer: %v", err)
	}
	// Defaults.
	c, err := New(Options{Login: map[string]string{
		"aws": "aws-web-identity role-arn:arn:aws:iam::000000000000:role/agent-{agent}",
		"gsm": "gcp-workload-identity provider://iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/providers/scrim",
		"akv": "azure-federated tenant:t client-id:{agent}",
	}, Issuer: iss})
	if err != nil {
		t.Fatal(err)
	}
	for store, want := range map[string]string{
		"aws": "aws-web-identity audience:sts.amazonaws.com duration:15m role-arn:arn:aws:iam::000000000000:role/agent-{agent}",
		"gsm": "audience:https://iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/providers/scrim",
		"akv": "audience:api://AzureADTokenExchange authority:https://login.microsoftonline.com client-id:{agent} tenant:t",
	} {
		if got := c.logins[store].describe(); !strings.Contains(got, want) {
			t.Errorf("%s: %q lacks %q", store, got, want)
		}
	}
}

func TestSessionName(t *testing.T) {
	long := identity.Identity{Agent: strings.Repeat("a", 70), Source: identity.SourceSession, SessionID: "sess-end"}
	for id, want := range map[*identity.Identity]string{
		{Agent: "claude-laptop", Source: identity.SourcePeer}:                      "claude-laptop",
		{Agent: "x", Source: identity.SourcePeer}:                                  "x-",
		{Agent: "claude-laptop", Source: identity.SourceSession, SessionID: "abc"}: "claude-laptop.abc",
		&long: strings.Repeat("a", 55) + ".sess-end",
	} {
		if got := SessionName(*id); got != want || len(got) > 64 {
			t.Errorf("SessionName(%s) = %q, want %q", id.Principal(), got, want)
		}
	}
}

// TestKubernetesLoginNeedsTheStore: a store must declare Kubernetes
// passthrough to take it, so a store that checks agents only by token
// exchange (Infisical) is refused at start-up instead of failing every use.
func TestKubernetesLoginNeedsTheStore(t *testing.T) {
	inf := &fedStore{Adapter: memstore.New("inf"), methods: []string{stores.FederationInfisical}}
	bao := &fedStore{Adapter: memstore.New("bao"), methods: []string{stores.LoginKubernetes, stores.FederationJWT}}
	adapter := func(n string) (stores.Adapter, bool) {
		switch n {
		case "inf":
			return inf, true
		case "bao":
			return bao, true
		}
		return nil, false
	}
	if _, err := New(Options{Login: map[string]string{"inf": "kubernetes role:x"}, Adapter: adapter}); err == nil ||
		!strings.Contains(err.Error(), "does not take method kubernetes") {
		t.Fatalf("kubernetes on a store without passthrough: %v", err)
	}
	if _, err := New(Options{Login: map[string]string{"bao": "kubernetes role:x"}, Adapter: adapter}); err != nil {
		t.Fatal(err)
	}
}
