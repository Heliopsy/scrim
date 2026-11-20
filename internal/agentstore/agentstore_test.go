// SPDX-License-Identifier: AGPL-3.0-only

package agentstore

import (
	"context"
	"errors"
	"strings"
	"testing"

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
