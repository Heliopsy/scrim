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

// Test kinds: one whose adapters check writes, one whose adapters cannot.
const (
	kindChecks   = "agentstore-test-checks"
	kindNoChecks = "agentstore-test-nochecks"
)

func init() { stores.DeclareAgentWriteCheck(kindChecks) }

// writeStore answers AgentCan for writes from a table of token -> writable
// prefix, and refuses reads it is not asked about.
type writeStore struct {
	stores.Adapter
	writable map[string]string
	ops      []stores.Op
}

func (f *writeStore) AgentCan(_ context.Context, c stores.AgentCredential, op stores.Op, ref stores.Ref) error {
	f.ops = append(f.ops, op)
	var key string
	_ = c.Token.Expose(func(b []byte) error { key = string(b); return nil })
	if key == "" {
		key = c.Role
	}
	if p, ok := f.writable[key]; ok && op == stores.OpWrite && strings.HasPrefix(ref.Path, p) {
		return nil
	}
	return stores.NewError(f.Name(), op, ref, stores.ErrPermission, errors.New("the agent's own identity may not write here"))
}

type writeEnv struct {
	checks, nochecks *writeStore
	c                *Checker
}

func newWriteEnv(t *testing.T, skip bool, refuse []string) writeEnv {
	t.Helper()
	e := writeEnv{
		checks:   &writeStore{Adapter: memstore.New("vw"), writable: map[string]string{"tok-A": "team-a/", "role-a": "team-a/"}},
		nochecks: &writeStore{Adapter: memstore.New("aws")},
	}
	set := stores.NewSet()
	for _, a := range []stores.Adapter{e.checks, e.nochecks, memstore.New("plain")} {
		if err := set.Add(a); err != nil {
			t.Fatal(err)
		}
	}
	c, err := New(Options{
		Login:       map[string]string{"vw": "kubernetes role:role-{service_account}"},
		Credentials: map[string]string{"vw/agent-a": "env:A", "vw/agent-b": "env:B", "aws/agent-a": "env:A"},
		Lookup:      set.Lookup,
		Resolve: func(_ context.Context, r config.SecretRef) (secret.Value, error) {
			v, _ := strings.CutPrefix(string(r), "env:")
			return secret.FromString("tok-" + v), nil
		},
		Kinds:           map[string]string{"vw": kindChecks, "aws": kindNoChecks, "plain": "memory"},
		SkipWriteChecks: skip, RefuseUncheckedWrites: refuse,
	})
	if err != nil {
		t.Fatal(err)
	}
	e.c = c
	return e
}

func peer(name string) identity.Identity {
	return identity.Identity{Agent: name, Source: identity.SourcePeer}
}

func TestCheckWrite(t *testing.T) {
	ctx := context.Background()
	e := newWriteEnv(t, false, nil)

	// A store that can check asks the agent's own identity, with OpWrite.
	got, err := e.c.CheckWrite(ctx, peer("agent-a"), nil, ref(t, "vw://team-a/db"))
	if err != nil || got != (WriteResult{Source: SourceStatic, Check: WriteChecked}) {
		t.Fatalf("agent-a, may write team-a: %+v %v", got, err)
	}
	if e.checks.ops[len(e.checks.ops)-1] != stores.OpWrite {
		t.Fatalf("asked %v, want write", e.checks.ops)
	}
	// Its identity may not write here although scrim's rules allowed it.
	got, err = e.c.CheckWrite(ctx, peer("agent-b"), nil, ref(t, "vw://team-a/db"))
	if !errors.Is(err, stores.ErrPermission) || got.Check != WriteChecked {
		t.Fatalf("agent-b, read-only on team-a: %+v %v", got, err)
	}
	if strings.Contains(err.Error(), "tok-B") {
		t.Fatalf("refusal quotes the agent's credential: %v", err)
	}
	// An agent with no identity for a store that requires one is refused.
	if got, err = e.c.CheckWrite(ctx, peer("nobody"), nil, ref(t, "vw://team-a/db")); !errors.Is(err, ErrNoIdentity) || got.Source != SourceNone {
		t.Fatalf("nobody: %+v %v", got, err)
	}
	// Kubernetes passthrough with the pod's token.
	if got, err = e.c.CheckWrite(ctx, pod("agents", "a"), []byte("eyJ.a.b"), ref(t, "vw://team-a/db")); err != nil || got.Source != SourceKubernetes {
		t.Fatalf("pod agents/a: %+v %v", got, err)
	}
	// A store that cannot check writes with scrim's identity, as before,
	// without asking the store.
	before := len(e.nochecks.ops)
	for _, who := range []string{"agent-a", "nobody"} {
		got, err = e.c.CheckWrite(ctx, peer(who), nil, ref(t, "aws://prod/db"))
		if err != nil || got.Check != WriteUnchecked {
			t.Fatalf("%s on a store that cannot check: %+v %v", who, got, err)
		}
	}
	if len(e.nochecks.ops) != before {
		t.Fatal("a store that cannot check a write was asked")
	}
	// A store without per-agent identity is untouched.
	if got, err = e.c.CheckWrite(ctx, peer("nobody"), nil, ref(t, "plain://x")); err != nil || got != (WriteResult{Source: SourceShared, Check: WriteShared}) {
		t.Fatalf("plain: %+v %v", got, err)
	}
}

func TestCheckWriteSkipped(t *testing.T) {
	e := newWriteEnv(t, true, nil)
	got, err := e.c.CheckWrite(context.Background(), peer("agent-b"), nil, ref(t, "vw://team-a/db"))
	if err != nil || got.Check != WriteSkipped || len(e.checks.ops) != 0 {
		t.Fatalf("skipped: %+v %v (asked %v)", got, err, e.checks.ops)
	}
	if !strings.Contains(e.c.WritePolicy("vw"), SkipWriteChecks.Name()) {
		t.Fatalf("write policy %q does not name the setting", e.c.WritePolicy("vw"))
	}
}

func TestRefuseUncheckedWrites(t *testing.T) {
	ctx := context.Background()
	for _, refuse := range [][]string{{"aws"}, {"*"}} {
		e := newWriteEnv(t, false, refuse)
		got, err := e.c.CheckWrite(ctx, peer("agent-a"), nil, ref(t, "aws://prod/db"))
		if !errors.Is(err, ErrUncheckedWrite) || got.Check != WriteUnchecked {
			t.Fatalf("%v: %+v %v", refuse, got, err)
		}
		// Stores that can check, and stores without per-agent identity,
		// are not affected.
		if _, err := e.c.CheckWrite(ctx, peer("agent-a"), nil, ref(t, "vw://team-a/db")); err != nil {
			t.Fatalf("%v: vw: %v", refuse, err)
		}
		if _, err := e.c.CheckWrite(ctx, peer("agent-a"), nil, ref(t, "plain://x")); err != nil {
			t.Fatalf("%v: plain: %v", refuse, err)
		}
		if !strings.Contains(e.c.WritePolicy("aws"), "refused") {
			t.Fatalf("%v: write policy %q", refuse, e.c.WritePolicy("aws"))
		}
	}
}

func TestWritePolicy(t *testing.T) {
	e := newWriteEnv(t, false, nil)
	for store, want := range map[string]string{
		"vw":    "checked with the agent's own identity",
		"aws":   "not checked",
		"plain": "no per-agent identity",
	} {
		if got := e.c.WritePolicy(store); !strings.Contains(got, want) {
			t.Errorf("%s: %q, want %q", store, got, want)
		}
	}
	var nilChecker *Checker
	if got, err := nilChecker.CheckWrite(context.Background(), peer("a"), nil, ref(t, "vw://x")); err != nil || got.Check != WriteShared {
		t.Fatalf("nil checker: %+v %v", got, err)
	}
}
