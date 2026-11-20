// SPDX-License-Identifier: AGPL-3.0-only

package stores_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores"
	"github.com/heliopsy/scrim/internal/stores/memstore"
)

func TestParseRef(t *testing.T) {
	cases := []struct {
		in        string
		scheme    string
		path      string
		field     string
		selectors string
		canonical string
	}{
		{"bao://kv/agents/github#token", "bao", "kv/agents/github", "token", "", ""},
		{"aws-sm://agents/github?stage=AWSPREVIOUS", "aws-sm", "agents/github", "", "stage=AWSPREVIOUS", ""},
		{"vault-eu:///kv/x/?version=3&a=b#f", "vault-eu", "kv/x", "f", "a=b&version=3", "vault-eu://kv/x?a=b&version=3#f"},
		{"inf://proj/prod/DB_PASSWORD", "inf", "proj/prod/DB_PASSWORD", "", "", ""},
	}
	for _, c := range cases {
		r, err := stores.ParseRef(c.in)
		if err != nil {
			t.Fatalf("%s: %v", c.in, err)
		}
		if r.Scheme != c.scheme || r.Path != c.path || r.Field != c.field || r.Selectors != c.selectors {
			t.Errorf("%s parsed as %+v", c.in, r)
		}
		want := c.canonical
		if want == "" {
			want = c.in
		}
		if r.String() != want {
			t.Errorf("String() = %s, want %s", r, want)
		}
		back, err := stores.ParseRef(r.String())
		if err != nil || back != r {
			t.Errorf("round trip %s: %+v %v", r, back, err)
		}
	}
	if r := stores.MustParseRef("aws-sm://a?stage=X"); r.Selector("stage") != "X" {
		t.Error("Selector")
	}
}

func TestParseRefRejects(t *testing.T) {
	for _, in := range []string{
		"", "kv/agents", "BAO://x", "bao://", "bao:///", "bao://x#", "bao://a//b",
		"bao://x?stage", "bao://x?a=1&a=2", "1bao://x", "bao_x://x",
	} {
		_, err := stores.ParseRef(in)
		if !errors.Is(err, stores.ErrInvalidRef) {
			t.Errorf("ParseRef(%q) = %v, want ErrInvalidRef", in, err)
		}
	}
	// A value pasted where a reference belongs is not echoed back.
	pasted := "ghp_" + strings.Repeat("Ab3", 12)
	if _, err := stores.ParseRef(pasted); err == nil || strings.Contains(err.Error(), pasted) {
		t.Errorf("error echoes the input: %v", err)
	}
}

func TestCapabilities(t *testing.T) {
	c := stores.CapRead | stores.CapList
	if !c.Has(stores.CapRead) || c.Has(stores.CapWrite) || c.Has(stores.CapRead|stores.CapWrite) {
		t.Fatal("Has")
	}
	if c.String() != "read,list" || stores.Capabilities(0).String() != "none" {
		t.Fatalf("String = %s", c)
	}
}

func TestErrorMessage(t *testing.T) {
	cause := errors.New("upstream said: body was hunter-value")
	err := stores.NewError("bao", stores.OpWrite, stores.MustParseRef("bao://kv/a"), stores.ErrPermission, cause)
	if got := err.Error(); got != "store bao: write bao://kv/a: permission denied by store" {
		t.Fatalf("Error() = %q", got)
	}
	if !errors.Is(err, stores.ErrPermission) || !errors.Is(err, cause) {
		t.Fatal("Unwrap")
	}
}

func TestRegistry(t *testing.T) {
	r := stores.NewRegistry()
	f := func(_ context.Context, inst stores.Instance) (stores.Adapter, error) {
		return memstore.New(inst.Name), nil
	}
	if err := r.Register("memory", f); err != nil {
		t.Fatal(err)
	}
	if r.Register("memory", f) == nil || r.Register("Bad Kind", f) == nil {
		t.Fatal("duplicate or invalid kind accepted")
	}
	if _, err := r.Open(context.Background(), stores.Instance{Name: "x", Kind: "nope"}); !errors.Is(err, stores.ErrUnknownKind) {
		t.Fatalf("Open unknown kind: %v", err)
	}
	if got := r.Kinds(); len(got) != 1 || got[0] != "memory" {
		t.Fatalf("Kinds = %v", got)
	}
}

func TestSet(t *testing.T) {
	ctx := context.Background()
	s := stores.NewSet()
	rw := memstore.New("bao")
	ro := memstore.New("env", memstore.WithCapabilities(stores.CapRead))
	if err := s.Add(rw, "openbao"); err != nil {
		t.Fatal(err)
	}
	if err := s.Add(ro); err != nil {
		t.Fatal(err)
	}
	if err := s.Add(memstore.New("other"), "bao"); err == nil {
		t.Fatal("duplicate scheme accepted")
	}
	v := secret.FromString("runtime-generated-value")
	if _, err := s.Write(ctx, stores.MustParseRef("openbao://kv/a"), map[string]secret.Value{"value": v}, stores.WriteOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Read(ctx, stores.MustParseRef("bao://kv/a#value")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Write(ctx, stores.MustParseRef("env://X"), map[string]secret.Value{"value": v}, stores.WriteOptions{}); !errors.Is(err, stores.ErrUnsupported) {
		t.Fatalf("write to read-only: %v", err)
	}
	if _, err := s.Read(ctx, stores.MustParseRef("xyz://foo")); !errors.Is(err, stores.ErrUnknownStore) {
		t.Fatalf("unknown scheme: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
}
