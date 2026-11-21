// SPDX-License-Identifier: AGPL-3.0-only

package env

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores"
	"github.com/heliopsy/scrim/internal/stores/storetest"
)

// fakeEnv is a concurrency-safe environment for tests.
type fakeEnv struct {
	mu sync.RWMutex
	m  map[string]string
}

func newFakeEnv() *fakeEnv { return &fakeEnv{m: map[string]string{}} }

func (f *fakeEnv) LookupEnv(name string) (string, bool) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	v, ok := f.m[name]
	return v, ok
}

func (f *fakeEnv) Environ() []string {
	f.mu.RLock()
	defer f.mu.RUnlock()
	out := make([]string, 0, len(f.m))
	for k, v := range f.m {
		out = append(out, k+"="+v)
	}
	return out
}

func (f *fakeEnv) set(name, v string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.m[name] = v
}

func plain(v secret.Value) string {
	var s string
	_ = v.Expose(func(b []byte) error { s = string(b); return nil })
	return s
}

func gen(t *testing.T) string {
	t.Helper()
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return "env_" + hex.EncodeToString(b)
}

func TestConformance(t *testing.T) {
	storetest.Run(t, func(storetest.TB) storetest.Harness {
		fe := newFakeEnv()
		return storetest.Harness{
			Adapter:     New("env", Config{}, WithEnvironment(fe)),
			SingleField: Field,
			Seed: func(t storetest.TB, ref stores.Ref, fields map[string]secret.Value) {
				fe.set(ref.Path, plain(fields[Field]))
			},
		}
	})
}

func TestConformanceWithPrefix(t *testing.T) {
	storetest.Run(t, func(storetest.TB) storetest.Harness {
		fe := newFakeEnv()
		return storetest.Harness{
			Adapter:     New("env", Config{Prefix: "SCRIM_T"}, WithEnvironment(fe)),
			Prefix:      "SCRIM_T/conformance",
			SingleField: Field,
			Seed: func(t storetest.TB, ref stores.Ref, fields map[string]secret.Value) {
				fe.set(ref.Path, plain(fields[Field]))
			},
		}
	})
}

func TestProcessEnvironment(t *testing.T) {
	v := gen(t)
	t.Setenv("SCRIM_TEST_ENV_SOURCE", v)
	a := New("env", Config{Prefix: "SCRIM_TEST_ENV_"})
	s, err := a.Read(t.Context(), stores.MustParseRef("env://SCRIM_TEST_ENV_SOURCE#value"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Wipe()
	if got, _ := s.Field(Field); plain(got) != v {
		t.Errorf("read the wrong value")
	}
	ms, err := a.List(t.Context(), stores.MustParseRef("env://SCRIM_TEST_ENV_*"))
	if err != nil || len(ms) != 1 || ms[0].Ref.Path != "SCRIM_TEST_ENV_SOURCE" {
		t.Errorf("List = %v, %v", ms, err)
	}
	// Outside the prefix: invisible even though set.
	t.Setenv("SCRIM_OTHER_VAR", gen(t))
	if _, err := a.Read(t.Context(), stores.MustParseRef("env://SCRIM_OTHER_VAR")); !errors.Is(err, stores.ErrNotFound) {
		t.Errorf("variable outside the prefix: %v, want not found", err)
	}
}

func TestAllowList(t *testing.T) {
	fe := newFakeEnv()
	for _, n := range []string{"GITHUB_TOKEN", "API_KEY_ONE", "API_KEY_TWO", "HOME_SECRET"} {
		fe.set(n, gen(t))
	}
	a := New("env", Config{Allow: []string{"GITHUB_TOKEN", "API_KEY_*"}}, WithEnvironment(fe))
	for name, want := range map[string]bool{"GITHUB_TOKEN": true, "API_KEY_ONE": true, "API_KEY_TWO": true, "HOME_SECRET": false} {
		s, err := a.Read(t.Context(), stores.Ref{Scheme: "env", Path: name})
		if want && err != nil {
			t.Errorf("Read %s: %v", name, err)
		}
		if !want && !errors.Is(err, stores.ErrNotFound) {
			t.Errorf("Read %s outside allow: %v, want not found", name, err)
		}
		s.Wipe()
	}
	ms, _ := a.List(t.Context(), stores.Ref{Scheme: "env", Path: "*"})
	if len(ms) != 3 {
		t.Errorf("List * returned %d entries, want 3", len(ms))
	}
}

// TestWriteToReadOnlySource is the spec scenario "Write to a read-only
// source": the call is refused with an error saying the env source is
// read-only, and nothing is stored.
func TestWriteToReadOnlySource(t *testing.T) {
	fe := newFakeEnv()
	set := stores.NewSet()
	if err := set.Add(New("env", Config{}, WithEnvironment(fe))); err != nil {
		t.Fatal(err)
	}
	ref := stores.MustParseRef("env://GENERATED_SECRET")
	v := gen(t)
	val := secret.FromString(v)
	for name, write := range map[string]func() error{
		"set": func() error {
			_, err := set.Write(t.Context(), ref, map[string]secret.Value{Field: val}, stores.WriteOptions{})
			return err
		},
		"adapter": func() error {
			_, err := set.Adapters()[0].Write(t.Context(), ref, map[string]secret.Value{Field: val}, stores.WriteOptions{})
			return err
		},
	} {
		err := write()
		if !errors.Is(err, stores.ErrUnsupported) {
			t.Fatalf("%s: Write = %v, want ErrUnsupported", name, err)
		}
		if strings.Contains(err.Error(), v) {
			t.Fatalf("%s: error contains the value", name)
		}
	}
	// The adapter's own refusal says why.
	_, err := set.Adapters()[0].Write(t.Context(), ref, map[string]secret.Value{Field: val}, stores.WriteOptions{})
	if !strings.Contains(err.Error(), "env source is read-only") {
		t.Errorf("error %q does not say the env source is read-only", err)
	}
	if _, ok := fe.LookupEnv("GENERATED_SECRET"); ok {
		t.Errorf("a refused write stored something")
	}
	if val.Wiped() {
		t.Errorf("a refused write wiped the caller's value")
	}
}

func TestRefusals(t *testing.T) {
	a := New("env", Config{}, WithEnvironment(newFakeEnv()))
	ctx := context.Background()
	if _, err := a.Read(ctx, stores.MustParseRef("env://X?version=2")); !errors.Is(err, stores.ErrInvalidRef) {
		t.Errorf("selector: %v", err)
	}
	if _, err := a.Read(ctx, stores.Ref{Scheme: "env", Path: "A=B"}); !errors.Is(err, stores.ErrInvalidRef) {
		t.Errorf("= in name: %v", err)
	}
	if _, err := a.Watch(ctx, stores.MustParseRef("env://X")); !errors.Is(err, stores.ErrUnsupported) {
		t.Errorf("watch: %v", err)
	}
}

func TestParseOptions(t *testing.T) {
	cfg, err := ParseOptions("env", map[string]any{"prefix": "APP_", "allow": "A, B_*"})
	if err != nil || cfg.Prefix != "APP_" || len(cfg.Allow) != 2 || cfg.Allow[1] != "B_*" {
		t.Fatalf("ParseOptions = %+v, %v", cfg, err)
	}
	_, err = ParseOptions("env", map[string]any{"prefx": "APP_"})
	if err == nil || !strings.Contains(err.Error(), "did you mean prefix") {
		t.Errorf("typo: %v", err)
	}
	if _, err := ParseOptions("env", map[string]any{"allow": []any{"["}}); err == nil {
		t.Errorf("malformed glob accepted")
	}
}

func TestRegistered(t *testing.T) {
	a, err := stores.DefaultRegistry.Open(t.Context(), stores.Instance{Name: "local-env", Kind: Kind, Options: map[string]any{"prefix": "SCRIM_"}})
	if err != nil {
		t.Fatal(err)
	}
	if a.Name() != "local-env" || a.Capabilities() != stores.CapRead|stores.CapList|stores.CapGlob {
		t.Errorf("registered adapter: %s %s", a.Name(), a.Capabilities())
	}
}

func TestNativeLabels(t *testing.T) {
	fe := newFakeEnv()
	fe.set("SCRIM_T_ONE", gen(t))
	a := New("env", Config{Prefix: "SCRIM_T"}, WithEnvironment(fe))
	s, err := a.Read(t.Context(), stores.Ref{Scheme: "env", Path: "SCRIM_T_ONE"})
	if err != nil {
		t.Fatal(err)
	}
	s.Wipe()
	ms, err := a.List(t.Context(), stores.Ref{Scheme: "env", Path: "SCRIM_T*"})
	if err != nil || len(ms) != 1 {
		t.Fatalf("List: %v %v", ms, err)
	}
	for _, l := range []map[string]string{s.Meta.Labels, ms[0].Labels} {
		if l["env.variable"] != "SCRIM_T_ONE" || l["env.prefix"] != "SCRIM_T" || len(l) != 2 {
			t.Errorf("labels = %v", l)
		}
	}
}
