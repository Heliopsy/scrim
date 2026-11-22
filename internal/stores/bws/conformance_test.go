// SPDX-License-Identifier: AGPL-3.0-only

package bws

import (
	"context"
	"strings"
	"testing"

	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores"
	"github.com/heliopsy/scrim/internal/stores/storetest"
)

// conformanceProject is the project the suite writes into; readOnlyProject
// is one the machine account may only read.
const (
	conformanceProject = "scrim-conformance"
	readOnlyProject    = "read-only"
)

func resolver(token string) func(context.Context, config.SecretRef) (secret.Value, error) {
	return func(context.Context, config.SecretRef) (secret.Value, error) { return secret.FromString(token), nil }
}

func newAdapter(t testing.TB, f *fakeBWS, extra map[string]any) *Adapter {
	t.Helper()
	opts := map[string]any{"server-url": f.srv.URL, "token": "env:BWS_ACCESS_TOKEN", "watch.interval": "50ms"}
	for k, v := range extra {
		opts[k] = v
	}
	a, err := New(t.Context(), stores.Instance{Name: "bws", Kind: Kind, Options: opts, Resolve: resolver(officialToken)})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return a.(*Adapter)
}

// TestConformance runs the shared suite against the fake (see fake_test.go
// for what it reproduces and where it falls short of the service).
func TestConformance(t *testing.T) {
	storetest.Run(t, func(tb storetest.TB) storetest.Harness {
		tt := tb.(*testing.T)
		f := newFake(tt)
		pid := f.addProject(conformanceProject, true)
		f.addProject(readOnlyProject, false)
		keyOf := func(ref stores.Ref) string {
			k, ok := strings.CutPrefix(ref.Path, conformanceProject+"/")
			if !ok {
				tb.Fatalf("seed outside the conformance project: %s", ref)
			}
			return k
		}
		return storetest.Harness{
			Adapter:     newAdapter(tt, f, nil),
			Prefix:      conformanceProject + "/" + newUUID()[:8],
			SingleField: FieldValue,
			Seed: func(_ storetest.TB, ref stores.Ref, fields map[string]secret.Value) {
				f.put(pid, keyOf(ref), fields[FieldValue])
			},
			Delete: func(_ storetest.TB, ref stores.Ref) { f.remove(pid, keyOf(ref)) },
			Outage: func(storetest.TB) func() {
				f.down.Store(true)
				return func() { f.down.Store(false) }
			},
			Reject: func(storetest.TB) stores.Ref {
				return stores.Ref{Scheme: "bws", Path: readOnlyProject + "/REJECTED"}
			},
			Unstorable: func(p string) bool { return storable(secret.FromString(p), maxValueLen, false) != "" },
		}
	})
}
