// SPDX-License-Identifier: AGPL-3.0-only

package gcpsm

import (
	"context"
	"errors"
	"maps"
	"testing"

	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores"
	"github.com/heliopsy/scrim/internal/stores/storetest"
)

// resolver resolves secret references from a map, as the stores collection
// would from env:, file: or another store.
func resolver(m map[string]string) func(context.Context, config.SecretRef) (secret.Value, error) {
	return func(_ context.Context, ref config.SecretRef) (secret.Value, error) {
		v, ok := m[string(ref)]
		if !ok {
			return secret.Value{}, errors.New("unknown reference")
		}
		return secret.FromString(v), nil
	}
}

// adapterFor builds an adapter against the fake with an access token it
// accepts, plus extra options.
func adapterFor(t testing.TB, f *fake, extra map[string]any) *Adapter {
	t.Helper()
	opts := map[string]any{
		"project":     f.project,
		"endpoint":    f.srv.URL,
		"auth.method": methodAccessToken,
		"token":       "env:GSM_TOKEN",
	}
	maps.Copy(opts, extra)
	a, err := newAdapter(stores.Instance{
		Name: "gsm", Kind: Kind, Options: opts,
		Resolve: resolver(map[string]string{"env:GSM_TOKEN": f.token()}),
	}, nil, f.srv.URL+"/iam")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = a.Close() })
	return a
}

func plain(t testing.TB, v secret.Value) string {
	t.Helper()
	var s string
	_ = v.Expose(func(b []byte) error { s = string(b); return nil })
	return s
}

func TestConformance(t *testing.T) {
	for _, tc := range []struct {
		name   string
		extra  map[string]any
		single string
	}{
		{"Raw", nil, Field},
		{"JSON", map[string]any{"format": "json"}, ""},
		{"Regional", map[string]any{"location": "europe-west4"}, Field},
		{"Underscores", map[string]any{"path-separator": "__", "format": "json"}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake(t)
			storetest.Run(t, func(tb storetest.TB) storetest.Harness {
				extra := map[string]any{
					"watch.interval":    "50ms",
					"watch.max-backoff": "200ms",
					"write-only-paths":  []string{"inbox"},
				}
				maps.Copy(extra, tc.extra)
				a := adapterFor(tb.(testing.TB), f, extra)
				parent := ""
				if loc, ok := tc.extra["location"].(string); ok {
					parent = "projects/" + f.project + "/locations/" + loc
				}
				return storetest.Harness{
					Adapter:         a,
					Prefix:          "conf-" + randHex(4),
					SingleField:     tc.single,
					VersionSelector: true,
					Labels:          true,
					WriteOnlyPrefix: "inbox",
					Reject: func(storetest.TB) stores.Ref {
						return stores.Ref{Scheme: "gsm", Path: "denied/" + randHex(4)}
					},
					Delete: func(tb storetest.TB, ref stores.Ref) {
						id, err := a.names.Name(ref.Path)
						if err != nil {
							tb.Fatalf("name: %v", err)
						}
						f.remove(parent, id)
					},
					Outage: func(storetest.TB) func() {
						f.setDown(true)
						return func() { f.setDown(false) }
					},
				}
			})
		})
	}
}
