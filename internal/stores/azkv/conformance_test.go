// SPDX-License-Identifier: AGPL-3.0-only

package azkv

import (
	"context"
	"strings"
	"testing"

	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores"
	"github.com/heliopsy/scrim/internal/stores/storetest"
)

// literal resolves every reference to its own text, as a literal
// credential in configuration would.
func literal(_ context.Context, ref config.SecretRef) (secret.Value, error) {
	return secret.FromString(string(ref)), nil
}

// baseOptions configures client-secret authentication against f.
func (f *fake) baseOptions() map[string]any {
	return map[string]any{
		"vault-url":      f.srv.URL,
		"auth":           map[string]any{"method": "client-secret"},
		"tenant-id":      f.tenant,
		"client-id":      f.clientID,
		"client-secret":  f.clientSecret,
		"authority-host": f.srv.URL,
		"tls":            map[string]any{"ca-file": f.caFile()},
		"watch":          map[string]any{"interval": "100ms", "max-backoff": "400ms"},
	}
}

func (f *fake) adapter(t testing.TB, name string, extra map[string]any) *Adapter {
	t.Helper()
	opts := f.baseOptions()
	for k, v := range extra {
		if v == nil {
			delete(opts, k)
			continue
		}
		opts[k] = v
	}
	a, err := New(t.Context(), stores.Instance{Name: name, Kind: Kind, Options: opts, Resolve: literal})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = a.Close() })
	return a.(*Adapter)
}

func nameOf(path string) string { return strings.ReplaceAll(path, "/", defaultPathSep) }

func TestConformance(t *testing.T) {
	for _, format := range []string{formatRaw, formatJSON} {
		t.Run(format, func(t *testing.T) {
			storetest.Run(t, func(tb storetest.TB) storetest.Harness {
				tt := tb.(*testing.T)
				f := newFake(tt)
				a := f.adapter(tt, "kv", map[string]any{"format": format, "write-only-paths": []any{"wo/inbox"}})
				h := storetest.Harness{
					Adapter:         a,
					VersionSelector: true,
					Labels:          true,
					WriteOnlyPrefix: "wo/inbox",
					Delete:          func(_ storetest.TB, ref stores.Ref) { f.remove(nameOf(ref.Path)) },
					Outage: func(storetest.TB) func() {
						f.setDown(true)
						return func() { f.setDown(false) }
					},
					Reject: func(storetest.TB) stores.Ref {
						f.mu.Lock()
						f.denyWrite = "denied"
						f.mu.Unlock()
						return stores.Ref{Scheme: "kv", Path: "denied/secret"}
					},
				}
				if format == formatRaw {
					h.SingleField = Field
				}
				return h
			})
		})
	}
}
