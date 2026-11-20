// SPDX-License-Identifier: AGPL-3.0-only

package stores_test

import (
	"errors"
	"testing"

	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores"
	"github.com/heliopsy/scrim/internal/stores/memstore"
)

var _ config.StoreResolver = (*stores.Set)(nil)

func TestSetResolveSecret(t *testing.T) {
	m := memstore.New("bao")
	m.Seed(stores.MustParseRef("bao://kv/one"), map[string]secret.Value{"token": secret.FromString("t-1")})
	m.Seed(stores.MustParseRef("bao://kv/two"), map[string]secret.Value{"a": secret.FromString("x"), "b": secret.FromString("y")})
	set := stores.NewSet()
	if err := set.Add(m); err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	for _, ref := range []string{"bao://kv/one", "bao://kv/one#token"} {
		v, err := set.ResolveSecret(ctx, ref)
		if err != nil {
			t.Fatalf("%s: %v", ref, err)
		}
		_ = v.Expose(func(b []byte) error {
			if string(b) != "t-1" {
				t.Errorf("%s: wrong value", ref)
			}
			return nil
		})
		v.Wipe()
	}
	if _, err := set.ResolveSecret(ctx, "bao://kv/two"); !errors.Is(err, stores.ErrInvalidRef) {
		t.Errorf("multi-field without a field: %v", err)
	}
	if _, err := set.ResolveSecret(ctx, "xyz://kv/one"); !errors.Is(err, stores.ErrUnknownStore) {
		t.Errorf("unknown scheme: %v", err)
	}
	if _, err := set.ResolveSecret(ctx, "bao://kv/missing#x"); !errors.Is(err, stores.ErrNotFound) {
		t.Errorf("missing: %v", err)
	}
}
