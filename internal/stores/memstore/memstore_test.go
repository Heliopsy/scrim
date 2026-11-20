// SPDX-License-Identifier: AGPL-3.0-only

package memstore_test

import (
	"context"
	"testing"

	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores"
	"github.com/heliopsy/scrim/internal/stores/memstore"
	"github.com/heliopsy/scrim/internal/stores/storetest"
)

func TestConformance(t *testing.T) {
	storetest.Run(t, func(storetest.TB) storetest.Harness {
		s := memstore.New("mem")
		return storetest.Harness{
			Adapter: s,
			Outage: func(storetest.TB) func() {
				s.SetDown(true)
				return func() { s.SetDown(false) }
			},
		}
	})
}

// A read-only source (env://, file://) declares read only and is seeded out
// of band.
func TestConformanceReadOnly(t *testing.T) {
	storetest.Run(t, func(storetest.TB) storetest.Harness {
		s := memstore.New("env", memstore.WithCapabilities(stores.CapRead))
		return storetest.Harness{
			Adapter: s,
			Seed: func(_ storetest.TB, ref stores.Ref, fields map[string]secret.Value) {
				s.Seed(ref, fields)
			},
		}
	})
}

func TestRegisteredInDefault(t *testing.T) {
	a, err := stores.DefaultRegistry.Open(context.Background(), stores.Instance{Name: "scratch", Kind: memstore.Kind})
	if err != nil {
		t.Fatal(err)
	}
	if a.Name() != "scratch" {
		t.Fatalf("name = %s", a.Name())
	}
}

func TestCloseWipes(t *testing.T) {
	s := memstore.New("mem")
	v := secret.FromString("generated-at-runtime")
	ref := stores.MustParseRef("mem://a/b")
	if _, err := s.Write(context.Background(), ref, map[string]secret.Value{"value": v}, stores.WriteOptions{}); err != nil {
		t.Fatal(err)
	}
	got, err := s.Read(context.Background(), ref)
	if err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	if v.Wiped() {
		t.Fatal("Close wiped the caller's value")
	}
	if got.Fields["value"].Wiped() {
		t.Fatal("Close wiped a value already handed to a caller")
	}
	if _, err := s.Read(context.Background(), ref); err == nil {
		t.Fatal("Read after Close succeeded")
	}
}
