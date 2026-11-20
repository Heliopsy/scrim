// SPDX-License-Identifier: AGPL-3.0-only

package audit_test

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/heliopsy/scrim/internal/audit"
	"github.com/heliopsy/scrim/internal/secret"
)

func TestFanout(t *testing.T) {
	ok := &audit.Memory{SinkName: "db"}
	slow := &audit.Memory{SinkName: "kafka", Fail: errors.New("unreachable")}
	var dropped int
	f := audit.Fanout{
		Targets: []*audit.Target{{Sink: ok}, {Sink: slow, Policy: audit.Drop}},
		OnDrop:  func(_ string, n int) { dropped += n },
	}
	batch := []audit.Entry{{Action: "decision"}, {Action: "grant.created"}}
	if err := f.Write(context.Background(), batch); err != nil {
		t.Fatalf("a dropping sink must not fail the write: %v", err)
	}
	if len(ok.Entries()) != 2 || f.Targets[1].Dropped() != 2 || dropped != 2 {
		t.Fatalf("delivered %d, dropped %d/%d", len(ok.Entries()), f.Targets[1].Dropped(), dropped)
	}

	blocking := audit.Fanout{Targets: []*audit.Target{{Sink: ok}, {Sink: slow, Policy: audit.Block}}}
	if err := blocking.Write(context.Background(), batch); !errors.Is(err, audit.ErrNotAudited) {
		t.Fatalf("a failing blocking sink must refuse: %v", err)
	}
}

// The entry type has no field that can carry a secret.Value.
func TestEntryHasNoValueField(t *testing.T) {
	assertNoSecretField(t, reflect.TypeFor[audit.Entry](), "Entry")
}

func assertNoSecretField(t *testing.T, typ reflect.Type, path string) {
	t.Helper()
	secretType := reflect.TypeFor[secret.Value]()
	switch typ.Kind() {
	case reflect.Struct:
		if typ == secretType {
			t.Fatalf("%s is a secret.Value", path)
		}
		for i := range typ.NumField() {
			f := typ.Field(i)
			assertNoSecretField(t, f.Type, path+"."+f.Name)
		}
	case reflect.Pointer, reflect.Slice, reflect.Array, reflect.Map:
		assertNoSecretField(t, typ.Elem(), path+"[]")
	}
}
