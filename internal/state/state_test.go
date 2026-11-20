// SPDX-License-Identifier: AGPL-3.0-only

package state_test

import (
	"reflect"
	"testing"
	"time"

	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/state"
)

// No state type can carry a secret value (specs/state-and-scaling "No
// secret value in any backend").
func TestTypesHoldNoValues(t *testing.T) {
	for _, typ := range []reflect.Type{
		reflect.TypeFor[state.Approval](), reflect.TypeFor[state.Grant](), reflect.TypeFor[state.Session](),
		reflect.TypeFor[state.Event](), reflect.TypeFor[state.Change](),
	} {
		walk(t, typ, typ.Name())
	}
}

func walk(t *testing.T, typ reflect.Type, path string) {
	t.Helper()
	if typ == reflect.TypeFor[secret.Value]() {
		t.Fatalf("%s is a secret.Value", path)
	}
	switch typ.Kind() {
	case reflect.Struct:
		for i := range typ.NumField() {
			walk(t, typ.Field(i).Type, path+"."+typ.Field(i).Name)
		}
	case reflect.Pointer, reflect.Slice, reflect.Array, reflect.Map:
		walk(t, typ.Elem(), path+"[]")
	}
}

func TestGrantUsable(t *testing.T) {
	now := time.Now()
	g := state.Grant{ExpiresAt: now.Add(time.Minute), MaxUses: 1}
	if !g.Usable(now) {
		t.Fatal("fresh grant unusable")
	}
	if g.Usable(now.Add(time.Minute)) {
		t.Fatal("usable at expiry")
	}
	g.Uses = 1
	if g.Usable(now) {
		t.Fatal("usable after its last use")
	}
	g.Uses, g.RevokedAt = 0, now
	if g.Usable(now) {
		t.Fatal("usable after revoke")
	}
}

func TestNewID(t *testing.T) {
	a, b := state.NewID(), state.NewID()
	if len(a) != 32 || a == b {
		t.Fatalf("NewID: %s %s", a, b)
	}
}
