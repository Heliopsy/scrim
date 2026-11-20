// SPDX-License-Identifier: AGPL-3.0-only

// Package storetest is the store adapter conformance suite
// (specs/secret-stores, "Adapter conformance suite"). Every adapter's tests
// call [Run]:
//
//	func TestConformance(t *testing.T) {
//		storetest.Run(t, func(t storetest.TB) storetest.Harness {
//			return storetest.Harness{Adapter: newAdapterAgainstEmulator(t)}
//		})
//	}
//
// The suite generates every value at runtime and checks behaviour through
// the [stores.Adapter] interface only: declared capabilities, read with and
// without a field selector, list, write, watch, outage, and that no error or
// metadata ever contains a value.
package storetest

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores"
)

// TB is the subset of testing.TB the cases use, so the suite can be run
// against a recorder to prove it catches a broken adapter.
type TB interface {
	Helper()
	Errorf(format string, args ...any)
	Fatalf(format string, args ...any)
	Cleanup(func())
	Context() context.Context
}

// Harness is one fresh adapter under test.
type Harness struct {
	// Adapter is the adapter under test. The suite closes it.
	Adapter stores.Adapter
	// Scheme is the scheme references use; default Adapter.Name().
	Scheme string
	// Prefix is the path under which the suite may create secrets, unique
	// per run against a shared store; default "scrim-conformance/<random>".
	Prefix string
	// Seed puts a secret into the store out of band. Required when the
	// adapter does not declare stores.CapWrite; otherwise Write is used.
	Seed func(t TB, ref stores.Ref, fields map[string]secret.Value)
	// Outage, if set, makes the store unreachable until restore is called.
	Outage func(t TB) (restore func())
	// WatchTimeout bounds how long a watch may take to report a change;
	// default 10s.
	WatchTimeout time.Duration
}

// Factory returns a fresh harness for each case.
type Factory func(t TB) Harness

// Case is one conformance check.
type Case struct {
	Name string
	Run  func(t TB, h *Harness)
}

// Run runs every case as a subtest.
func Run(t *testing.T, f Factory) {
	t.Helper()
	for _, c := range Cases() {
		t.Run(c.Name, func(t *testing.T) {
			h := Prepare(t, f)
			c.Run(t, h)
		})
	}
}

// Prepare builds a harness with defaults filled in and registers Close.
func Prepare(t TB, f Factory) *Harness {
	t.Helper()
	h := f(t)
	if h.Adapter == nil {
		t.Fatalf("storetest: harness has no adapter")
	}
	if h.Scheme == "" {
		h.Scheme = h.Adapter.Name()
	}
	if h.Prefix == "" {
		h.Prefix = "scrim-conformance/" + randHex(t, 6)
	}
	if h.WatchTimeout == 0 {
		h.WatchTimeout = 10 * time.Second
	}
	t.Cleanup(func() { _ = h.Adapter.Close() })
	return &h
}

// Cases returns the conformance cases in order.
func Cases() []Case {
	return []Case{
		{"DeclaresRead", declaresRead},
		{"UnsupportedRefused", unsupportedRefused},
		{"ReadSeeded", readSeeded},
		{"ReadField", readField},
		{"ReadMissing", readMissing},
		{"List", list},
		{"WriteRoundTrip", writeRoundTrip},
		{"WriteCreateOnly", writeCreateOnly},
		{"Watch", watch},
		{"Health", health},
		{"Outage", outage},
	}
}

// ref builds a reference under the harness prefix.
func (h *Harness) ref(name string) stores.Ref {
	if name == "" {
		return stores.Ref{Scheme: h.Scheme, Path: h.Prefix}
	}
	return stores.Ref{Scheme: h.Scheme, Path: h.Prefix + "/" + name}
}

func (h *Harness) seed(t TB, ref stores.Ref, fields map[string]secret.Value) {
	t.Helper()
	if h.Seed != nil {
		h.Seed(t, ref, fields)
		return
	}
	if !h.Adapter.Capabilities().Has(stores.CapWrite) {
		t.Fatalf("storetest: adapter %s is read-only and the harness has no Seed", h.Adapter.Name())
	}
	if _, err := h.Adapter.Write(t.Context(), ref, fields, stores.WriteOptions{}); err != nil {
		t.Fatalf("seed %s: %v", ref, err)
	}
}

// values generates a field map and returns the plain values for leak checks.
func values(t TB, names ...string) (map[string]secret.Value, []string) {
	fields := map[string]secret.Value{}
	var plain []string
	for _, n := range names {
		p := "conf_" + randHex(t, 16)
		fields[n] = secret.FromString(p)
		plain = append(plain, p)
	}
	return fields, plain
}

func randHex(t TB, n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return hex.EncodeToString(b)
}

func expose(t TB, v secret.Value) string {
	t.Helper()
	var s string
	if err := v.Expose(func(b []byte) error { s = string(b); return nil }); err != nil {
		t.Fatalf("expose: %v", err)
	}
	return s
}

// noLeak fails if err's message, or its %+v form, contains any value.
func noLeak(t TB, what string, x any, plain []string) {
	t.Helper()
	if x == nil {
		return
	}
	var texts []string
	if err, ok := x.(error); ok {
		texts = append(texts, err.Error())
	}
	texts = append(texts, fmt.Sprintf("%+v", x), fmt.Sprintf("%#v", x))
	for _, text := range texts {
		for _, p := range plain {
			if strings.Contains(text, p) {
				t.Errorf("%s contains a secret value: %q", what, text)
				return
			}
		}
	}
}

func wantKind(t TB, err, kind error, what string) {
	t.Helper()
	if !errors.Is(err, kind) {
		t.Errorf("%s: got error %v, want one wrapping %q", what, err, kind)
	}
}

func declaresRead(t TB, h *Harness) {
	if !h.Adapter.Capabilities().Has(stores.CapRead) {
		t.Errorf("adapter %s does not declare read; every store must", h.Adapter.Name())
	}
}

func unsupportedRefused(t TB, h *Harness) {
	caps := h.Adapter.Capabilities()
	ctx := t.Context()
	ref := h.ref("unsupported")
	fields, plain := values(t, "value")
	if !caps.Has(stores.CapWrite) {
		_, err := h.Adapter.Write(ctx, ref, fields, stores.WriteOptions{})
		wantKind(t, err, stores.ErrUnsupported, "Write on a store without write")
		noLeak(t, "unsupported write error", err, plain)
	}
	if !caps.Has(stores.CapList) {
		_, err := h.Adapter.List(ctx, h.ref(""))
		wantKind(t, err, stores.ErrUnsupported, "List on a store without list")
	}
	if !caps.Has(stores.CapWatch) {
		_, err := h.Adapter.Watch(ctx, h.ref(""))
		wantKind(t, err, stores.ErrUnsupported, "Watch on a store without watch")
	}
}

func readSeeded(t TB, h *Harness) {
	ref := h.ref("multi")
	fields, plain := values(t, "username", "password")
	h.seed(t, ref, fields)
	got, err := h.Adapter.Read(t.Context(), ref)
	if err != nil {
		t.Fatalf("Read %s: %v", ref, err)
	}
	defer got.Wipe()
	for i, name := range []string{"username", "password"} {
		v, ok := got.Field(name)
		if !ok {
			t.Errorf("Read %s: field %s missing", ref, name)
			continue
		}
		if expose(t, v) != plain[i] {
			t.Errorf("Read %s: field %s has the wrong value", ref, name)
		}
	}
	noLeak(t, "secret metadata", got.Meta, plain)
	noLeak(t, "secret", got, plain)
}

func readField(t TB, h *Harness) {
	ref := h.ref("fields")
	fields, plain := values(t, "token", "other")
	h.seed(t, ref, fields)
	got, err := h.Adapter.Read(t.Context(), ref.WithField("token"))
	if err != nil {
		t.Fatalf("Read with field: %v", err)
	}
	defer got.Wipe()
	if len(got.Fields) != 1 {
		t.Errorf("Read with field returned %d fields, want 1", len(got.Fields))
	}
	if v, ok := got.Field("token"); !ok || expose(t, v) != plain[0] {
		t.Errorf("Read with field: wrong or missing token")
	}
	_, err = h.Adapter.Read(t.Context(), ref.WithField("absent"))
	wantKind(t, err, stores.ErrNotFound, "Read of a missing field")
	noLeak(t, "missing field error", err, plain)
}

func readMissing(t TB, h *Harness) {
	_, err := h.Adapter.Read(t.Context(), h.ref("does-not-exist"))
	wantKind(t, err, stores.ErrNotFound, "Read of a missing secret")
}

func list(t TB, h *Harness) {
	if !h.Adapter.Capabilities().Has(stores.CapList) {
		return
	}
	var all []string
	want := []stores.Ref{h.ref("list/a"), h.ref("list/b")}
	for _, r := range want {
		fields, plain := values(t, "value")
		all = append(all, plain...)
		h.seed(t, r, fields)
	}
	got, err := h.Adapter.List(t.Context(), h.ref("list"))
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	var paths []string
	for _, m := range got {
		noLeak(t, "list metadata", m, all)
		paths = append(paths, m.Ref.Path)
		if m.Ref.Scheme != h.Scheme {
			t.Errorf("List: ref %s has scheme %q, want %q", m.Ref, m.Ref.Scheme, h.Scheme)
		}
	}
	for _, r := range want {
		if !slices.Contains(paths, r.Path) {
			t.Errorf("List: %s missing from %v", r, paths)
		}
	}
}

func writeRoundTrip(t TB, h *Harness) {
	if !h.Adapter.Capabilities().Has(stores.CapWrite) {
		return
	}
	ctx := t.Context()
	ref := h.ref("written")
	first, p1 := values(t, "value")
	m1, err := h.Adapter.Write(ctx, ref, first, stores.WriteOptions{})
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	noLeak(t, "write metadata", m1, p1)
	second, p2 := values(t, "value")
	m2, err := h.Adapter.Write(ctx, ref, second, stores.WriteOptions{})
	if err != nil {
		t.Fatalf("second Write: %v", err)
	}
	if m1.Version != "" && m1.Version == m2.Version {
		t.Errorf("a new write kept version %q", m1.Version)
	}
	got, err := h.Adapter.Read(ctx, ref.WithField("value"))
	if err != nil {
		t.Fatalf("Read after Write: %v", err)
	}
	defer got.Wipe()
	if v, _ := got.Field("value"); expose(t, v) != p2[0] {
		t.Errorf("Read after Write did not return the latest version")
	}
	// The caller keeps ownership: the adapter must not wipe what it was given.
	if second["value"].Wiped() {
		t.Errorf("Write wiped the caller's value")
	}
}

func writeCreateOnly(t TB, h *Harness) {
	if !h.Adapter.Capabilities().Has(stores.CapWrite) {
		return
	}
	ref := h.ref("create-only")
	fields, plain := values(t, "value")
	if _, err := h.Adapter.Write(t.Context(), ref, fields, stores.WriteOptions{CreateOnly: true}); err != nil {
		t.Fatalf("create-only Write of a new secret: %v", err)
	}
	_, err := h.Adapter.Write(t.Context(), ref, fields, stores.WriteOptions{CreateOnly: true})
	wantKind(t, err, stores.ErrConflict, "create-only Write of an existing secret")
	noLeak(t, "conflict error", err, plain)
}

func watch(t TB, h *Harness) {
	if !h.Adapter.Capabilities().Has(stores.CapWatch) {
		return
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	ch, err := h.Adapter.Watch(ctx, h.ref("watched"))
	if err != nil {
		t.Fatalf("Watch: %v", err)
	}
	ref := h.ref("watched/one")
	fields, plain := values(t, "value")
	h.seed(t, ref, fields)
	timeout := time.After(h.WatchTimeout)
	for done := false; !done; {
		select {
		case c, ok := <-ch:
			if !ok {
				t.Fatalf("Watch channel closed before the change arrived")
			}
			noLeak(t, "change", c, plain)
			done = c.Ref.Path == ref.Path && c.Kind == stores.Changed
		case <-timeout:
			t.Fatalf("Watch reported no change for %s within %s", ref, h.WatchTimeout)
		}
	}
	cancel()
	deadline := time.After(h.WatchTimeout)
	for {
		select {
		case _, ok := <-ch:
			if !ok {
				return
			}
		case <-deadline:
			t.Fatalf("Watch channel not closed after the context ended")
		}
	}
}

func health(t TB, h *Harness) {
	if err := h.Adapter.Health(t.Context()); err != nil {
		t.Errorf("Health on a working store: %v", err)
	}
}

func outage(t TB, h *Harness) {
	if h.Outage == nil {
		return
	}
	ref := h.ref("outage")
	fields, plain := values(t, "value")
	h.seed(t, ref, fields)
	restore := h.Outage(t)
	_, err := h.Adapter.Read(t.Context(), ref)
	wantKind(t, err, stores.ErrUnavailable, "Read during an outage")
	noLeak(t, "outage error", err, plain)
	if err := h.Adapter.Health(t.Context()); !errors.Is(err, stores.ErrUnavailable) {
		t.Errorf("Health during an outage: %v, want ErrUnavailable", err)
	}
	restore()
	got, err := h.Adapter.Read(t.Context(), ref)
	if err != nil {
		t.Fatalf("Read after the outage: %v", err)
	}
	got.Wipe()
}
