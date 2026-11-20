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
// the [stores.Adapter] interface only: declared capabilities and the refusal
// of everything outside them, read with and without a field selector,
// version selectors, value fidelity, list, write, create-only and rejected
// writes, write-only paths, labels, watch (create, rotate, delete, survive
// an outage), health, outage, concurrent use, and that no error, metadata or
// change notification ever contains a value. Optional behaviour is switched
// on by the [Harness] fields that describe what the store under test can do.
//
// The suite proves itself: storetest_test.go runs it against deliberately
// broken adapters and requires each to fail the case aimed at it.
package storetest

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
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
	Logf(format string, args ...any)
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
	// SingleField names the only field a secret holds, for stores whose
	// secrets are single values (Infisical, env, a raw file). Empty means
	// the store holds multi-field secrets with arbitrary field names.
	SingleField string
	// Seed puts a secret into the store out of band. Required when the
	// adapter does not declare stores.CapWrite; otherwise Write is used.
	Seed func(t TB, ref stores.Ref, fields map[string]secret.Value)
	// Delete removes a secret out of band. When set, the suite checks that
	// Watch reports the deletion and Read then reports not found.
	Delete func(t TB, ref stores.Ref)
	// Outage, if set, makes the store unreachable until restore is called.
	Outage func(t TB) (restore func())
	// VersionSelector says the adapter resolves `?version=<v>` selectors
	// with the versions it reports in Metadata.Version.
	VersionSelector bool
	// Labels says the adapter stores WriteOptions.Labels and reports them
	// in Metadata.Labels.
	Labels bool
	// WriteOnlyPrefix is a path prefix the adapter is configured to treat
	// as write-only: writes succeed, reads are refused without contacting
	// the store, and list reports the entries as write-only.
	WriteOnlyPrefix string
	// Reject returns a reference the store refuses to write (for example a
	// path outside scrim's policy). When set, the suite checks the refusal
	// is ErrPermission, names the reference and carries no value.
	Reject func(t TB) stores.Ref
	// Unstorable reports values the store cannot hold byte for byte (for
	// example Infisical trims surrounding whitespace). For those the suite
	// requires Write to refuse with ErrUnsupported and store nothing,
	// instead of storing a changed value that would no longer match what
	// scrim redacts.
	Unstorable func(value string) bool
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
			Check(t, f, c)
		})
	}
}

// Check prepares a harness and runs one case against it.
func Check(t TB, f Factory, c Case) {
	t.Helper()
	h := Prepare(t, f)
	c.Run(t, h)
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
	h.Prefix = strings.Trim(h.Prefix, "/")
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
		{"ReadUnknownSelector", readUnknownSelector},
		{"ValueFidelity", valueFidelity},
		{"List", list},
		{"ListEmpty", listEmpty},
		{"WriteRoundTrip", writeRoundTrip},
		{"WriteCreateOnly", writeCreateOnly},
		{"WriteVersions", writeVersions},
		{"WriteLabels", writeLabels},
		{"WriteRejected", writeRejected},
		{"WriteOnly", writeOnly},
		{"Watch", watch},
		{"WatchDelete", watchDelete},
		{"Health", health},
		{"Outage", outage},
		{"Concurrent", concurrent},
	}
}

// ref builds a reference under the harness prefix.
func (h *Harness) ref(name string) stores.Ref {
	p := h.Prefix
	if name != "" {
		p += "/" + name
	}
	return stores.Ref{Scheme: h.Scheme, Path: p}
}

// names returns the field names a multi-field case should use, collapsed
// to the single field for single-value stores.
func (h *Harness) names(multi ...string) []string {
	if h.SingleField != "" {
		return []string{h.SingleField}
	}
	return multi
}

func (h *Harness) can(c stores.Capability) bool { return h.Adapter.Capabilities().Has(c) }

func (h *Harness) seed(t TB, ref stores.Ref, fields map[string]secret.Value) {
	t.Helper()
	if h.Seed != nil {
		h.Seed(t, ref, fields)
		return
	}
	if !h.can(stores.CapWrite) {
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

// noLeak fails if x's message, or its %+v or %#v form, contains any value.
// For an error it checks every error in the chain too: a cause kept for
// errors.Is must not hold a value either, since a caller may log it.
func noLeak(t TB, what string, x any, plain []string) {
	t.Helper()
	if x == nil {
		return
	}
	var texts []string
	if err, ok := x.(error); ok {
		texts = append(texts, chainTexts(err)...)
	}
	texts = append(texts, fmt.Sprintf("%+v", x), fmt.Sprintf("%#v", x))
	for _, text := range texts {
		for _, p := range plain {
			if p != "" && strings.Contains(text, p) {
				t.Errorf("%s contains a secret value", what)
				return
			}
		}
	}
}

func chainTexts(err error) []string {
	if err == nil {
		return nil
	}
	out := []string{err.Error()}
	switch u := err.(type) {
	case interface{ Unwrap() []error }:
		for _, e := range u.Unwrap() {
			out = append(out, chainTexts(e)...)
		}
	case interface{ Unwrap() error }:
		out = append(out, chainTexts(u.Unwrap())...)
	}
	return out
}

// wantKind checks err wraps kind and is a *stores.Error naming the adapter.
func wantKind(t TB, h *Harness, err, kind error, what string) {
	t.Helper()
	if !errors.Is(err, kind) {
		t.Errorf("%s: got error %v, want one wrapping %q", what, err, kind)
		return
	}
	var se *stores.Error
	if !errors.As(err, &se) {
		t.Errorf("%s: error %v is not a *stores.Error", what, err)
		return
	}
	if se.Store != h.Adapter.Name() {
		t.Errorf("%s: error names store %q, want %q", what, se.Store, h.Adapter.Name())
	}
}

func declaresRead(t TB, h *Harness) {
	if !h.can(stores.CapRead) {
		t.Errorf("adapter %s does not declare read; every store must", h.Adapter.Name())
	}
	if h.can(stores.CapWatch) && !h.can(stores.CapList) {
		t.Errorf("adapter %s declares watch without list; a watcher cannot load what changed", h.Adapter.Name())
	}
}

func unsupportedRefused(t TB, h *Harness) {
	ctx := t.Context()
	ref := h.ref("unsupported")
	fields, plain := values(t, h.names("value")...)
	if !h.can(stores.CapWrite) {
		_, err := h.Adapter.Write(ctx, ref, fields, stores.WriteOptions{})
		wantKind(t, h, err, stores.ErrUnsupported, "Write on a store without write")
		noLeak(t, "unsupported write error", err, plain)
		// Refused before any partial write: nothing is there afterwards.
		if s, err := h.Adapter.Read(ctx, ref); err == nil {
			s.Wipe()
			t.Errorf("a refused Write still stored %s", ref)
		}
		for _, v := range fields {
			if v.Wiped() {
				t.Errorf("a refused Write wiped the caller's value")
			}
		}
	}
	if !h.can(stores.CapList) {
		_, err := h.Adapter.List(ctx, h.ref(""))
		wantKind(t, h, err, stores.ErrUnsupported, "List on a store without list")
	}
	if !h.can(stores.CapWatch) {
		_, err := h.Adapter.Watch(ctx, h.ref(""))
		wantKind(t, h, err, stores.ErrUnsupported, "Watch on a store without watch")
	}
}

func readSeeded(t TB, h *Harness) {
	ref := h.ref("multi")
	names := h.names("username", "password")
	fields, plain := values(t, names...)
	h.seed(t, ref, fields)
	got, err := h.Adapter.Read(t.Context(), ref)
	if err != nil {
		t.Fatalf("Read %s: %v", ref, err)
	}
	defer got.Wipe()
	for i, name := range names {
		v, ok := got.Field(name)
		if !ok {
			t.Errorf("Read %s: field %s missing", ref, name)
			continue
		}
		if expose(t, v) != plain[i] {
			t.Errorf("Read %s: field %s has the wrong value", ref, name)
		}
	}
	if got.Meta.Ref.Path != ref.Path || got.Meta.Ref.Scheme != h.Scheme {
		t.Errorf("Read %s: metadata names %s", ref, got.Meta.Ref)
	}
	if got.Meta.Ref.Field != "" {
		t.Errorf("Read %s: metadata ref carries field %q", ref, got.Meta.Ref.Field)
	}
	noLeak(t, "secret metadata", got.Meta, plain)
	noLeak(t, "secret", got, plain)
}

func readField(t TB, h *Harness) {
	ref := h.ref("fields")
	names := h.names("token", "other")
	fields, plain := values(t, names...)
	h.seed(t, ref, fields)
	got, err := h.Adapter.Read(t.Context(), ref.WithField(names[0]))
	if err != nil {
		t.Fatalf("Read with field: %v", err)
	}
	defer got.Wipe()
	if len(got.Fields) != 1 {
		t.Errorf("Read with field returned %d fields, want 1", len(got.Fields))
	}
	if v, ok := got.Field(names[0]); !ok || expose(t, v) != plain[0] {
		t.Errorf("Read with field: wrong or missing %s", names[0])
	}
	_, err = h.Adapter.Read(t.Context(), ref.WithField("absent"))
	wantKind(t, h, err, stores.ErrNotFound, "Read of a missing field")
	noLeak(t, "missing field error", err, plain)
}

func readMissing(t TB, h *Harness) {
	ref := h.ref("does-not-exist")
	_, err := h.Adapter.Read(t.Context(), ref)
	wantKind(t, h, err, stores.ErrNotFound, "Read of a missing secret")
	if err != nil && !strings.Contains(err.Error(), ref.Path) {
		t.Errorf("Read of a missing secret: error %q does not name the reference", err)
	}
}

func readUnknownSelector(t TB, h *Harness) {
	ref := h.ref("selector")
	fields, plain := values(t, h.names("value")...)
	h.seed(t, ref, fields)
	bad := ref
	bad.Selectors = "scrim-unknown-selector=1"
	got, err := h.Adapter.Read(t.Context(), bad)
	if err == nil {
		got.Wipe()
		t.Errorf("Read with an unknown selector succeeded; a selector the store cannot honour must be refused, not ignored")
		return
	}
	wantKind(t, h, err, stores.ErrInvalidRef, "Read with an unknown selector")
	noLeak(t, "selector error", err, plain)
}

// trickyValues are values that break naive quoting, trimming or encoding.
func trickyValues(t TB) []string {
	r := randHex(t, 6)
	return []string{
		`quote"` + r + `"and\backslash\\`,
		"line one " + r + "\nline two\r\nline three\ttab",
		" leading and trailing space " + r + " ",
		"unicode é 日本 🔑    " + r,
		"<html>&amp;'single' {{template}} ${VAR} $(cmd) `tick` " + r,
		"=" + r + "=#;not a comment",
	}
}

func valueFidelity(t TB, h *Harness) {
	ctx := t.Context()
	for i, p := range trickyValues(t) {
		ref := h.ref(fmt.Sprintf("fidelity-%d", i))
		field := h.names("value")[0]
		if h.Unstorable != nil && h.Unstorable(p) {
			if !h.can(stores.CapWrite) {
				continue
			}
			_, err := h.Adapter.Write(ctx, ref, map[string]secret.Value{field: secret.FromString(p)}, stores.WriteOptions{})
			wantKind(t, h, err, stores.ErrUnsupported, fmt.Sprintf("Write of unstorable value %d", i))
			noLeak(t, "unstorable value error", err, []string{p})
			if s, err := h.Adapter.Read(ctx, ref); err == nil {
				s.Wipe()
				t.Errorf("an unstorable value %d was stored anyway", i)
			}
			continue
		}
		h.seed(t, ref, map[string]secret.Value{field: secret.FromString(p)})
		got, err := h.Adapter.Read(ctx, ref.WithField(field))
		if err != nil {
			t.Errorf("Read %s: %v", ref, err)
			continue
		}
		v, _ := got.Field(field)
		if expose(t, v) != p {
			t.Errorf("value %d did not round-trip byte for byte", i)
		}
		got.Wipe()
	}
}

func list(t TB, h *Harness) {
	if !h.can(stores.CapList) {
		return
	}
	var all []string
	want := []stores.Ref{h.ref("list/a"), h.ref("list/b"), h.ref("list/sub/c")}
	outside := []stores.Ref{h.ref("list-other/x"), h.ref("listx")}
	for _, r := range append(slices.Clone(want), outside...) {
		fields, plain := values(t, h.names("value")...)
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
		if m.Ref.Field != "" {
			t.Errorf("List: ref %s carries a field", m.Ref)
		}
	}
	for _, r := range want {
		if !slices.Contains(paths, r.Path) {
			t.Errorf("List: %s missing from %v", r, paths)
		}
	}
	for _, r := range outside {
		if slices.Contains(paths, r.Path) {
			t.Errorf("List of %s/list returned %s, which is outside the prefix", h.Prefix, r)
		}
	}
	// The version List reports is the version Read reports.
	for _, m := range got {
		if m.Ref.Path != want[0].Path || m.Version == "" {
			continue
		}
		s, err := h.Adapter.Read(t.Context(), m.Ref)
		if err != nil {
			t.Fatalf("Read %s: %v", m.Ref, err)
		}
		if s.Meta.Version != "" && s.Meta.Version != m.Version {
			t.Errorf("List reports version %q for %s, Read reports %q", m.Version, m.Ref, s.Meta.Version)
		}
		s.Wipe()
	}
}

func listEmpty(t TB, h *Harness) {
	if !h.can(stores.CapList) {
		return
	}
	got, err := h.Adapter.List(t.Context(), h.ref("nothing-here"))
	if err != nil {
		t.Errorf("List of an empty prefix: %v, want no error", err)
	}
	if len(got) != 0 {
		t.Errorf("List of an empty prefix returned %d entries", len(got))
	}
}

func writeRoundTrip(t TB, h *Harness) {
	if !h.can(stores.CapWrite) {
		return
	}
	ctx := t.Context()
	ref := h.ref("written")
	field := h.names("value")[0]
	first, p1 := values(t, field)
	m1, err := h.Adapter.Write(ctx, ref, first, stores.WriteOptions{})
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	noLeak(t, "write metadata", m1, p1)
	if m1.Ref.Path != ref.Path {
		t.Errorf("Write returned metadata for %s, want %s", m1.Ref, ref)
	}
	second, p2 := values(t, field)
	m2, err := h.Adapter.Write(ctx, ref, second, stores.WriteOptions{})
	if err != nil {
		t.Fatalf("second Write: %v", err)
	}
	noLeak(t, "write metadata", m2, append(p1, p2...))
	if m1.Version != "" && m1.Version == m2.Version {
		t.Errorf("a new write kept version %q", m1.Version)
	}
	got, err := h.Adapter.Read(ctx, ref.WithField(field))
	if err != nil {
		t.Fatalf("Read after Write: %v", err)
	}
	defer got.Wipe()
	if v, _ := got.Field(field); expose(t, v) != p2[0] {
		t.Errorf("Read after Write did not return the latest version")
	}
	if m2.Version != "" && got.Meta.Version != "" && got.Meta.Version != m2.Version {
		t.Errorf("Read reports version %q after a write that reported %q", got.Meta.Version, m2.Version)
	}
	// The caller keeps ownership: the adapter must not wipe what it was given.
	if second[field].Wiped() || first[field].Wiped() {
		t.Errorf("Write wiped the caller's value")
	}
}

func writeCreateOnly(t TB, h *Harness) {
	if !h.can(stores.CapWrite) {
		return
	}
	ref := h.ref("create-only")
	field := h.names("value")[0]
	fields, plain := values(t, field)
	if _, err := h.Adapter.Write(t.Context(), ref, fields, stores.WriteOptions{CreateOnly: true}); err != nil {
		t.Fatalf("create-only Write of a new secret: %v", err)
	}
	again, plain2 := values(t, field)
	_, err := h.Adapter.Write(t.Context(), ref, again, stores.WriteOptions{CreateOnly: true})
	wantKind(t, h, err, stores.ErrConflict, "create-only Write of an existing secret")
	noLeak(t, "conflict error", err, append(plain, plain2...))
	got, err := h.Adapter.Read(t.Context(), ref.WithField(field))
	if err != nil {
		t.Fatalf("Read after a refused create: %v", err)
	}
	defer got.Wipe()
	if v, _ := got.Field(field); expose(t, v) != plain[0] {
		t.Errorf("a refused create-only Write replaced the existing value")
	}
}

func writeVersions(t TB, h *Harness) {
	if !h.VersionSelector || !h.can(stores.CapWrite) {
		return
	}
	ctx := t.Context()
	ref := h.ref("versions")
	field := h.names("value")[0]
	first, p1 := values(t, field)
	m1, err := h.Adapter.Write(ctx, ref, first, stores.WriteOptions{})
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	second, _ := values(t, field)
	if _, err := h.Adapter.Write(ctx, ref, second, stores.WriteOptions{}); err != nil {
		t.Fatalf("second Write: %v", err)
	}
	if m1.Version == "" {
		t.Fatalf("harness declares VersionSelector but Write reports no version")
	}
	pinned := ref.WithField(field)
	pinned.Selectors = "version=" + m1.Version
	got, err := h.Adapter.Read(ctx, pinned)
	if err != nil {
		t.Fatalf("Read %s: %v", pinned, err)
	}
	defer got.Wipe()
	if v, _ := got.Field(field); expose(t, v) != p1[0] {
		t.Errorf("Read %s did not return the pinned version", pinned)
	}
	if got.Meta.Version != m1.Version {
		t.Errorf("Read %s reports version %q", pinned, got.Meta.Version)
	}
	missing := ref
	missing.Selectors = "version=999999"
	_, err = h.Adapter.Read(ctx, missing)
	wantKind(t, h, err, stores.ErrNotFound, "Read of a version that does not exist")
}

func writeLabels(t TB, h *Harness) {
	if !h.Labels || !h.can(stores.CapWrite) {
		return
	}
	ref := h.ref("labelled/one")
	fields, plain := values(t, h.names("value")...)
	labels := map[string]string{"scrim.hosts": "api.example.test", "scrim.placeholder": "SCRIM_EXAMPLE"}
	m, err := h.Adapter.Write(t.Context(), ref, fields, stores.WriteOptions{Labels: labels})
	if err != nil {
		t.Fatalf("Write with labels: %v", err)
	}
	noLeak(t, "labelled metadata", m, plain)
	check := func(where string, got map[string]string) {
		t.Helper()
		for k, v := range labels {
			if got[k] != v {
				t.Errorf("%s: label %s = %q, want %q", where, k, got[k], v)
			}
		}
	}
	got, err := h.Adapter.Read(t.Context(), ref)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	check("Read", got.Meta.Labels)
	got.Wipe()
	if h.can(stores.CapList) {
		ms, err := h.Adapter.List(t.Context(), h.ref("labelled"))
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		found := false
		for _, m := range ms {
			if m.Ref.Path == ref.Path {
				found = true
				check("List", m.Labels)
			}
		}
		if !found {
			t.Errorf("List: %s missing", ref)
		}
	}
}

func writeRejected(t TB, h *Harness) {
	if h.Reject == nil || !h.can(stores.CapWrite) {
		return
	}
	ref := h.Reject(t)
	fields, plain := values(t, h.names("value")...)
	_, err := h.Adapter.Write(t.Context(), ref, fields, stores.WriteOptions{})
	wantKind(t, h, err, stores.ErrPermission, "Write the store refuses")
	noLeak(t, "rejected write error", err, plain)
	if err != nil && !strings.Contains(err.Error(), ref.Path) {
		t.Errorf("rejected write error %q does not name the reference", err)
	}
	for _, v := range fields {
		if v.Wiped() {
			t.Errorf("a rejected Write wiped the caller's value")
		}
	}
}

func writeOnly(t TB, h *Harness) {
	if h.WriteOnlyPrefix == "" {
		return
	}
	prefix := strings.Trim(h.WriteOnlyPrefix, "/")
	ref := stores.Ref{Scheme: h.Scheme, Path: prefix + "/" + randHex(t, 6)}
	fields, plain := values(t, h.names("value")...)
	m, err := h.Adapter.Write(t.Context(), ref, fields, stores.WriteOptions{})
	if err != nil {
		t.Fatalf("Write to a write-only path: %v", err)
	}
	noLeak(t, "write-only metadata", m, plain)
	if !m.WriteOnly {
		t.Errorf("Write to %s did not report the secret as write-only", ref)
	}
	got, err := h.Adapter.Read(t.Context(), ref)
	if err == nil {
		got.Wipe()
		t.Errorf("Read of write-only %s succeeded; scrim must not load write-only secrets from the store", ref)
	} else {
		wantKind(t, h, err, stores.ErrPermission, "Read of a write-only path")
		noLeak(t, "write-only read error", err, plain)
	}
	if h.can(stores.CapList) {
		ms, err := h.Adapter.List(t.Context(), stores.Ref{Scheme: h.Scheme, Path: prefix})
		if err != nil {
			// Listing a write-only prefix may itself be denied by policy.
			wantKind(t, h, err, stores.ErrPermission, "List of a write-only prefix")
			return
		}
		for _, m := range ms {
			noLeak(t, "write-only list metadata", m, plain)
			if !m.WriteOnly {
				t.Errorf("List reports %s under write-only %s without WriteOnly", m.Ref, prefix)
			}
		}
	}
}

// nextChange waits for a change to path with kind, ignoring others.
func nextChange(t TB, h *Harness, ch <-chan stores.Change, path string, kind stores.ChangeKind, plain []string) {
	t.Helper()
	timeout := time.After(h.WatchTimeout)
	for {
		select {
		case c, ok := <-ch:
			if !ok {
				t.Fatalf("Watch channel closed before the %s change to %s arrived", kind, path)
			}
			noLeak(t, "change", c, plain)
			if c.Ref.Scheme != h.Scheme {
				t.Errorf("change ref %s has scheme %q, want %q", c.Ref, c.Ref.Scheme, h.Scheme)
			}
			if c.Ref.Path == path && c.Kind == kind {
				return
			}
		case <-timeout:
			t.Fatalf("Watch reported no %s change for %s within %s", kind, path, h.WatchTimeout)
		}
	}
}

func waitClosed(t TB, h *Harness, ch <-chan stores.Change) {
	t.Helper()
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

func watch(t TB, h *Harness) {
	if !h.can(stores.CapWatch) {
		return
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	ch, err := h.Adapter.Watch(ctx, h.ref("watched"))
	if err != nil {
		t.Fatalf("Watch: %v", err)
	}
	ref := h.ref("watched/one")
	fields, plain := values(t, h.names("value")...)
	h.seed(t, ref, fields)
	nextChange(t, h, ch, ref.Path, stores.Changed, plain)
	// A rotation of an existing secret is a change too.
	rotated, plain2 := values(t, h.names("value")...)
	h.seed(t, ref, rotated)
	nextChange(t, h, ch, ref.Path, stores.Changed, append(plain, plain2...))
	cancel()
	waitClosed(t, h, ch)
}

func watchDelete(t TB, h *Harness) {
	if h.Delete == nil {
		return
	}
	ref := h.ref("deleted/one")
	fields, plain := values(t, h.names("value")...)
	h.seed(t, ref, fields)
	var ch <-chan stores.Change
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	if h.can(stores.CapWatch) {
		var err error
		if ch, err = h.Adapter.Watch(ctx, h.ref("deleted")); err != nil {
			t.Fatalf("Watch: %v", err)
		}
	}
	h.Delete(t, ref)
	if ch != nil {
		nextChange(t, h, ch, ref.Path, stores.Deleted, plain)
	}
	_, err := h.Adapter.Read(t.Context(), ref)
	wantKind(t, h, err, stores.ErrNotFound, "Read of a deleted secret")
	noLeak(t, "deleted read error", err, plain)
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
	ctx := t.Context()
	ref := h.ref("outage")
	fields, plain := values(t, h.names("value")...)
	h.seed(t, ref, fields)
	// Read once before the outage. Keeping last known values is the
	// refresher's job, not the adapter's: an adapter that serves a cached
	// copy during an outage hides it from health and degraded status.
	if before, err := h.Adapter.Read(ctx, ref); err != nil {
		t.Fatalf("Read before the outage: %v", err)
	} else {
		before.Wipe()
	}

	var ch <-chan stores.Change
	wctx, cancel := context.WithCancel(ctx)
	defer cancel()
	if h.can(stores.CapWatch) {
		var err error
		if ch, err = h.Adapter.Watch(wctx, h.ref("")); err != nil {
			t.Fatalf("Watch: %v", err)
		}
	}

	restore := h.Outage(t)
	restored := false
	defer func() {
		if !restored {
			restore()
		}
	}()
	_, err := h.Adapter.Read(ctx, ref)
	wantKind(t, h, err, stores.ErrUnavailable, "Read during an outage")
	noLeak(t, "outage read error", err, plain)
	if err := h.Adapter.Health(ctx); !errors.Is(err, stores.ErrUnavailable) {
		t.Errorf("Health during an outage: %v, want ErrUnavailable", err)
	}
	if h.can(stores.CapList) {
		_, err := h.Adapter.List(ctx, h.ref(""))
		wantKind(t, h, err, stores.ErrUnavailable, "List during an outage")
	}
	if h.can(stores.CapWrite) {
		during, p := values(t, h.names("value")...)
		_, err := h.Adapter.Write(ctx, h.ref("outage-write"), during, stores.WriteOptions{})
		wantKind(t, h, err, stores.ErrUnavailable, "Write during an outage")
		noLeak(t, "outage write error", err, p)
	}
	restore()
	restored = true

	got, err := h.Adapter.Read(ctx, ref)
	if err != nil {
		t.Fatalf("Read after the outage: %v", err)
	}
	got.Wipe()
	// A watch started before the outage keeps working after it.
	if ch != nil {
		after := h.ref("after-outage")
		f2, p2 := values(t, h.names("value")...)
		h.seed(t, after, f2)
		nextChange(t, h, ch, after.Path, stores.Changed, append(plain, p2...))
	}
}

func concurrent(t TB, h *Harness) {
	ctx := t.Context()
	field := h.names("value")[0]
	refs := make([]stores.Ref, 4)
	want := map[string]string{}
	for i := range refs {
		refs[i] = h.ref(fmt.Sprintf("concurrent/%d", i))
		fields, plain := values(t, field)
		h.seed(t, refs[i], fields)
		want[refs[i].Path] = plain[0]
	}
	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		errs = map[string]bool{}
	)
	fail := func(format string, args ...any) {
		mu.Lock()
		errs[fmt.Sprintf(format, args...)] = true
		mu.Unlock()
	}
	for g := range 8 {
		wg.Go(func() {
			for i := range 5 {
				ref := refs[(g+i)%len(refs)]
				s, err := h.Adapter.Read(ctx, ref.WithField(field))
				if err != nil {
					fail("concurrent Read %s: %v", ref, err)
					continue
				}
				v, _ := s.Field(field)
				ok := false
				_ = v.Expose(func(b []byte) error { ok = string(b) == want[ref.Path]; return nil })
				if !ok {
					fail("concurrent Read %s returned another value", ref)
				}
				s.Wipe()
				if h.can(stores.CapList) && i == 0 {
					if _, err := h.Adapter.List(ctx, h.ref("concurrent")); err != nil {
						fail("concurrent List: %v", err)
					}
				}
			}
		})
	}
	wg.Wait()
	keys := make([]string, 0, len(errs))
	for k := range errs {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, e := range keys {
		t.Errorf("%s", e)
	}
}
