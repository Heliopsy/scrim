// SPDX-License-Identifier: AGPL-3.0-only

package infisical

import (
	"errors"
	"maps"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/heliopsy/scrim/internal/stores"
)

// metadataFixture puts secrets covering every label source into the fake:
// tags, plain and encrypted metadata, rotation, reminder, an import and a
// second version.
func metadataFixture(t *testing.T, f *fake) (values []string) {
	t.Helper()
	v := func() string {
		s := "v-" + randID(16)
		values = append(values, s)
		return s
	}
	f.put("prod", "/db/Primary", "PASSWORD", v(), func(s *fakeSecret) {
		s.tags = []apiTag{{Slug: "pci", Name: "PCI"}, {Slug: "prod", Name: "Prod"}}
		s.metadata = []kv{
			{Key: "owner", Value: "payments"},
			{Key: "infisical.environment", Value: "dev"},
			{Key: "pin", Value: "e-" + randID(8), IsEncrypted: true},
		}
		s.rotation = "11111111-0000-4000-8000-" + randID(6)
		s.reminder = 30
		s.comment = "c-" + randID(8)
		s.versions = append(s.versions, v())
	})
	f.put("dev", "/shared", "SHARED_KEY", v(), nil)
	f.put("prod", "/app", "OWN", v(), nil)
	f.put("dev", "/", "ROOT", v(), nil)
	f.mu.Lock()
	f.imports[f.projects["proj"]+"|prod|/app"] = "dev|/shared"
	f.mu.Unlock()
	return values
}

// metadataRefs are the references metadataFixture serves, in every form the
// adapter accepts.
func metadataRefs(f *fake) []string {
	pid := f.projects["proj"]
	return []string{
		"proj/prod/db/Primary/PASSWORD",
		"proj/prod/db/Primary/PASSWORD?version=1",
		"proj/prod/app/SHARED_KEY",
		"proj/prod/app/OWN",
		"proj/dev/ROOT",
		pid + "/dev/ROOT",
	}
}

func parse(t *testing.T, path string) stores.Ref {
	t.Helper()
	p, sel, _ := strings.Cut(path, "?")
	return stores.Ref{Scheme: "inf", Path: p, Selectors: sel}
}

// ReadMetadata returns exactly the metadata Read returns, labels included,
// and asks Infisical for no value.
func TestReadMetadataMatchesRead(t *testing.T) {
	f := newFake(t)
	a := newAdapter(t, f, map[string]any{"expand-references": true})
	values := metadataFixture(t, f)
	for _, path := range metadataRefs(f) {
		ref := parse(t, path)
		s, err := a.Read(t.Context(), ref)
		if err != nil {
			t.Fatalf("Read %s: %v", path, err)
		}
		s.Wipe()
		f.mu.Lock()
		f.gets, f.valuesServed = nil, 0
		f.mu.Unlock()

		m, err := a.ReadMetadata(t.Context(), ref)
		if err != nil {
			t.Fatalf("ReadMetadata %s: %v", path, err)
		}
		if !reflect.DeepEqual(m, s.Meta) {
			t.Errorf("%s: ReadMetadata differs from Read\n got %#v\nwant %#v", path, m, s.Meta)
		}
		if len(m.Labels) == 0 || !maps.Equal(m.Labels, s.Meta.Labels) {
			t.Errorf("%s: labels differ\n got %v\nwant %v", path, m.Labels, s.Meta.Labels)
		}
		f.mu.Lock()
		gets, served := f.gets, f.valuesServed
		f.mu.Unlock()
		if len(gets) != 1 {
			t.Fatalf("%s: %d single reads, want 1", path, len(gets))
		}
		if q := gets[0]; q.Get("viewSecretValue") != "false" || q.Get("expandSecretReferences") != "false" {
			t.Errorf("%s: metadata read asked with viewSecretValue=%q expandSecretReferences=%q", path,
				q.Get("viewSecretValue"), q.Get("expandSecretReferences"))
		}
		if served != 0 {
			t.Errorf("%s: the fake served %d values to a metadata read", path, served)
		}
		for k, v := range m.Labels {
			for _, val := range values {
				if strings.Contains(k, val) || strings.Contains(v, val) {
					t.Errorf("%s: label %s holds a value", path, k)
				}
			}
		}
	}
}

// stores.Set.Metadata goes through ReadMetadata, never through Read, and
// the composed labels are the ones the Read path composes.
func TestSetMetadataUsesReadMetadata(t *testing.T) {
	f := newFake(t)
	a := newAdapter(t, f, nil)
	metadataFixture(t, f)
	set := stores.NewSet()
	if err := set.Add(a); err != nil {
		t.Fatal(err)
	}
	set.SetLabeling(a.Name(), Kind, nil)
	for _, path := range metadataRefs(f) {
		ref := parse(t, path)
		s, err := a.Read(t.Context(), ref)
		if err != nil {
			t.Fatalf("Read %s: %v", path, err)
		}
		s.Wipe()
		f.mu.Lock()
		f.valuesServed = 0
		f.mu.Unlock()
		m, exists, err := set.Metadata(t.Context(), ref.WithField(Field))
		if err != nil || !exists {
			t.Fatalf("Set.Metadata %s: exists %v, %v", path, exists, err)
		}
		f.mu.Lock()
		served := f.valuesServed
		f.mu.Unlock()
		if served != 0 {
			t.Errorf("%s: Set.Metadata fetched %d values", path, served)
		}
		got, want := set.Labels(ref, m.Labels), set.Labels(ref, s.Meta.Labels)
		if !maps.Equal(got, want) {
			t.Errorf("%s: composed labels differ\n got %v\nwant %v", path, got, want)
		}
		if !maps.Equal(got, stores.ComposeLabels(a.Name(), Kind, ref, s.Meta.Labels, nil)) {
			t.Errorf("%s: Set.Labels is not ComposeLabels of the Read labels", path)
		}
	}
}

// ReadMetadata fails where Read fails, with the same error kind, and a
// missing secret is reported as missing, not as an error.
func TestReadMetadataErrors(t *testing.T) {
	f := newFake(t)
	a := newAdapter(t, f, nil)
	f.put("prod", "/", "A", "v-"+randID(8), nil)
	set := stores.NewSet()
	if err := set.Add(a); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		path string
		kind error
	}{
		{"proj/prod/MISSING", stores.ErrNotFound},
		{"proj/prod/A?version=9", stores.ErrNotFound},
		{"proj/prod/A?version=x", stores.ErrInvalidRef},
		{"proj/prod/A?rev=1", stores.ErrInvalidRef},
		{"proj/A", stores.ErrInvalidRef},
		{"nope/prod/A", stores.ErrNotFound},
	} {
		ref := parse(t, c.path)
		_, rerr := a.Read(t.Context(), ref)
		_, merr := a.ReadMetadata(t.Context(), ref)
		if !errors.Is(rerr, c.kind) || !errors.Is(merr, c.kind) {
			t.Errorf("%s: Read %v, ReadMetadata %v, want %v for both", c.path, rerr, merr, c.kind)
		}
	}
	if _, err := a.ReadMetadata(t.Context(), stores.Ref{Scheme: "inf", Path: "proj/prod/A", Field: "other"}); !errors.Is(err, stores.ErrNotFound) {
		t.Errorf("unknown field: %v", err)
	}
	if _, exists, err := set.Metadata(t.Context(), parse(t, "proj/prod/MISSING")); exists || err != nil {
		t.Errorf("Set.Metadata of a missing secret: exists %v, %v", exists, err)
	}

	// An outage fails closed: an error, never empty labels.
	f.setDown(true)
	_, rerr := a.Read(t.Context(), parse(t, "proj/prod/A"))
	_, merr := a.ReadMetadata(t.Context(), parse(t, "proj/prod/A"))
	if !errors.Is(rerr, stores.ErrUnavailable) || !errors.Is(merr, stores.ErrUnavailable) {
		t.Errorf("outage: Read %v, ReadMetadata %v", rerr, merr)
	}
	if _, exists, err := set.Metadata(t.Context(), parse(t, "proj/prod/A")); exists || !errors.Is(err, stores.ErrUnavailable) {
		t.Errorf("Set.Metadata during an outage: exists %v, %v", exists, err)
	}
	f.setDown(false)
}

// An identity that may describe secrets but not read their values still
// gets labels, because ReadMetadata never asks for the value.
func TestReadMetadataWithoutValuePermission(t *testing.T) {
	f := newFake(t)
	a := newAdapter(t, f, nil)
	f.put("prod", "/db", "A", "v-"+randID(8), func(s *fakeSecret) { s.tags = []apiTag{{Slug: "pci"}} })
	f.mu.Lock()
	f.denyValues = true
	f.mu.Unlock()
	ref := parse(t, "proj/prod/db/A")
	if _, err := a.Read(t.Context(), ref); !errors.Is(err, stores.ErrPermission) {
		t.Fatalf("Read with values denied: %v", err)
	}
	m, err := a.ReadMetadata(t.Context(), ref)
	if err != nil {
		t.Fatalf("ReadMetadata with values denied: %v", err)
	}
	wantLabels(t, "denied", m.Labels, map[string]string{"infisical.tag.pci": "true", "infisical.folder.db": "true"})
}

// A server that ignores viewSecretValue sends the value anyway: it is
// wiped unread and appears in no label, as with the fallback read.
func TestReadMetadataServerIgnoresView(t *testing.T) {
	f := newFake(t)
	a := newAdapter(t, f, nil)
	value := "v-" + randID(16)
	f.put("prod", "/", "A", value, nil)
	f.mu.Lock()
	f.ignoreView = true
	f.mu.Unlock()
	m, err := a.ReadMetadata(t.Context(), parse(t, "proj/prod/A"))
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range slices.Sorted(maps.Keys(m.Labels)) {
		if strings.Contains(k, value) || strings.Contains(m.Labels[k], value) {
			t.Errorf("label %s holds the value", k)
		}
	}
	if !slices.Equal(m.Fields, []string{Field}) {
		t.Errorf("fields: %v", m.Fields)
	}
}

// An identity that may describe a secret but not read its value gets the
// mask with secretValueHidden on a normal read. Read refuses it as a
// permission error and never returns the mask as the value.
func TestReadRefusesHiddenValue(t *testing.T) {
	f := newFake(t)
	a := newAdapter(t, f, nil)
	f.put("prod", "/", "A", "v-"+randID(16), nil)
	f.mu.Lock()
	f.maskValues = true
	f.mu.Unlock()
	s, err := a.Read(t.Context(), parse(t, "proj/prod/A"))
	if !errors.Is(err, stores.ErrPermission) {
		t.Fatalf("Read of a hidden value = %v, want ErrPermission", err)
	}
	if len(s.Fields) != 0 {
		t.Fatalf("Read returned fields for a hidden value")
	}
	if strings.Contains(err.Error(), "hidden-by-infisical") {
		t.Fatalf("error carries the mask: %v", err)
	}
	if _, err := a.ReadMetadata(t.Context(), parse(t, "proj/prod/A")); err != nil {
		t.Fatalf("ReadMetadata of a hidden value: %v", err)
	}
}
