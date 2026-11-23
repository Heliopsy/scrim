// SPDX-License-Identifier: AGPL-3.0-only

package gcpsm

import (
	"errors"
	"fmt"
	"maps"
	"strings"
	"testing"
	"time"

	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores"
)

func TestNativeLabels(t *testing.T) {
	f := newFake(t)
	a := adapterFor(t, f, nil)
	value := "lbl-" + randHex(8)
	f.put("", "prod--db", []byte(value))
	exp := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	f.edit("", "prod--db", func(s *fakeSecret) {
		s.replication = map[string]any{"userManaged": map[string]any{"replicas": []any{
			map[string]any{"location": "europe-west1", "customerManagedEncryption": map[string]any{"kmsKeyName": "projects/k/locations/europe-west1/keyRings/r/cryptoKeys/a"}},
			map[string]any{"location": "europe-west4"},
		}}}
		s.labels = map[string]string{"env": "prod", "team": "payments"}
		s.annotations = map[string]string{
			"scrim.hosts":      "db.example.test",
			"gcpsm.location":   "us-central1", // forged native key
			"gcpsm.replica.x":  "true",        // forged presence key
			"team":             "annotated",   // loses to the label
			"owner.example.io": "alice",
		}
		s.topics = []string{"projects/p/topics/rotations"}
		s.expire = exp
		s.rotation = map[string]any{"nextRotationTime": "2029-06-01T00:00:00Z", "rotationPeriod": "2592000s"}
		s.aliases = map[string]int{"current": 1}
	})
	s, err := a.Read(t.Context(), ref("prod/db"))
	if err != nil {
		t.Fatal(err)
	}
	s.Wipe()
	l := s.Meta.Labels
	want := map[string]string{
		"gcpsm.project":                           f.project,
		"gcpsm.project.number":                    f.number,
		"gcpsm.location":                          "global",
		"gcpsm.secret":                            "prod--db",
		"gcpsm.path":                              "prod/db",
		"gcpsm.replication":                       "user-managed",
		"gcpsm.replica":                           "europe-west1,europe-west4",
		"gcpsm.replica.europe-west1":              "true",
		"gcpsm.replica.europe-west4":              "true",
		"gcpsm.kms-key":                           "projects/k/locations/europe-west1/keyRings/r/cryptoKeys/a",
		"gcpsm.topic.projects/p/topics/rotations": "true",
		"gcpsm.expires":                           "2030-01-02T03:04:05Z",
		"gcpsm.rotation.next":                     "2029-06-01T00:00:00Z",
		"gcpsm.rotation.period":                   "2592000s",
		"gcpsm.alias":                             "current",
		"gcpsm.alias.current":                     "true",
		"gcpsm.version":                           "1",
		"gcpsm.version-alias":                     "current",
		"gcpsm.version.state":                     "enabled",
		"gcpsm.meta.env":                          "prod",
		"gcpsm.meta.team":                         "payments",
		"gcpsm.meta.owner.example.io":             "alice",
		"gcpsm.meta.gcpsm.location":               "us-central1",
		"scrim.hosts":                             "db.example.test",
		"owner.example.io":                        "alice",
	}
	for k, v := range want {
		if l[k] != v {
			t.Errorf("label %s = %q, want %q", k, l[k], v)
		}
	}
	if _, ok := l["gcpsm.replica.x"]; ok {
		t.Errorf("an annotation forged a presence key")
	}
	if l["gcpsm.created"] == "" {
		t.Errorf("no gcpsm.created")
	}
	for k, v := range l {
		if strings.Contains(k, value) || strings.Contains(v, value) {
			t.Errorf("label %s carries the payload", k)
		}
	}
	// Composed for policy, every label is kept and store.* is scrim's.
	set := stores.NewSet()
	_ = set.Add(a)
	set.SetLabeling("gsm", Kind, nil)
	c := set.Labels(ref("prod/db"), l)
	if c["store.kind"] != Kind || c["gcpsm.location"] != "global" {
		t.Errorf("composed labels %v", c)
	}
}

func TestRegionalLabels(t *testing.T) {
	f := newFake(t)
	a := adapterFor(t, f, map[string]any{"location": "europe-west4"})
	parent := "projects/" + f.project + "/locations/europe-west4"
	f.put(parent, "r", []byte("v"))
	f.edit(parent, "r", func(s *fakeSecret) {
		s.cmek = map[string]any{"kmsKeyName": "projects/k/locations/europe-west4/keyRings/r/cryptoKeys/b"}
	})
	m, err := a.ReadMetadata(t.Context(), ref("r"))
	if err != nil {
		t.Fatal(err)
	}
	if m.Labels["gcpsm.location"] != "europe-west4" || m.Labels["gcpsm.replication"] != "regional" ||
		m.Labels["gcpsm.kms-key"] != "projects/k/locations/europe-west4/keyRings/r/cryptoKeys/b" {
		t.Errorf("regional labels %v", m.Labels)
	}
	// The global collection does not hold the regional secret.
	g := adapterFor(t, f, nil)
	if _, err := g.Read(t.Context(), ref("r")); !errors.Is(err, stores.ErrNotFound) {
		t.Errorf("regional secret read through the global endpoint: %v", err)
	}
}

func TestMetadataWithoutValues(t *testing.T) {
	f := newFake(t)
	a := adapterFor(t, f, nil)
	ctx := t.Context()
	value := "md-" + randHex(8)
	if _, err := a.Write(ctx, ref("app/key"), map[string]secret.Value{Field: secret.FromString(value)},
		stores.WriteOptions{Labels: map[string]string{"scrim.hosts": "api.example.test"}}); err != nil {
		t.Fatal(err)
	}
	f.edit("", "app--key", func(s *fakeSecret) { s.labels = map[string]string{"env": "dev"}; s.aliases = map[string]int{"live": 1} })
	s, err := a.Read(ctx, ref("app/key"))
	if err != nil {
		t.Fatal(err)
	}
	s.Wipe()
	before := f.accesses
	m, err := a.ReadMetadata(ctx, ref("app/key"))
	if err != nil {
		t.Fatal(err)
	}
	if f.accesses != before {
		t.Errorf("ReadMetadata accessed a payload")
	}
	if !maps.Equal(m.Labels, s.Meta.Labels) {
		t.Errorf("metadata labels differ from Read's:\n got %v\nwant %v", m.Labels, s.Meta.Labels)
	}
	if m.Version != s.Meta.Version || m.Version != "1" {
		t.Errorf("metadata version %q, read %q", m.Version, s.Meta.Version)
	}
	noValue(t, fmt.Sprintf("%+v %#v", m, m), value)
	// Errors are Read's.
	if _, err := a.ReadMetadata(ctx, ref("app/missing")); !errors.Is(err, stores.ErrNotFound) {
		t.Errorf("missing: %v", err)
	}
	f.setDown(true)
	_, err = a.ReadMetadata(ctx, ref("app/key"))
	f.setDown(false)
	if !errors.Is(err, stores.ErrUnavailable) {
		t.Errorf("outage: %v", err)
	}
	// Labels found through scrim's Set use the reader, not a value read.
	set := stores.NewSet()
	_ = set.Add(a)
	before = f.accesses
	if _, ok, err := set.Metadata(ctx, stores.MustParseRef("gsm://app/key#value")); !ok || err != nil {
		t.Fatalf("Set.Metadata: %v %v", ok, err)
	}
	if f.accesses != before {
		t.Errorf("Set.Metadata read the payload")
	}
}

func TestWriteLabels(t *testing.T) {
	f := newFake(t)
	a := adapterFor(t, f, nil)
	l := a.WriteLabels(ref("inbox/new"))
	if l["gcpsm.secret"] != "inbox--new" || l["gcpsm.project"] != f.project || l["gcpsm.location"] != "global" || l["gcpsm.path"] != "inbox/new" {
		t.Errorf("write labels %v", l)
	}
	if a.WriteLabels(ref("bad.name")) != nil {
		t.Errorf("labels for a reference that cannot be written")
	}
	// Writes never store gcpsm.* keys as annotations, and keep scrim.*.
	ctx := t.Context()
	_, err := a.Write(ctx, ref("x"), map[string]secret.Value{Field: secret.FromString("v")},
		stores.WriteOptions{Labels: map[string]string{"gcpsm.location": "evil", "scrim.hosts": "h.example.test"}})
	if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	ann := maps.Clone(f.secrets["projects/"+f.project+"/x"].annotations)
	f.mu.Unlock()
	if _, ok := ann["gcpsm.location"]; ok || ann["scrim.hosts"] != "h.example.test" {
		t.Errorf("stored annotations %v", ann)
	}
	// A rotation without labels keeps the annotations.
	if _, err := a.Write(ctx, ref("x"), map[string]secret.Value{Field: secret.FromString("v2")}, stores.WriteOptions{}); err != nil {
		t.Fatal(err)
	}
	m, _ := a.ReadMetadata(ctx, ref("x"))
	if m.Labels["scrim.hosts"] != "h.example.test" || m.Version != "2" {
		t.Errorf("after rotation: version %q labels %v", m.Version, m.Labels)
	}
}

func noValue(t *testing.T, text, value string) {
	t.Helper()
	if strings.Contains(text, value) {
		t.Errorf("output carries the value")
	}
}
