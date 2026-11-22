// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"context"
	"testing"

	"github.com/heliopsy/scrim/internal/catalog"
	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/localapi"
	"github.com/heliopsy/scrim/internal/secret"
)

func TestProjectValuesAreRedactedUntilTheSessionEnds(t *testing.T) {
	v1, v2 := seed(t, "proj-a-"), seed(t, "proj-b-")
	applied := 0
	p := newProjectValues(func(context.Context) error { applied++; return nil })
	cfg := buildConfig(t, "proxy:\n  listen: 127.0.0.1:9790\n")
	b := &SnapshotBuilder{Config: func() *config.Config { return cfg }, Values: []ValueSource{p},
		Catalog: func() *catalog.Catalog { return nil }}
	b.SetKeys(testRing(t))

	a := secret.FromString(v1)
	err := p.set(context.Background(), "sess-1", []localapi.NamedValue{
		{Name: ".env#OPENAI_API_KEY", Value: a},
		{Name: "config/app.yaml#password", Value: secret.FromString(v2)},
	})
	if err != nil || applied != 1 {
		t.Fatalf("set: %v, applied %d times, want once before returning", err, applied)
	}
	s, err := b.Build(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	byVal := map[string]string{}
	for _, e := range s.GetValues() {
		if len(e.GetBoundHosts()) != 0 || len(e.GetDeclaredPlaceholders()) != 0 {
			t.Errorf("project value %s is injectable", e.GetRef())
		}
		byVal[string(e.GetValue())] = e.GetRef()
	}
	if byVal[v1] != "project://.env#OPENAI_API_KEY" || byVal[v2] != "project://config/app.yaml#password" {
		t.Fatalf("snapshot refs = %v", byVal)
	}

	// A new set for the session replaces and wipes the old one.
	if err := p.set(context.Background(), "sess-1", []localapi.NamedValue{{Name: ".env#OPENAI_API_KEY", Value: secret.FromString(v2)}}); err != nil {
		t.Fatal(err)
	}
	if !a.Wiped() {
		t.Error("the replaced value was not wiped")
	}
	if !p.prune(func(string) bool { return false }) {
		t.Fatal("prune of an ended session reported nothing")
	}
	s, _ = b.Build(context.Background())
	if n := len(s.GetValues()); n != 0 {
		t.Errorf("%d values left after the session ended", n)
	}
}
