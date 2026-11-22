// SPDX-License-Identifier: AGPL-3.0-only

package stores_test

import (
	"maps"
	"testing"

	"github.com/heliopsy/scrim/internal/stores"
	"github.com/heliopsy/scrim/internal/stores/memstore"
)

func TestLabelKey(t *testing.T) {
	for in, want := range map[string]string{
		"Collection":   "collection",
		"a..b.":        "a.b",
		"Team Name/x":  "team_name_x",
		"ünï":          "_n_",
		"":             "",
		"...":          "",
		"db-host_1.Ok": "db-host_1.ok",
	} {
		if got := stores.LabelKey(in); got != want {
			t.Errorf("LabelKey(%q) = %q, want %q", in, got, want)
		}
	}
	if got := stores.NativeKey("VaultWarden", "Org"); got != "vaultwarden.org" {
		t.Errorf("NativeKey = %q", got)
	}
	if got := stores.NativeKey("", "org"); got != "" {
		t.Errorf("NativeKey without kind = %q", got)
	}
}

func TestSetNative(t *testing.T) {
	stores.DeclareMulti("labeltest", "collection")
	l := map[string]string{}
	stores.SetNative(l, "labeltest", "org", "Acme")
	stores.SetNative(l, "labeltest", "collection", "Prod")
	stores.SetNative(l, "labeltest", "folder", "X", "Y", "X", "")
	stores.SetNative(l, "labeltest", "empty")
	stores.SetNative(l, "labeltest", "meta.forged", "true")
	want := map[string]string{
		"labeltest.org":             "Acme",
		"labeltest.collection":      "Prod",
		"labeltest.collection.Prod": "true",
		"labeltest.folder":          "X,Y",
		"labeltest.folder.X":        "true",
		"labeltest.folder.Y":        "true",
	}
	if !maps.Equal(l, want) {
		t.Fatalf("labels = %v, want %v", l, want)
	}
	if !stores.IsMulti("labeltest", "Collection") || stores.IsMulti("labeltest", "org") {
		t.Fatal("IsMulti")
	}
}

// User metadata can never forge a native label: it lands under
// <kind>.meta., and neither order of calls lets it replace a native key.
func TestUserMetaCannotForgeNative(t *testing.T) {
	l := map[string]string{}
	stores.UserMeta(l, "labeltest", "labeltest.org", "Evil")
	stores.UserMeta(l, "labeltest", "org", "Evil")
	stores.SetNative(l, "labeltest", "org", "Acme")
	stores.UserMeta(l, "labeltest", "Owner", "alice")
	stores.UserMeta(l, "labeltest", "owner", "mallory")
	stores.UserMeta(l, "labeltest", "", "x")
	want := map[string]string{
		"labeltest.org":                "Acme",
		"labeltest.meta.org":           "Evil",
		"labeltest.meta.labeltest.org": "Evil",
		"labeltest.meta.owner":         "alice",
	}
	if !maps.Equal(l, want) {
		t.Fatalf("labels = %v, want %v", l, want)
	}
	// A native attribute set after user metadata replaces a same-named key.
	l = map[string]string{"labeltest.org": "Evil"}
	stores.SetNative(l, "labeltest", "org", "Acme")
	if l["labeltest.org"] != "Acme" {
		t.Fatalf("native did not win: %v", l)
	}
}

func TestGenericLabels(t *testing.T) {
	got := stores.GenericLabels("vw", "vaultwarden", stores.MustParseRef("vw-alias://Prod/db/main?version=2#password"))
	want := map[string]string{
		"store.name": "vw", "store.kind": "vaultwarden", "store.path": "Prod/db/main",
		"store.container": "Prod/db", "store.field": "password",
	}
	if !maps.Equal(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	got = stores.GenericLabels("env", "", stores.MustParseRef("env://TOKEN"))
	want = map[string]string{"store.name": "env", "store.path": "TOKEN", "store.container": ""}
	if !maps.Equal(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func mapping(t *testing.T, kind string, raw map[string]any) stores.LabelMapping {
	t.Helper()
	m, err := stores.ParseLabelMapping(kind, raw)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestComposeLabels(t *testing.T) {
	native := map[string]string{
		"labeltest.org":             "Acme",
		"labeltest.collection":      "Prod,Shared",
		"labeltest.collection.Prod": "true",
		"labeltest.path":            "prod/app/db",
		"labeltest.meta.team":       "forged",
		"store.name":                "forged", // an adapter cannot set store.*
		"memory.top":                "forged", // nor speak for another kind
		"scrim.hosts":               "api.example.test",
	}
	m := mapping(t, "labeltest", map[string]any{
		"team":   "labeltest.org",
		"env":    map[string]any{"value": "prod"},
		"isprod": map[string]any{"from": "labeltest.collection.Prod", "value": "yes"},
		"isdev":  map[string]any{"from": "labeltest.collection.Dev", "value": "yes"},
		"tier":   map[string]any{"from": "labeltest.path", "regex": "^prod/", "value": "prod"},
		"app":    map[string]any{"from": "store.path", "regex": "^prod/([^/]+)/", "value": "$1"},
		"top":    map[string]any{"from": "labeltest.path", "regex": "^[a-z]+"},
		"nope":   map[string]any{"from": "labeltest.path", "regex": "^dev/", "value": "x"},
	})
	got := stores.ComposeLabels("vw", "labeltest", stores.MustParseRef("vw://prod/app/db#password"), native, m)
	want := map[string]string{
		"labeltest.org": "Acme", "labeltest.collection": "Prod,Shared", "labeltest.collection.Prod": "true",
		"labeltest.path": "prod/app/db", "labeltest.meta.team": "forged", "scrim.hosts": "api.example.test",
		"store.name": "vw", "store.kind": "labeltest", "store.path": "prod/app/db", "store.container": "prod/app",
		"store.field": "password",
		"team":        "Acme", "env": "prod", "isprod": "yes", "tier": "prod", "app": "app", "top": "prod",
	}
	if !maps.Equal(got, want) {
		t.Fatalf("got  %v\nwant %v", got, want)
	}
	if native["store.name"] != "forged" {
		t.Fatal("ComposeLabels modified its input")
	}
}

// A derived label never replaces a native or store.* label, even when the
// operator's mapping names one (config validation refuses such names too)
// and its source is user-editable metadata.
func TestMappingCannotOverwriteNative(t *testing.T) {
	m := stores.LabelMapping{
		"labeltest.org": {From: "labeltest.meta.org"},
		"store.kind":    {From: "labeltest.meta.org"},
		"fresh":         {From: "labeltest.meta.org"},
	}
	native := map[string]string{"labeltest.org": "Acme"}
	stores.UserMeta(native, "labeltest", "org", "Evil")
	got := stores.ComposeLabels("vw", "labeltest", stores.MustParseRef("vw://x"), native, m)
	if got["labeltest.org"] != "Acme" || got["store.kind"] != "labeltest" || got["fresh"] != "Evil" {
		t.Fatalf("labels = %v", got)
	}
}

func TestParseLabelMappingRejects(t *testing.T) {
	for name, raw := range map[string]any{
		"store.kind":    "x",
		"scrim.hosts":   "x",
		"labeltest.org": "x",
		"memory.top":    "x",
		"Team":          "x",
		"empty":         "",
		"nofrom":        map[string]any{"regex": "x"},
		"nothing":       map[string]any{},
		"badregex":      map[string]any{"from": "a", "regex": "("},
		"unknown":       map[string]any{"from": "a", "to": "b"},
		"notstring":     map[string]any{"from": 3},
		"list":          []any{"a"},
	} {
		if _, err := stores.ParseLabelMapping("labeltest", map[string]any{name: raw}); err == nil {
			t.Errorf("%s: accepted %v", name, raw)
		}
	}
	if _, err := stores.ParseLabelMapping("labeltest", "team"); err == nil {
		t.Error("accepted a non-map")
	}
	if m, err := stores.ParseLabelMapping("labeltest", nil); err != nil || m != nil {
		t.Errorf("nil: %v %v", m, err)
	}
}

func TestSetLabels(t *testing.T) {
	set := stores.NewSet()
	if err := set.Add(memstore.New("mem"), "mem-alias"); err != nil {
		t.Fatal(err)
	}
	set.SetLabeling("mem", memstore.Kind, mapping(t, memstore.Kind, map[string]any{"area": "memory.top"}))
	got := set.Labels(stores.MustParseRef("mem-alias://team/x"), map[string]string{"memory.top": "team"})
	if got["store.name"] != "mem" || got["store.kind"] != "memory" || got["area"] != "team" {
		t.Fatalf("labels = %v", got)
	}
	// A new item gets the adapter's WriteLabels.
	got = set.WriteLabels(stores.MustParseRef("mem://ops/new"))
	if got["memory.top"] != "ops" || got["area"] != "ops" || got["store.container"] != "ops" {
		t.Fatalf("write labels = %v", got)
	}
}
