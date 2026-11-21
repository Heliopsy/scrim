// SPDX-License-Identifier: AGPL-3.0-only

package stores_test

import (
	"maps"
	"testing"

	"github.com/heliopsy/scrim/internal/stores"
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
