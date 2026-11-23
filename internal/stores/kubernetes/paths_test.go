// SPDX-License-Identifier: AGPL-3.0-only

package kubernetes

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/heliopsy/scrim/internal/stores"
)

func TestPaths(t *testing.T) {
	multi := New("k8s", Config{Namespaces: []string{"a", "b"}})
	one := New("k8s", Config{Namespace: "a"})
	for _, c := range []struct {
		a        *Adapter
		path     string
		ns, name string
	}{
		{multi, "a/db", "a", "db"},
		{multi, "b/tls/example/com", "b", "tls.example.com"},
		{one, "db", "a", "db"},
		{one, "sh/helm/release/v1/app/v3", "a", "sh.helm.release.v1.app.v3"},
	} {
		tg, err := c.a.secretTarget(stores.OpRead, stores.Ref{Scheme: "k8s", Path: c.path})
		if err != nil {
			t.Errorf("%s: %v", c.path, err)
			continue
		}
		if tg.ns != c.ns || tg.name != c.name {
			t.Errorf("%s: got %s/%s", c.path, tg.ns, tg.name)
		}
		if back := c.a.path(tg.ns, tg.name); back != c.path {
			t.Errorf("%s: maps back to %s", c.path, back)
		}
	}
	long := strings.Repeat("a/", 130) + "a"
	for _, p := range []string{"a/x.y", "a/X", "a/x_y", "a/-x", "c/db", "a", long} {
		if _, err := multi.secretTarget(stores.OpRead, stores.Ref{Scheme: "k8s", Path: p}); err == nil {
			t.Errorf("%s accepted", p)
		}
	}
}

func TestSelections(t *testing.T) {
	multi := New("k8s", Config{Namespaces: []string{"a", "b"}})
	one := New("k8s", Config{Namespace: "a"})
	names := []string{"app", "app.db", "app.db.x", "app-two", "apple", "other"}
	for _, c := range []struct {
		a    *Adapter
		path string
		ns   []string
		want []string
	}{
		{multi, "*", []string{"a", "b"}, names},
		{multi, "a", []string{"a"}, names},
		{multi, "a/*", []string{"a"}, names},
		{multi, "a/app", []string{"a"}, []string{"app", "app.db", "app.db.x"}},
		{multi, "a/app/*", []string{"a"}, []string{"app", "app.db", "app.db.x"}},
		{multi, "a/app*", []string{"a"}, []string{"app", "app.db", "app.db.x", "app-two", "apple"}},
		{multi, "a/app-*", []string{"a"}, []string{"app-two"}},
		{multi, "a/app/d*", []string{"a"}, []string{"app.db", "app.db.x"}},
		{one, "app/db", []string{"a"}, []string{"app.db", "app.db.x"}},
		{one, "ap*", []string{"a"}, []string{"app", "app.db", "app.db.x", "app-two", "apple"}},
	} {
		sel, err := c.a.selectionFor(stores.OpList, stores.Ref{Scheme: "k8s", Path: c.path})
		if err != nil {
			t.Errorf("%s: %v", c.path, err)
			continue
		}
		if !slices.Equal(sel.namespaces, c.ns) {
			t.Errorf("%s: namespaces %v", c.path, sel.namespaces)
		}
		var got []string
		for _, n := range names {
			if sel.match(n) {
				got = append(got, n)
			}
		}
		if !slices.Equal(got, c.want) {
			t.Errorf("%s: matched %v, want %v", c.path, got, c.want)
		}
	}
	for _, c := range []struct {
		path string
		kind error
	}{
		{"a*", stores.ErrInvalidRef},
		{"a/x*y", stores.ErrInvalidRef},
		{"a/X*", stores.ErrInvalidRef},
		{"c/db", stores.ErrPermission},
	} {
		if _, err := multi.selectionFor(stores.OpList, stores.Ref{Scheme: "k8s", Path: c.path}); !errors.Is(err, c.kind) {
			t.Errorf("%s: %v, want %v", c.path, err, c.kind)
		}
	}
}
