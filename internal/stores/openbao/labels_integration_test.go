// SPDX-License-Identifier: AGPL-3.0-only

package openbao_test

import (
	"strings"
	"testing"

	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores"
	"github.com/heliopsy/scrim/internal/stores/openbao"
)

// labelsPolicy may do everything scrim does under kv-labels/prod, metadata
// included. dataOnlyPolicy may read data and nothing else, so every label
// lookup is refused.
const (
	labelsPolicy = `
path "kv-labels/data/prod/*"              { capabilities = ["create", "read", "update"] }
path "kv-labels/metadata/prod/*"          { capabilities = ["list", "read", "update"] }
path "kv-labels/detailed-metadata/prod/*" { capabilities = ["list"] }
`
	dataOnlyPolicy = `
path "kv-labels/data/prod/*" { capabilities = ["read"] }
`
)

func (s *server) tokenAdapter(t *testing.T, name, policy string) *openbao.Adapter {
	t.Helper()
	if _, err := s.api("PUT", "sys/policies/acl/"+name, map[string]any{"policy": policy}); err != nil {
		t.Fatal(err)
	}
	tok, err := s.api("POST", "auth/token/create", map[string]any{"policies": []string{name}, "ttl": "10m"})
	if err != nil {
		t.Fatal(err)
	}
	client, _ := tok["auth"].(map[string]any)["client_token"].(string)
	a, err := openbao.New(stores.Instance{
		Name: name, Kind: openbao.Kind,
		Options: map[string]any{"address": s.addr, "auth.method": "token", "token": "test:token"},
		Resolve: resolver(map[string]string{"test:token": client}),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	return a
}

func TestNativeLabelsLive(t *testing.T) {
	s := startServer(t)
	if _, err := s.api("POST", "sys/mounts/kv-labels", map[string]any{
		"type": "kv", "description": "Production, team Payments", "options": map[string]string{"version": "2"},
	}); err != nil && !strings.Contains(err.Error(), "HTTP 400") {
		t.Fatal(err)
	}
	p := "prod/eu/db-" + randHex(t, 4)
	value := "pw_" + randHex(t, 16)
	if _, err := s.api("POST", "kv-labels/metadata/"+p, map[string]any{
		"max_versions": 5, "cas_required": false, "delete_version_after": "720h",
		"custom_metadata": map[string]string{"team": "payments", "scrim.hosts": "db.example.test", "openbao.mount": "kv-dev"},
	}); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err := s.api("POST", "kv-labels/data/"+p, map[string]any{"data": map[string]string{"password": value}}); err != nil {
			t.Fatal(err)
		}
	}
	ref := stores.Ref{Scheme: "bao-labels", Path: "kv-labels/" + p}
	noValue := func(where string, l map[string]string) {
		t.Helper()
		for k, v := range l {
			if strings.Contains(k, value) || strings.Contains(v, value) {
				t.Errorf("%s: label %q carries the value", where, k)
			}
		}
	}
	want := map[string]string{
		"openbao.mount": "kv-labels", "openbao.engine": "kv-v2", "openbao.path": p,
		"openbao.ancestors.prod": "true", "openbao.ancestors.prod/eu": "true", "openbao.folder": "prod/eu",
		"openbao.mount_type": "kv", "openbao.mount_version": "2", "openbao.mount_description": "Production, team Payments",
		"openbao.version": "2", "openbao.current_version": "2", "openbao.oldest_version": "-",
		"openbao.max_versions": "5", "openbao.cas_required": "false", "openbao.delete_version_after": "720h0m0s",
		"openbao.versions": "2", "openbao.destroyed": "false",
		"openbao.meta.team": "payments", "scrim.hosts": "db.example.test", "openbao.meta.openbao.mount": "kv-dev",
	}
	check := func(where string, l map[string]string, want map[string]string) {
		t.Helper()
		noValue(where, l)
		for k, v := range want {
			g, ok := l[k]
			if v == "-" {
				if ok {
					t.Errorf("%s: label %s = %q, want it absent", where, k, g)
				}
				continue
			}
			if g != v {
				t.Errorf("%s: label %s = %q, want %q", where, k, g, v)
			}
		}
		for _, k := range []string{"openbao.created_time", "openbao.updated_time", "openbao.version_created_time", "openbao.deletion_time"} {
			if v, ok := want[k]; ok && v == "-" {
				continue
			}
			if l[k] == "" {
				t.Errorf("%s: label %s missing", where, k)
			}
		}
	}

	full := s.tokenAdapter(t, "bao-labels", labelsPolicy)
	got, err := full.Read(t.Context(), ref)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	got.Wipe()
	check("Read", got.Meta.Labels, want)
	ms, err := full.List(t.Context(), stores.Ref{Scheme: "bao-labels", Path: "kv-labels/prod"})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	found := false
	for _, m := range ms {
		if m.Ref.Path == ref.Path {
			found = true
			check("List", m.Labels, want)
		}
	}
	if !found {
		t.Fatalf("List: %s missing", ref)
	}
	m, err := full.Write(t.Context(), ref, map[string]secret.Value{"password": secret.FromString(value)}, stores.WriteOptions{})
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	noValue("Write", m.Labels)
	if m.Labels["openbao.version"] != "3" || m.Labels["openbao.mount_type"] != "kv" {
		t.Errorf("Write labels %v", m.Labels)
	}

	// A token that may read the data and nothing else still reads the
	// secret; the labels that need metadata are missing.
	thin := s.tokenAdapter(t, "bao-labels-thin", dataOnlyPolicy)
	got, err = thin.Read(t.Context(), ref)
	if err != nil {
		t.Fatalf("Read with every label lookup refused: %v", err)
	}
	if v, ok := got.Field("password"); !ok || v.IsZero() {
		t.Error("value missing")
	}
	got.Wipe()
	check("Read (data only)", got.Meta.Labels, map[string]string{
		"openbao.mount": "kv-labels", "openbao.path": p, "openbao.ancestors.prod/eu": "true",
		"openbao.version": "3", "openbao.destroyed": "false", "openbao.meta.team": "payments",
		"scrim.hosts":             "db.example.test",
		"openbao.current_version": "-", "openbao.max_versions": "-", "openbao.created_time": "-",
		"openbao.updated_time": "-",
		// sys/internal/ui/mounts answers any token with a capability under
		// the mount, so mount labels survive a data-only policy.
		"openbao.mount_type": "kv", "openbao.mount_description": "Production, team Payments",
	})
}
