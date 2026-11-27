// SPDX-License-Identifier: AGPL-3.0-only

package config_test

import (
	"path/filepath"
	"testing"

	"github.com/heliopsy/scrim/internal/config"
)

// TestOwnPaths: file: references (settings and collection secret fields),
// key-material settings with their companions, key-material collection
// fields, the state directory and the config files are listed by path, each
// once; literals, env: references and relative paths are not.
func TestOwnPaths(t *testing.T) {
	w := newWorld(t)
	db := config.MustRegisterIn(w.reg, config.Spec[string]{
		Key: "state.sqlite.path", KeyMaterial: true, Companions: []string{"-wal"},
		Description: "SQLite state file.",
	})
	config.MustRegisterIn(w.reg, config.Spec[string]{Key: "policy.rules-file", Description: "Not key material."})
	_, err := config.RegisterCollectionIn(w.reg, config.CollectionSpec{
		Key: "vaults", Description: "Vaults.", SecretFields: []string{"unlock"},
		KeyMaterialFields: []string{"root", "auth.token-file"},
	})
	if err != nil {
		t.Fatal(err)
	}
	slack := w.file("secrets/slack", "x")
	unlock := w.file("secrets/vw-master", "x")
	ca := w.file("secrets/ca.key", "x")
	cfgFile := w.file("c.yaml", header+`
interception.ca-key: file:`+ca+`
stores.openbao.token: env:BAO_TOKEN
policy.rules-file: /etc/scrim/rules.yaml
state.sqlite.path: /var/lib/scrim/state.db
notifiers:
  ops:
    kind: slack
    token: file:`+slack+`
vaults:
  vw:
    unlock: file:`+unlock+`
  files:
    root: /srv/secrets
    auth:
      token-file: /run/token
  rel:
    root: relative/dir
`)
	w.setenv("BAO_TOKEN=x", "XDG_STATE_HOME="+filepath.Join(w.dir, "state"))
	c := w.build(cfgFile)
	if got := db.Get(c); got != "/var/lib/scrim/state.db" {
		t.Fatalf("state.sqlite.path = %q", got)
	}
	got := map[string]string{}
	for _, p := range c.OwnPaths() {
		if _, dup := got[p.Path]; dup {
			t.Errorf("%s listed twice", p.Path)
		}
		got[p.Path] = p.Origin
	}
	want := map[string]string{
		ca:                                  "interception.ca-key",
		slack:                               "notifiers.ops.token",
		unlock:                              "vaults.vw.unlock",
		"/var/lib/scrim/state.db":           "state.sqlite.path",
		"/var/lib/scrim/state.db-wal":       "state.sqlite.path",
		"/srv/secrets":                      "vaults.files.root",
		"/run/token":                        "vaults.files.auth.token-file",
		filepath.Join(w.dir, "state/scrim"): config.OwnOriginStateDir,
		cfgFile:                             config.OwnOriginConfigFile,
	}
	for p, o := range want {
		if got[p] != o {
			t.Errorf("%s: origin %q, want %q", p, got[p], o)
		}
	}
	for p := range got {
		if _, ok := want[p]; !ok {
			t.Errorf("unexpected own path %s (%s)", p, got[p])
		}
	}
}

// TestKeyMaterialOnlyForStrings: KeyMaterial and Companions are refused
// where they make no sense.
func TestKeyMaterialOnlyForStrings(t *testing.T) {
	r := config.NewRegistry()
	if _, err := config.RegisterIn(r, config.Spec[bool]{Key: "a.b", KeyMaterial: true, Description: "x"}); err == nil {
		t.Error("KeyMaterial accepted on a bool setting")
	}
	if _, err := config.RegisterIn(r, config.Spec[string]{Key: "a.c", Companions: []string{"-wal"}, Description: "x"}); err == nil {
		t.Error("Companions accepted without KeyMaterial")
	}
}
