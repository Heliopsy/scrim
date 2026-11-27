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
	// Absolute on this platform: /var/lib is not absolute on Windows, and
	// OwnPaths leaves relative paths out.
	db0 := filepath.Join(w.dir, "lib", "state.db")
	root := filepath.Join(w.dir, "srv", "secrets")
	token := filepath.Join(w.dir, "run", "token")
	cfgFile := w.file("c.yaml", header+`
interception.ca-key: file:`+ca+`
stores.openbao.token: env:BAO_TOKEN
policy.rules-file: /etc/scrim/rules.yaml
state.sqlite.path: '`+db0+`'
notifiers:
  ops:
    kind: slack
    token: file:`+slack+`
vaults:
  vw:
    unlock: file:`+unlock+`
  files:
    root: '`+root+`'
    auth:
      token-file: '`+token+`'
  rel:
    root: relative/dir
`)
	w.setenv("BAO_TOKEN=x", "XDG_STATE_HOME="+filepath.Join(w.dir, "state"))
	c := w.build(cfgFile)
	if got := db.Get(c); got != db0 {
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
		db0:                                 "state.sqlite.path",
		db0 + "-wal":                        "state.sqlite.path",
		root:                                "vaults.files.root",
		token:                               "vaults.files.auth.token-file",
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

// TestOwnPathsKeyMaterialWhen: a key-material setting with a default path
// counts only while the feature that reads it is on. A pod's service account
// token at its default path is not scrim's own file unless scrim uses it.
func TestOwnPathsKeyMaterialWhen(t *testing.T) {
	w := newWorld(t)
	tokenDefault := filepath.Join(w.dir, "sa", "token")
	enabled := config.MustRegisterIn(w.reg, config.Spec[bool]{Key: "identity.kube.enabled", Description: "Feature."})
	config.MustRegisterIn(w.reg, config.Spec[string]{
		Key: "identity.kube.token-file", KeyMaterial: true, Default: tokenDefault,
		KeyMaterialWhen: func(c *config.Config) bool { return enabled.Get(c) },
		Description:     "Token read only with the feature on.",
	})
	has := func(c *config.Config) bool {
		for _, p := range c.OwnPaths() {
			if p.Path == tokenDefault {
				if p.Origin != "identity.kube.token-file" {
					t.Errorf("origin %q", p.Origin)
				}
				return true
			}
		}
		return false
	}
	if has(w.build()) {
		t.Error("default token path listed with the feature off")
	}
	w.setenv("SCRIM_IDENTITY_KUBE_ENABLED=true")
	if !has(w.build()) {
		t.Error("token path not listed with the feature on")
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
	if _, err := config.RegisterIn(r, config.Spec[string]{Key: "a.d", KeyMaterialWhen: func(*config.Config) bool { return true }, Description: "x"}); err == nil {
		t.Error("KeyMaterialWhen accepted without KeyMaterial")
	}
}
