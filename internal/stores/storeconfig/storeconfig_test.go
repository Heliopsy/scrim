// SPDX-License-Identifier: AGPL-3.0-only

package storeconfig_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"go.yaml.in/yaml/v4"

	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/stores"
	_ "github.com/heliopsy/scrim/internal/stores/env"
	_ "github.com/heliopsy/scrim/internal/stores/memstore"
	"github.com/heliopsy/scrim/internal/stores/openbao"
	"github.com/heliopsy/scrim/internal/stores/storeconfig"
)

func build(t *testing.T, yaml string, environ ...string) (*config.Config, error) {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "scrim.yaml")
	if err := os.WriteFile(p, []byte("apiVersion: scrim.dev/v1\nkind: Config\n"+yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	return config.Build(config.Options{ConfigPaths: []string{p}, Environ: environ, SystemDir: dir})
}

const good = `
stores:
  bao:
    kind: openbao
    aliases: [bao-prod]
    address: http://127.0.0.1:1
    auth: {method: approle}
    role-id: env:BAO_ROLE
    secret-id: env:BAO_SECRET
    write-only-paths: [kv/inbox]
    redact: ["bao://kv/agents/*"]
    refresh: {interval: 1m, staleness: 30m}
  mem:
    kind: memory
`

func TestOpenBuildsAdaptersAndRefreshers(t *testing.T) {
	cfg, err := build(t, good, "BAO_ROLE=role-abcdef", "BAO_SECRET=sid-0123456789")
	if err != nil {
		t.Fatal(err)
	}
	o, err := storeconfig.Open(t.Context(), cfg, stores.DefaultRegistry)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = o.Close() }()
	if len(o.Refreshers) != 2 {
		t.Fatalf("%d refreshers", len(o.Refreshers))
	}
	a, err := o.Set.Lookup(stores.MustParseRef("bao-prod://kv/x"))
	if err != nil || a.Name() != "bao" {
		t.Fatalf("alias lookup: %v", err)
	}
	// The adapter resolves its credentials from the collection's secret
	// fields; the refresher's status names the store.
	if st := o.Refreshers[0].Status(); st.Store != "bao" {
		t.Fatalf("status %+v", st)
	}
	if _, ok := a.(*openbao.Adapter); !ok {
		t.Fatalf("adapter %T", a)
	}
}

func TestValidationNamesTheProblem(t *testing.T) {
	cases := map[string]string{
		"unknown kind":   "stores:\n  x:\n    kind: nosuch\n",
		"adapter typo":   "stores:\n  bao:\n    kind: openbao\n    adress: http://x\n    token: env:T\n",
		"refresh typo":   "stores:\n  bao:\n    kind: openbao\n    address: http://x\n    token: env:T\n    refresh: {intervall: 1m}\n",
		"foreign target": "stores:\n  bao:\n    kind: openbao\n    address: http://x\n    token: env:T\n    redact: [\"inf://p/e/*\"]\n",
		"missing kind":   "stores:\n  bao:\n    address: http://x\n",
		"glob on bao":    "stores:\n  bao:\n    kind: openbao\n    address: http://x\n    token: env:T\n    redact: [\"bao://kv/app-*\"]\n",
	}
	want := map[string]string{
		"unknown kind": "unknown store kind", "adapter typo": "did you mean address",
		"refresh typo": "did you mean refresh.interval", "foreign target": "names another store",
		"missing kind": "is required", "glob on bao": "bao://kv/app-*: store bao (capabilities read,list,watch,write) does not match names by a trailing *",
	}
	for name, yaml := range cases {
		_, err := build(t, yaml, "T=tok-0123456789")
		if err == nil || !strings.Contains(err.Error(), want[name]) {
			t.Errorf("%s: got %v, want %q", name, err, want[name])
		}
	}
}

func TestCredentialsAreMaskedAndResolved(t *testing.T) {
	const secretID = "sid-must-not-leak-0123456789"
	cfg, err := build(t, good, "BAO_ROLE=role-abcdef", "BAO_SECRET="+secretID)
	if err != nil {
		t.Fatal(err)
	}
	v, ok := cfg.SecretAt("stores.bao.secret-id")
	if !ok {
		t.Fatal("secret-id not resolved as a secret field")
	}
	_ = v.Expose(func(b []byte) error {
		if string(b) != secretID {
			t.Error("wrong value")
		}
		return nil
	})
	for _, inst := range storeconfig.Collection.Get(cfg) {
		if strings.Contains(inst.String("secret-id"), secretID) {
			t.Fatal("instance fields hold the resolved value")
		}
	}
}

// quickstart is the README configuration.
const quickstart = `
stores:
  local:
    kind: env
    prefix: SCRIM_SECRET_
    redact:
      - local://SCRIM_SECRET_*
`

func TestQuickstartGlobLoads(t *testing.T) {
	t.Setenv("SCRIM_SECRET_X", "val-"+strings.Repeat("q", 20))
	cfg, err := build(t, quickstart)
	if err != nil {
		t.Fatal(err)
	}
	o, err := storeconfig.Open(t.Context(), cfg, stores.DefaultRegistry)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = o.Close() }()
	r := o.Refreshers[0]
	if err := r.RefreshNow(t.Context()); err != nil {
		t.Fatal(err)
	}
	st := r.Status()
	if len(st.Targets) != 1 || st.Targets[0].Target != "local://SCRIM_SECRET_*" || st.Targets[0].Values < 1 {
		t.Fatalf("status %+v", st)
	}
}

// TestEmptyTargetNeedsTheWeakeningSetting: a redact target that matches
// nothing fails the first load, unless redaction.allow-empty-targets is on.
func TestEmptyTargetNeedsTheWeakeningSetting(t *testing.T) {
	yaml := strings.Replace(quickstart, "SCRIM_SECRET_*", "SCRIM_SECRET_NOTHING_HERE_*", 1)
	for _, allow := range []bool{false, true} {
		var env []string
		if allow {
			env = []string{"SCRIM_REDACTION_ALLOW_EMPTY_TARGETS=true"}
		}
		cfg, err := build(t, yaml, env...)
		if err != nil {
			t.Fatal(err)
		}
		if allow != storeconfig.AllowEmptyTargets.Get(cfg) {
			t.Fatalf("setting not read from %v", env)
		}
		o, err := storeconfig.Open(t.Context(), cfg, stores.DefaultRegistry)
		if err != nil {
			t.Fatal(err)
		}
		err = o.Refreshers[0].RefreshNow(t.Context())
		st := o.Refreshers[0].Status()
		_ = o.Close()
		if allow {
			if err != nil || st.State != "degraded" || st.Targets[0].Values != 0 {
				t.Fatalf("allowed: %v, %+v", err, st)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), "local://SCRIM_SECRET_NOTHING_HERE_*") {
			t.Fatalf("not allowed: %v", err)
		}
	}
}

func TestLabelMapping(t *testing.T) {
	cfg, err := build(t, `
stores:
  mem:
    kind: memory
    aliases: [m]
    labels:
      area: memory.top
      env: {value: prod}
      app: {from: store.path, regex: "^apps/([^/]+)/", value: "$1"}
`)
	if err != nil {
		t.Fatal(err)
	}
	o, err := storeconfig.Open(t.Context(), cfg, stores.DefaultRegistry)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = o.Close() }()
	got := o.Set.WriteLabels(stores.MustParseRef("m://apps/web/db#password"))
	for k, want := range map[string]string{
		"store.name": "mem", "store.kind": "memory", "store.path": "apps/web/db", "store.container": "apps/web",
		"store.field": "password", "memory.top": "apps", "area": "apps", "env": "prod", "app": "web",
	} {
		if got[k] != want {
			t.Errorf("%s = %q, want %q (all: %v)", k, got[k], want, got)
		}
	}
	for name, yaml := range map[string]string{
		"reserved store":  "stores:\n  mem:\n    kind: memory\n    labels: {store.kind: memory.top}\n",
		"reserved native": "stores:\n  mem:\n    kind: memory\n    labels: {memory.top: store.path}\n",
		"reserved other":  "stores:\n  mem:\n    kind: memory\n    labels: {env.prefix: store.path}\n",
		"bad regex":       "stores:\n  mem:\n    kind: memory\n    labels: {x: {from: store.path, regex: \"(\"}}\n",
	} {
		if _, err := build(t, yaml); err == nil {
			t.Errorf("%s: accepted", name)
		} else if !strings.Contains(err.Error(), "labels.") {
			t.Errorf("%s: error does not name the label: %v", name, err)
		}
	}
}

// TestDocsLabelMapping keeps the labels example in docs/policy.md valid.
func TestDocsLabelMapping(t *testing.T) {
	data, err := os.ReadFile("../../../docs/policy.md")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile("(?s)```yaml\n(# scrim.yaml.*?)```").FindSubmatch(data)
	if m == nil {
		t.Fatal("no configuration example in docs/policy.md")
	}
	var doc struct {
		Stores map[string]map[string]any `yaml:"stores"`
	}
	if err := yaml.Unmarshal(m[1], &doc); err != nil {
		t.Fatal(err)
	}
	for name, inst := range doc.Stores {
		kind, _ := inst["kind"].(string)
		lm, err := stores.ParseLabelMapping(kind, inst["labels"])
		if err != nil || len(lm) == 0 {
			t.Errorf("%s: %v (%d labels)", name, err, len(lm))
		}
	}
}

// TestRedactAddsTargets: a reference configuration uses as a secret value
// elsewhere (a database password) becomes a redact target of the store its
// scheme or alias names, as the whole secret, and loads with the store. A
// reference naming no store, or more than one secret, is refused.
func TestRedactAddsTargets(t *testing.T) {
	t.Setenv("SCRIM_DBREF_PW", "pw-"+strings.Repeat("r", 20))
	t.Setenv("SCRIM_DBREF_OTHER", "ot-"+strings.Repeat("s", 20))
	cfg, err := build(t, `
stores:
  local:
    kind: env
    aliases: [envs]
    prefix: SCRIM_DBREF_
    redact: ["local://SCRIM_DBREF_OTHER#value"]
`)
	if err != nil {
		t.Fatal(err)
	}
	o, err := storeconfig.OpenWith(t.Context(), cfg, stores.DefaultRegistry, storeconfig.Options{
		Redact: []string{"envs://SCRIM_DBREF_PW#value", "local://SCRIM_DBREF_OTHER", "local://SCRIM_DBREF_PW"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = o.Close() }()
	r := o.Refreshers[0]
	if err := r.RefreshNow(t.Context()); err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, ts := range r.Status().Targets {
		if ts.Values != 1 {
			t.Errorf("target %s holds %d values", ts.Target, ts.Values)
		}
		got = append(got, ts.Target)
	}
	if want := []string{"local://SCRIM_DBREF_OTHER", "local://SCRIM_DBREF_PW"}; strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("targets %v, want %v", got, want)
	}

	for raw, want := range map[string]string{
		"nosuch://kv/x":         "no configured store has the scheme nosuch",
		"local://SCRIM_DBREF_*": "must name one secret",
	} {
		_, err := storeconfig.OpenWith(t.Context(), cfg, stores.DefaultRegistry, storeconfig.Options{Redact: []string{raw}})
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: got %v, want %q", raw, err, want)
		}
	}
}
