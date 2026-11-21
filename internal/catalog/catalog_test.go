// SPDX-License-Identifier: AGPL-3.0-only

package catalog

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores"
	"github.com/heliopsy/scrim/internal/stores/memstore"
)

func randHex(t *testing.T, n int) string {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

func file(name string) Source { return Source{Kind: SourceFile, Where: name} }

func compile(t *testing.T, sel Selection, entries ...Entry) *Catalog {
	t.Helper()
	c, err := Compile(Input{Entries: entries}, sel)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestLogicalNameEverywhere(t *testing.T) {
	c := compile(t, Selection{}, Entry{
		Name: "github", Ref: "bao://kv/agents/github#token", Hosts: []string{"api.github.com"},
		Placeholder: "SCRIM_GITHUB_TOKEN", Tools: []string{"gh"}, Source: file("a.yaml"),
	})
	for _, s := range []string{"github", "SCRIM_GITHUB_TOKEN", "{{scrim:bao://kv/agents/github#token}}", "bao://kv/agents/github#token"} {
		b, err := c.Lookup(s)
		if err != nil {
			t.Fatalf("%s: %v", s, err)
		}
		if b.Ref.String() != "bao://kv/agents/github#token" || !b.AllowsHost("api.github.com") || b.AllowsHost("evil.example") {
			t.Fatalf("%s: binding %+v", s, b)
		}
	}
	// Another field of the same secret inherits the binding, with its own field.
	b, _ := c.Lookup("{{scrim:bao://kv/agents/github#other}}")
	if b.Ref.Field != "other" || !b.Injectable() {
		t.Fatalf("field variant: %+v", b)
	}
	if _, err := c.Lookup("gitlab"); !errors.Is(err, ErrUnknown) {
		t.Fatalf("unknown name: %v", err)
	}
	if _, err := c.Lookup("SCRIM_NOPE"); !errors.Is(err, ErrUnknown) {
		t.Fatalf("unknown placeholder: %v", err)
	}
}

func TestReferencePlaceholderWithoutCatalog(t *testing.T) {
	c := Empty(Selection{})
	b, err := c.Lookup("{{scrim:bao://kv/agents/github#token}}")
	if err != nil {
		t.Fatal(err)
	}
	if b.Ref.String() != "bao://kv/agents/github#token" {
		t.Fatalf("ref %s", b.Ref)
	}
	if b.Injectable() {
		t.Fatal("a reference placeholder without a host binding must not be injectable")
	}
	if _, _, err := ParseReferencePlaceholder("{{scrim:nope}}"); err == nil {
		t.Fatal("malformed reference placeholder accepted")
	}
	if _, ok, _ := ParseReferencePlaceholder("SCRIM_X"); ok {
		t.Fatal("declared placeholder parsed as a reference placeholder")
	}
	if got := ReferencePlaceholder(stores.MustParseRef("bao://kv/a#b")); got != "{{scrim:bao://kv/a#b}}" {
		t.Fatal(got)
	}
}

func TestLiteralValueFailsValidation(t *testing.T) {
	gh := "ghp_" + strings.Repeat("A", 4) + randHex(t, 16)
	random := "Zq8" + randHex(t, 12) + "XkP9" // high entropy, no separators
	cases := map[string]Entry{
		"ref is a token":         {Name: "x", Ref: gh},
		"ref hides a token":      {Name: "x", Ref: "env://" + gh},
		"random path segment":    {Name: "x", Ref: "bao://kv/" + random},
		"profile ref is literal": {Name: "x", Profiles: map[string]string{"dev": gh}},
		"host is a token":        {Name: "x", Ref: "bao://kv/x", Hosts: []string{gh}},
		"placeholder is literal": {Name: "x", Ref: "bao://kv/x", Placeholder: "AKIA" + strings.ToUpper(randHex(t, 8))},
		"plain literal ref":      {Name: "x", Ref: "hunter2-" + randHex(t, 4)},
	}
	for name, e := range cases {
		e.Source = file("c.yaml")
		_, err := Compile(Input{Entries: []Entry{e}}, Selection{})
		if !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: want ErrInvalid, got %v", name, err)
			continue
		}
		for _, lit := range []string{gh, random, e.Ref} {
			if lit != "" && strings.Contains(err.Error(), lit) && !strings.Contains(lit, "://") {
				t.Errorf("%s: error quotes the literal: %v", name, err)
			}
		}
	}

	// A value written into a catalog file under any key is refused and the
	// file is not loaded.
	doc := "apiVersion: " + config.APIVersion + "\nkind: Catalog\nentries:\n  github:\n    ref: bao://kv/agents/github#token\n    value: " + gh + "\n"
	_, err := ParseFile("cat.yaml", []byte(doc))
	if !errors.Is(err, ErrInvalid) || strings.Contains(err.Error(), gh) {
		t.Fatalf("value key: %v", err)
	}
	doc = "apiVersion: " + config.APIVersion + "\nkind: Catalog\nentries:\n  github:\n    ref: " + gh + "\n"
	if _, err := ParseFile("cat.yaml", []byte(doc)); !errors.Is(err, ErrInvalid) || strings.Contains(err.Error(), gh) {
		t.Fatalf("literal ref: %v", err)
	}
}

func TestPerProfileMapping(t *testing.T) {
	e := Entry{
		Name: "db", Placeholder: "SCRIM_DB_PASSWORD", Hosts: []string{"db.internal"},
		Profiles: map[string]string{"dev": "bao://kv/dev/db#password", "prod": "aws-sm://prod/db#password"},
		Source:   file("c.yaml"),
	}
	dev := compile(t, Selection{Profile: "dev"}, e)
	prod := compile(t, Selection{Profile: "prod"}, e)
	bd, err := dev.Placeholder("SCRIM_DB_PASSWORD")
	if err != nil || bd.Ref.String() != "bao://kv/dev/db#password" || bd.Selected != "profile=dev" {
		t.Fatalf("dev: %+v %v", bd, err)
	}
	bp, _ := prod.Placeholder("SCRIM_DB_PASSWORD")
	if bp.Ref.String() != "aws-sm://prod/db#password" {
		t.Fatalf("prod: %+v", bp)
	}
	// The dev session never gets the production reference, not even by
	// naming it as a reference placeholder.
	if b := dev.Ref(stores.MustParseRef("aws-sm://prod/db#password")); b.Injectable() {
		t.Fatal("dev session binds the production secret")
	}
	// No profile and no default: unresolved, never a fallback to prod.
	none := compile(t, Selection{Profile: "staging"}, e)
	if _, err := none.Placeholder("SCRIM_DB_PASSWORD"); !errors.Is(err, ErrUnresolved) {
		t.Fatalf("staging: %v", err)
	}
	if len(none.Placeholders()) != 0 {
		t.Fatal("unresolved placeholder listed")
	}
}

func TestVariantSpecificity(t *testing.T) {
	e := Entry{
		Name: "deploy", Ref: "bao://kv/default/deploy", Source: file("c.yaml"),
		Variants: []Variant{
			{When: map[string]string{KeyProfile: "prod"}, Ref: "bao://kv/prod/deploy"},
			{When: map[string]string{KeyProfile: "prod", KeyAgent: "ci"}, Ref: "bao://kv/prod/ci-deploy"},
			{When: map[string]string{KeyNamespace: "build"}, Ref: "bao://kv/build/deploy"},
		},
	}
	for sel, want := range map[Selection]string{
		{}:                             "bao://kv/default/deploy",
		{Profile: "prod"}:              "bao://kv/prod/deploy",
		{Profile: "prod", Agent: "ci"}: "bao://kv/prod/ci-deploy",
		{Namespace: "build"}:           "bao://kv/build/deploy",
	} {
		b, err := compile(t, sel, e).Name("deploy")
		if err != nil || b.Ref.String() != want {
			t.Errorf("%s: got %s %v, want %s", sel, b.Ref, err, want)
		}
	}
	// Profile prod and namespace build both match with one key: ambiguous.
	if _, err := Compile(Input{Entries: []Entry{e}}, Selection{Profile: "prod", Namespace: "build"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("tie: %v", err)
	}
	dup := e
	dup.Profiles = map[string]string{"prod": "bao://kv/x"}
	if _, err := Compile(Input{Entries: []Entry{dup}}, Selection{}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("profile set twice: %v", err)
	}
	bad := Entry{Name: "x", Source: file("c"), Variants: []Variant{{When: map[string]string{"region": "eu"}, Ref: "bao://kv/x"}}}
	if _, err := Compile(Input{Entries: []Entry{bad}}, Selection{}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unknown key: %v", err)
	}
}

func listing(refs ...string) []stores.Metadata {
	var out []stores.Metadata
	for _, r := range refs {
		out = append(out, stores.Metadata{Ref: stores.MustParseRef(r)})
	}
	return out
}

func TestBulkPrefixMapping(t *testing.T) {
	bulk := Entry{Name: "acme", Prefix: "inf://acme/prod/*", Template: "SCRIM_ACME_{NAME}", Hosts: []string{"api.acme.example"}, Source: file("c.yaml")}
	in := Input{
		Entries:  []Entry{bulk},
		Listings: map[string][]stores.Metadata{"inf://acme/prod/*": listing("inf://acme/prod/API_KEY", "inf://acme/prod/webhook-secret")},
	}
	c, err := Compile(in, Selection{})
	if err != nil {
		t.Fatal(err)
	}
	for ph, ref := range map[string]string{"SCRIM_ACME_API_KEY": "inf://acme/prod/API_KEY", "SCRIM_ACME_WEBHOOK_SECRET": "inf://acme/prod/webhook-secret"} {
		b, err := c.Placeholder(ph)
		if err != nil || b.Ref.String() != ref || !b.AllowsHost("api.acme.example") {
			t.Errorf("%s: %+v %v", ph, b, err)
		}
	}

	// Two keys deriving the same name collide.
	in.Listings["inf://acme/prod/*"] = listing("inf://acme/prod/API_KEY", "inf://acme/prod/api-key")
	if _, err := Compile(in, Selection{}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("colliding keys: %v", err)
	}
	// A derived placeholder colliding with a declared one fails and names both.
	in.Listings["inf://acme/prod/*"] = listing("inf://acme/prod/API_KEY")
	in.Entries = append(in.Entries, Entry{Name: "other", Ref: "bao://kv/other", Placeholder: "SCRIM_ACME_API_KEY", Source: file("d.yaml")})
	_, err = Compile(in, Selection{})
	if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), `"other"`) || !strings.Contains(err.Error(), `"acme/API_KEY"`) {
		t.Fatalf("collision with a declared placeholder: %v", err)
	}
	// Two templates over overlapping prefixes collide.
	in.Entries = []Entry{bulk, {Name: "acme2", Prefix: "inf://acme/prod/*", Template: "SCRIM_ACME_{NAME}", Source: file("e.yaml")}}
	if _, err := Compile(in, Selection{}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("colliding templates: %v", err)
	}
	for _, e := range []Entry{
		{Name: "b", Prefix: "inf://acme/prod", Template: "SCRIM_{NAME}"},
		{Name: "b", Prefix: "inf://acme/prod/*", Template: "SCRIM_ACME"},
		{Name: "b", Prefix: "inf://acme/prod/*", Template: "SCRIM_{NAME}", Placeholder: "SCRIM_X"},
	} {
		e.Source = file("f")
		if _, err := Compile(Input{Entries: []Entry{e}}, Selection{}); !errors.Is(err, ErrInvalid) {
			t.Errorf("%+v accepted", e)
		}
	}
	// No listing: a warning, not an error.
	c, err = Compile(Input{Entries: []Entry{bulk}}, Selection{})
	if err != nil || len(c.Warnings()) != 1 {
		t.Fatalf("missing listing: %v %v", err, c.Warnings())
	}
}

func TestDuplicatePlaceholderNamesBoth(t *testing.T) {
	_, err := Compile(Input{Entries: []Entry{
		{Name: "a", Ref: "bao://kv/a", Placeholder: "SCRIM_SAME", Source: file("one.yaml")},
		{Name: "b", Ref: "bao://kv/b", Placeholder: "SCRIM_SAME", Source: file("two.yaml")},
	}}, Selection{})
	if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), `"a"`) || !strings.Contains(err.Error(), `"b"`) {
		t.Fatalf("got %v", err)
	}
	_, err = Compile(Input{Entries: []Entry{
		{Name: "a", Ref: "bao://kv/a", Source: file("one.yaml")},
		{Name: "a", Ref: "bao://kv/b", Source: file("two.yaml")},
	}}, Selection{})
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("same name twice in one source kind: %v", err)
	}
}

func TestPrecedenceAndMetadata(t *testing.T) {
	cfgEntry := Entry{Name: "github", Ref: "bao://kv/agents/github#token", Hosts: []string{"api.github.com"}, Source: Source{Kind: SourceConfig, Where: "catalog.entries.github"}}
	fileEntry := Entry{Name: "github", Ref: "bao://kv/old/github", Source: file("c.yaml")}
	meta, warns := EntriesFromMetadata([]stores.Metadata{
		{Ref: stores.MustParseRef("bao://kv/agents/github"), Labels: map[string]string{"scrim.hosts": "evil.example"}},
		{Ref: stores.MustParseRef("bao://kv/agents/npm"), Labels: map[string]string{"scrim.hosts": "registry.npmjs.org", "scrim.placeholder": "SCRIM_NPM_TOKEN", "scrim.field": "token"}},
		{Ref: stores.MustParseRef("bao://kv/agents/unlabelled")},
		{Ref: stores.MustParseRef("bao://kv/agents/bad"), Labels: map[string]string{"scrim.hosts": "not a host"}},
	}, "scrim.")
	if len(meta) != 2 || len(warns) != 1 {
		t.Fatalf("metadata entries %d, warnings %v", len(meta), warns)
	}
	c, err := Compile(Input{Entries: append([]Entry{fileEntry, cfgEntry}, meta...)}, Selection{})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := c.Name("github")
	if b.Ref.String() != "bao://kv/agents/github#token" || b.Source.Kind != SourceConfig {
		t.Fatalf("configuration should override the file: %+v", b)
	}
	if b.AllowsHost("evil.example") {
		t.Fatal("store metadata overrode the catalog's hosts")
	}
	ws := strings.Join(c.Warnings(), "\n")
	if !strings.Contains(ws, "overrides") || !strings.Contains(ws, "hosts differs") {
		t.Fatalf("conflicts not reported: %s", ws)
	}
	npm, err := c.Placeholder("SCRIM_NPM_TOKEN")
	if err != nil || npm.Ref.String() != "bao://kv/agents/npm#token" || !npm.AllowsHost("registry.npmjs.org") {
		t.Fatalf("metadata entry: %+v %v", npm, err)
	}
	if npm.Name != "bao-kv-agents-npm" {
		t.Fatalf("derived name %q", npm.Name)
	}
}

// The spec scenario: custom metadata scrim.hosts on a secret binds the host
// without a catalog file entry. The memory store carries labels the way
// the OpenBao adapter carries custom metadata.
func TestMetadataBindsHostFromStore(t *testing.T) {
	store := memstore.New("bao")
	ctx := context.Background()
	if _, err := store.Write(ctx, stores.MustParseRef("bao://kv/agents/github"), map[string]secret.Value{"token": secret.FromString("t_" + randHex(t, 8))},
		stores.WriteOptions{Labels: map[string]string{"scrim.hosts": "api.github.com"}}); err != nil {
		t.Fatal(err)
	}
	set := stores.NewSet()
	if err := set.Add(store); err != nil {
		t.Fatal(err)
	}
	cfg := buildConfig(t, nil, "SCRIM_CATALOG_METADATA_FROM=bao://kv/agents")
	c, err := Load(ctx, cfg, set, SelectionFrom(cfg))
	if err != nil {
		t.Fatal(err)
	}
	b, err := c.Lookup("{{scrim:bao://kv/agents/github#token}}")
	if err != nil || !b.AllowsHost("api.github.com") {
		t.Fatalf("binding: %+v %v", b, err)
	}
	// An outage does not block the catalog; it is a warning.
	store.SetDown(true)
	c, err = Load(ctx, cfg, set, SelectionFrom(cfg))
	if err != nil || len(c.Warnings()) == 0 {
		t.Fatalf("outage: %v %v", err, c.Warnings())
	}
}

func buildConfig(t *testing.T, paths []string, environ ...string) *config.Config {
	t.Helper()
	c, err := config.Build(config.Options{Registry: config.Default, ConfigPaths: paths, Environ: environ, SystemDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func catalogDoc(entries string) string {
	return "apiVersion: " + config.APIVersion + "\nkind: Catalog\nentries:\n" + entries
}

func TestSourcesFileConfigAndEnv(t *testing.T) {
	dir := t.TempDir()
	catFile := filepath.Join(dir, "catalog.yaml")
	writeFile(t, catFile, catalogDoc("  github:\n    ref: bao://kv/agents/github#token\n    hosts: [api.github.com]\n    placeholder: SCRIM_GITHUB_TOKEN\n  stripe:\n    ref: bao://kv/agents/stripe\n    hosts: [api.stripe.com]\n"))
	cfgFile := filepath.Join(dir, "config.yaml")
	writeFile(t, cfgFile, "apiVersion: "+config.APIVersion+"\nkind: Config\ncatalog:\n  files: ["+catFile+"]\n  profile: dev\n  entries:\n    db:\n      profiles:\n        dev: bao://kv/dev/db#password\n        prod: aws-sm://prod/db#password\n      placeholder: SCRIM_DB_PASSWORD\n      hosts: [db.internal]\n")
	cfg := buildConfig(t, []string{cfgFile}, `SCRIM_CATALOG_ENTRIES_DB_HOSTS=["db2.internal"]`)
	c, err := Load(context.Background(), cfg, nil, SelectionFrom(cfg))
	if err != nil {
		t.Fatal(err)
	}
	if b, err := c.Placeholder("SCRIM_GITHUB_TOKEN"); err != nil || b.Source.Kind != SourceFile {
		t.Fatalf("file entry: %+v %v", b, err)
	}
	if b, err := c.Placeholder("SCRIM_DB_PASSWORD"); err != nil || b.Ref.String() != "bao://kv/dev/db#password" {
		t.Fatalf("config entry for profile dev: %+v %v", b, err)
	}
	if b, _ := c.Name("db"); !b.AllowsHost("db2.internal") || b.AllowsHost("db.internal") {
		t.Fatalf("environment did not override the file's hosts: %+v", b)
	}

	// The whole collection as JSON in the environment overrides a catalog
	// file entry of the same name.
	cfg = buildConfig(t, []string{cfgFile}, `SCRIM_CATALOG_ENTRIES={"stripe":{"ref":"bao://kv/agents/stripe-live","hosts":["api.stripe.com"]}}`)
	c, err = Load(context.Background(), cfg, nil, SelectionFrom(cfg))
	if err != nil {
		t.Fatal(err)
	}
	if b, err := c.Name("stripe"); err != nil || b.Ref.String() != "bao://kv/agents/stripe-live" || b.Source.Kind != SourceConfig {
		t.Fatalf("environment entry should override the file: %+v %v", b, err)
	}

	// A literal in the configuration's catalog fails the configuration.
	bad := filepath.Join(dir, "bad.yaml")
	writeFile(t, bad, "apiVersion: "+config.APIVersion+"\nkind: Config\ncatalog:\n  entries:\n    gh:\n      ref: ghp_"+randHex(t, 18)+"\n")
	if _, err := config.Build(config.Options{Registry: config.Default, ConfigPaths: []string{bad}, Environ: []string{}, SystemDir: t.TempDir()}); err == nil {
		t.Fatal("configuration with a literal catalog value accepted")
	}
}

func TestManagerHotReload(t *testing.T) {
	dir := t.TempDir()
	catFile := filepath.Join(dir, "catalog.yaml")
	writeFile(t, catFile, catalogDoc("  github:\n    ref: bao://kv/agents/github#token\n    hosts: [api.github.com]\n"))
	cfg := buildConfig(t, nil, "SCRIM_CATALOG_FILES="+catFile, "SCRIM_CATALOG_RELOAD_INTERVAL=100ms")
	h := config.NewHolder(cfg)
	m, err := NewManager(context.Background(), h, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	applied := make(chan *Catalog, 8)
	m.Subscribe(func(c *Catalog) { applied <- c })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = m.Run(ctx) }()

	wait := func(what string, ok func(*Catalog) bool) {
		t.Helper()
		deadline := time.After(5 * time.Second)
		for {
			select {
			case c := <-applied:
				if ok(c) {
					return
				}
			case <-deadline:
				t.Fatalf("%s: no reload", what)
			}
		}
	}

	// A file change is picked up without restart.
	writeFile(t, catFile, catalogDoc("  github:\n    ref: bao://kv/agents/github#token\n    hosts: [api.github.com]\n  npm:\n    ref: bao://kv/agents/npm\n    hosts: [registry.npmjs.org]\n"))
	wait("file change", func(c *Catalog) bool { _, err := c.Name("npm"); return err == nil })

	// An invalid file is not loaded; the previous catalog stays.
	writeFile(t, catFile, catalogDoc("  npm:\n    ref: npm_"+randHex(t, 20)+"\n"))
	deadline := time.Now().Add(5 * time.Second)
	for m.LastError() == nil && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if m.LastError() == nil {
		t.Fatal("invalid catalog not reported")
	}
	if _, err := m.Current().Name("npm"); err != nil {
		t.Fatal("the previous catalog was dropped")
	}

	// A configuration change (new profile) triggers a reload.
	writeFile(t, catFile, catalogDoc("  db:\n    profiles:\n      dev: bao://kv/dev/db\n      prod: bao://kv/prod/db\n"))
	h.Swap(buildConfig(t, nil, "SCRIM_CATALOG_FILES="+catFile, "SCRIM_CATALOG_RELOAD_INTERVAL=100ms", "SCRIM_CATALOG_PROFILE=prod"))
	wait("config change", func(c *Catalog) bool {
		b, err := c.Name("db")
		return err == nil && b.Ref.String() == "bao://kv/prod/db"
	})
	if m.LastError() != nil {
		t.Fatalf("last error after a good reload: %v", m.LastError())
	}
}

func TestEnvName(t *testing.T) {
	for in, want := range map[string]string{"api-key": "API_KEY", "Webhook.Secret": "WEBHOOK_SECRET", "__x__y": "X_Y", "A1": "A1"} {
		if got := envName(in); got != want {
			t.Errorf("%s: %s, want %s", in, got, want)
		}
	}
}

func TestPlaceholderFormatAndSigV4Validation(t *testing.T) {
	for _, tc := range []struct {
		name string
		e    Entry
		ok   bool
	}{
		{"shape", Entry{Name: "gh", Ref: "env://GH", PlaceholderFormat: "shape"}, true},
		{"unknown format", Entry{Name: "gh", Ref: "env://GH", PlaceholderFormat: "jwt"}, false},
		{"display shape", Entry{Name: "gh", Ref: "env://GH", Class: ClassDisplay, PlaceholderFormat: "shape"}, false},
		{"sigv4", Entry{Name: "aws-secret", Ref: "env://S", AWSSigV4: &AWSSigV4{AccessKeyID: "aws-akid", Regions: []string{"us-east-1"}}}, true},
		{"sigv4 self", Entry{Name: "aws-secret", Ref: "env://S", AWSSigV4: &AWSSigV4{AccessKeyID: "aws-secret"}}, false},
		{"sigv4 bad region", Entry{Name: "aws-secret", Ref: "env://S", AWSSigV4: &AWSSigV4{AccessKeyID: "aws-akid", Regions: []string{"US EAST"}}}, false},
		{"sigv4 and cert", Entry{Name: "x", Ref: "env://S", ClientCertificate: true, AWSSigV4: &AWSSigV4{AccessKeyID: "y"}}, false},
	} {
		e := tc.e
		err := validateEntry(&e)
		if (err == nil) != tc.ok {
			t.Errorf("%s: err = %v", tc.name, err)
		}
	}
}
