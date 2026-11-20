// SPDX-License-Identifier: AGPL-3.0-only

package catalog

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores"
	"github.com/heliopsy/scrim/internal/stores/memstore"
)

func TestSuggestFromProject(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "shop")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	stripe := "sk_live_" + randHex(t, 12)
	gh := "ghp_" + randHex(t, 18)
	acmeKey := "acme-" + randHex(t, 12)
	dbpw := "pw" + randHex(t, 6)
	env := strings.Join([]string{
		"# project settings",
		"STRIPE_SECRET_KEY=" + stripe,
		"export GITHUB_TOKEN=\"" + gh + "\"",
		"ACME_API_URL=https://api.acme.example/v2",
		"ACME_API_KEY=" + acmeKey,
		"DATABASE_URL=postgres://app:" + dbpw + "@db.internal:5432/shop",
		"LOG_LEVEL=debug",
		"",
	}, "\n")
	envFile := filepath.Join(dir, ".env")
	if err := os.WriteFile(envFile, []byte(env), 0o600); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadDir(dir)

	store := memstore.New("inf")
	store.Seed(stores.MustParseRef("inf://shop/prod/GITHUB_TOKEN"), map[string]secret.Value{"value": secret.FromString("x" + randHex(t, 8))})
	store.Seed(stores.MustParseRef("inf://shop/prod/SENTRY_DSN"), map[string]secret.Value{"value": secret.FromString("y" + randHex(t, 8))})
	set := stores.NewSet()
	if err := set.Add(store); err != nil {
		t.Fatal(err)
	}
	cat := compile(t, Selection{}, Entry{Name: "mapped", Ref: "bao://kv/x", Placeholder: "SCRIM_STRIPE_SECRET_KEY", Source: file("c")})

	sugg, warnings, err := Suggest(context.Background(), SuggestOptions{
		Dir: dir, Store: "bao://kv/agents", Lister: set, Prefixes: []stores.Ref{stores.MustParseRef("inf://shop/prod")},
		Catalog: cat,
		Tools:   map[string]ToolHint{"gh": {Env: []string{"GITHUB_TOKEN", "GH_ENTERPRISE_TOKEN"}, Hosts: []string{"api.github.com"}}},
	})
	if err != nil || len(warnings) != 0 {
		t.Fatalf("%v %v", err, warnings)
	}
	byName := map[string]Suggestion{}
	for _, s := range sugg {
		byName[s.Entry.Name] = s
	}
	// Stripe is already mapped by placeholder: skipped.
	if _, ok := byName["stripe-secret-key"]; ok {
		t.Error("mapped secret suggested again")
	}
	if s := byName["github-token"]; s.Entry.Ref != "inf://shop/prod/GITHUB_TOKEN" || s.Entry.Hosts[0] != "api.github.com" || s.Entry.Tools[0] != "gh" {
		t.Errorf("github: %+v", s)
	}
	if s := byName["acme-api-key"]; s.Entry.Ref != "bao://kv/agents/shop/acme-api-key" || s.Entry.Hosts[0] != "api.acme.example" || s.Entry.Placeholder != "SCRIM_ACME_API_KEY" {
		t.Errorf("acme: %+v", s)
	}
	if s := byName["database-url"]; len(s.Entry.Hosts) != 1 || s.Entry.Hosts[0] != "db.internal" {
		t.Errorf("database url: %+v", s)
	}
	if _, ok := byName["gh-enterprise-token"]; !ok {
		t.Error("tool profile credential not suggested")
	}
	if s := byName["sentry-dsn"]; s.Entry.Ref != "inf://shop/prod/SENTRY_DSN" || s.Entry.Hosts[0] != "sentry.io" {
		t.Errorf("store secret: %+v", s)
	}
	if _, ok := byName["log-level"]; ok {
		t.Error("non-secret variable suggested")
	}
	if _, ok := byName["acme-api-url"]; ok {
		t.Error("URL without credentials suggested")
	}

	var out bytes.Buffer
	if err := WriteSuggestions(&out, sugg, warnings); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	for _, v := range []string{stripe, gh, acmeKey, dbpw} {
		if strings.Contains(text, v) {
			t.Fatal("suggestions contain a value from the project")
		}
	}
	if !strings.Contains(text, "nothing was applied") {
		t.Fatal("output does not say nothing was applied")
	}
	// The printed draft is itself a valid catalog file.
	if _, err := ParseFile("draft.yaml", out.Bytes()); err != nil {
		t.Fatalf("draft does not parse: %v\n%s", err, text)
	}
	// Nothing was written.
	after, _ := os.ReadDir(dir)
	if len(after) != len(before) {
		t.Fatal("suggest wrote into the project")
	}
	if data, _ := os.ReadFile(envFile); string(data) != env {
		t.Fatal("suggest changed the .env file")
	}
}

// The spec scenario: a .env referencing three APIs gives three drafts.
func TestSuggestThreeAPIs(t *testing.T) {
	dir := t.TempDir()
	env := "OPENAI_API_KEY=" + randHex(t, 8) + "\nANTHROPIC_API_KEY=" + randHex(t, 8) + "\nSLACK_BOT_TOKEN=" + randHex(t, 8) + "\nPORT=8080\n"
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte(env), 0o600); err != nil {
		t.Fatal(err)
	}
	sugg, _, err := Suggest(context.Background(), SuggestOptions{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if len(sugg) != 3 {
		t.Fatalf("%d suggestions", len(sugg))
	}
	for _, s := range sugg {
		if s.Entry.Placeholder == "" || s.Entry.Ref == "" || len(s.Entry.Hosts) != 1 {
			t.Errorf("incomplete draft %+v", s.Entry)
		}
	}
	var out bytes.Buffer
	_ = WriteSuggestions(&out, nil, nil)
	if _, err := ParseFile("empty.yaml", out.Bytes()); err != nil {
		t.Fatalf("empty draft does not parse: %v", err)
	}
}
