// SPDX-License-Identifier: AGPL-3.0-only

package cli

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/heliopsy/scrim/internal/config"
)

func writeCatalogConfig(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "config.yaml")
	body := "apiVersion: " + config.APIVersion + "\nkind: Config\nstate:\n  backend: memory\ncatalog:\n  entries:\n" +
		"    db:\n      profiles:\n        dev: bao://kv/dev/db#password\n        prod: aws-sm://prod/db#password\n      placeholder: SCRIM_DB_PASSWORD\n      hosts: [db.internal]\n" +
		"    github:\n      ref: bao://kv/agents/github#token\n      hosts: [api.github.com]\n"
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestCatalogShow(t *testing.T) {
	cfg := writeCatalogConfig(t)
	e, out, errb := newEnv()
	if code := Run(context.Background(), e, []string{"--config", cfg, "--catalog-profile", "dev", "catalog", "show"}); code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	text := out.String()
	if !strings.Contains(text, "selection: profile=dev") || !strings.Contains(text, "bao://kv/dev/db#password") ||
		strings.Contains(text, "aws-sm://prod/db#password") || !strings.Contains(text, "profile=dev") {
		t.Fatalf("show for dev:\n%s", text)
	}

	e, out, errb = newEnv()
	if code := Run(context.Background(), e, []string{"--config", cfg, "catalog", "show", "--json", "--for-profile", "prod"}); code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	var got struct {
		Selection string `json:"selection"`
		Entries   []struct {
			Name     string `json:"name"`
			Resolved bool   `json:"resolved"`
			Binding  *struct {
				Ref      string `json:"ref"`
				Selected string `json:"selected"`
			} `json:"binding"`
			Variants map[string]string `json:"variants"`
		} `json:"entries"`
	}
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	if got.Selection != "profile=prod" || len(got.Entries) != 2 || got.Entries[0].Binding.Ref != "aws-sm://prod/db#password" || len(got.Entries[0].Variants) != 2 {
		t.Fatalf("json: %+v", got)
	}
}

func TestCatalogSuggestPrintsOnly(t *testing.T) {
	cfg := writeCatalogConfig(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("OPENAI_API_KEY=sk-"+strings.Repeat("q", 20)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(cfg)
	e, out, errb := newEnv()
	if code := Run(context.Background(), e, []string{"--config", cfg, "catalog", "suggest", "--dir", dir}); code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	if !strings.Contains(out.String(), "SCRIM_OPENAI_API_KEY") || strings.Contains(out.String(), "qqqqqqqq") {
		t.Fatalf("suggest output:\n%s", out.String())
	}
	after, _ := os.ReadFile(cfg)
	if string(before) != string(after) {
		t.Fatal("suggest changed the configuration")
	}
}
