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

func writeLabelsConfig(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.yaml")
	body := "apiVersion: " + config.APIVersion + "\nkind: Config\nstate:\n  backend: memory\n" + `stores:
  lblenv:
    kind: env
    prefix: SCRIMLBL_
    labels:
      team: {value: ops}
      tier: {from: env.variable, regex: "_PROD_", value: prod}
catalog:
  entries:
    tok:
      ref: lblenv://SCRIMLBL_PROD_TOKEN
      hosts: [api.example.test]
`
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestCatalogLabels(t *testing.T) {
	cfg := writeLabelsConfig(t)
	value := "lbl-" + strings.Repeat("v", 20)
	t.Setenv("SCRIMLBL_PROD_TOKEN", value)
	e, out, errb := newEnv()
	if code := Run(context.Background(), e, []string{"--config", cfg, "catalog", "labels", "tok"}); code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	text := out.String()
	for _, want := range []string{
		"ref: lblenv://SCRIMLBL_PROD_TOKEN", "store.kind", "env.variable", "SCRIMLBL_PROD_TOKEN", "native",
		"tier", "prod", "derived", "team",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("labels output lacks %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "not in the store") || strings.Contains(text+errb.String(), value) {
		t.Fatalf("labels output:\n%s", text)
	}

	e, out, errb = newEnv()
	if code := Run(context.Background(), e, []string{"--config", cfg, "catalog", "labels", "--json", "lblenv://SCRIMLBL_NEW"}); code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	var got struct {
		Exists bool              `json:"exists"`
		Labels map[string]string `json:"labels"`
	}
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Exists || got.Labels["store.name"] != "lblenv" || got.Labels["team"] != "ops" || got.Labels["tier"] != "" {
		t.Fatalf("new item: %+v", got)
	}

	e, out, errb = newEnv()
	if code := Run(context.Background(), e, []string{"--config", cfg, "catalog", "show", "tok"}); code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	if text := out.String(); !strings.Contains(text, "reference: lblenv://SCRIMLBL_PROD_TOKEN") || !strings.Contains(text, "env.prefix") ||
		strings.Contains(text, value) {
		t.Fatalf("show tok:\n%s", text)
	}
}

func TestPolicyEvalLabels(t *testing.T) {
	p := writeRules(t, `default: allow
rules:
  - name: prod-collection-writes
    decision: ask
    when: op == "store.write" && "vaultwarden.collection.Prod" in secret.labels
  - name: acme
    decision: deny
    when: '"vaultwarden.org" in secret.labels && secret.labels["vaultwarden.org"] == "Acme"'
`)
	eval := func(args ...string) string {
		t.Helper()
		code, out, errs := runAdmin(t, "", append([]string{"policy", "eval", p, "--agent", "a", "--ref", "vw://x"}, args...)...)
		if code != 0 {
			t.Fatalf("%d %q", code, errs)
		}
		var res struct {
			Rule string `json:"rule"`
		}
		if err := json.Unmarshal([]byte(out), &res); err != nil {
			t.Fatal(err)
		}
		return res.Rule
	}
	if r := eval("--op", "store.write", "--label", "vaultwarden.collection=Prod,Shared", "--label", "vaultwarden.collection.Prod=true"); r != "prod-collection-writes" {
		t.Fatalf("collection: %q", r)
	}
	if r := eval("--op", "inject", "--label", "vaultwarden.org=Acme"); r != "acme" {
		t.Fatalf("org: %q", r)
	}
	if r := eval("--op", "store.write", "--label", "vaultwarden.org=Other"); r != "default" && r != "" {
		t.Fatalf("other: %q", r)
	}
	if code, _, _ := runAdmin(t, "", "policy", "eval", p, "--label", "novalue"); code == 0 {
		t.Fatal("--label without = accepted")
	}
}
