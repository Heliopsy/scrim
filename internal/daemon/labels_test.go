// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/heliopsy/scrim/internal/testing/fakeprovider"
)

// withLabels rewrites the harness configuration: the env store derives
// labels, two display values join the catalog (one of them "prod" by a
// derived label), and the rules deny restoring prod values.
func withLabels(t *testing.T, h *harness) (note, prod string) {
	t.Helper()
	cfgPath := filepath.Join(h.dir, "config.yaml")
	b, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	cfg := strings.Replace(string(b), `    redact: ["testenv://SCRIMTEST_TOKEN"]
`, `    redact: ["testenv://SCRIMTEST_TOKEN", "testenv://SCRIMTEST_NOTE", "testenv://SCRIMTEST_PROD_NOTE"]
    labels:
      team: {value: ops}
      variable: env.variable
      tier: {from: env.variable, regex: "_PROD_", value: prod}
`, 1)
	cfg = strings.Replace(cfg, `catalog:
  entries:
`, `catalog:
  entries:
    note:
      ref: testenv://SCRIMTEST_NOTE
      class: display
    prodnote:
      ref: testenv://SCRIMTEST_PROD_NOTE
      class: display
`, 1)
	if !strings.Contains(cfg, "tier:") || !strings.Contains(cfg, "prodnote:") {
		t.Fatal("harness configuration changed shape")
	}
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	rules := filepath.Join(h.dir, "rules.yaml")
	r, err := os.ReadFile(rules)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rules, append(r, []byte(`  - name: no-prod-restore
    decision: deny
    when: op == "restore" && "tier" in secret.labels && secret.labels.tier == "prod" && secret.labels["store.kind"] == "env"
`)...), 0o600); err != nil {
		t.Fatal(err)
	}
	note, prod = seed(t, "note-"), seed(t, "prodnote-")
	t.Setenv("SCRIMTEST_NOTE", note)
	t.Setenv("SCRIMTEST_PROD_NOTE", prod)
	return note, prod
}

// TestSnapshotCarriesStoreLabels: every value in the snapshot carries the
// labels rules see as secret.labels: the env store's native labels, the
// generic store.* labels and the configured derived labels.
func TestSnapshotCarriesStoreLabels(t *testing.T) {
	h := newHarness(t, seed(t, "tok-"))
	withLabels(t, h)
	startDaemon(t, h)
	want := map[string]map[string]string{
		"testenv://SCRIMTEST_TOKEN#value": {
			"store.name": "testenv", "store.kind": "env", "store.path": "SCRIMTEST_TOKEN", "store.container": "",
			"store.field": "value", "env.variable": "SCRIMTEST_TOKEN", "env.prefix": "SCRIMTEST_",
			"team": "ops", "variable": "SCRIMTEST_TOKEN",
		},
		"testenv://SCRIMTEST_PROD_NOTE#value": {"tier": "prod", "env.variable": "SCRIMTEST_PROD_NOTE"},
		"testenv://SCRIMTEST_NOTE#value":      {"team": "ops"},
	}
	eventually(t, "labelled values in the snapshot", func() bool {
		seen := 0
		for _, v := range h.snapshot(t).GetValues() {
			w, ok := want[v.GetRef()]
			if !ok {
				if v.GetLabels()["store.name"] == "" {
					t.Fatalf("%s has no store.name label: %v", v.GetRef(), v.GetLabels())
				}
				continue
			}
			for k, val := range w {
				if v.GetLabels()[k] != val {
					return false
				}
			}
			if v.GetRef() == "testenv://SCRIMTEST_NOTE#value" && v.GetLabels()["tier"] != "" {
				t.Fatalf("SCRIMTEST_NOTE has a tier label: %v", v.GetLabels())
			}
			seen++
		}
		return seen == len(want)
	})
}

// TestRestoreRuleOnLabelRealDataPlane: a deny rule on a store label is
// enforced by the real data plane when it restores placeholders in a model
// reply. Both values are display values; only the one the derived label
// marks prod stays a placeholder.
func TestRestoreRuleOnLabelRealDataPlane(t *testing.T) {
	bin := realDataPlane(t)
	fake := fakeprovider.New(fakeprovider.Options{})
	up := httptest.NewServer(fake)
	defer up.Close()

	h := newHarness(t, seed(t, "sk-lbl-"))
	note, prod := withLabels(t, h)
	h.opts.DataPlaneEnv = nil
	h.opts.Config.Environ = append(h.opts.Config.Environ, "SCRIM_DATAPLANE_PATH="+bin,
		"SCRIM_PROXY_UPSTREAM_ANTHROPIC="+up.URL)
	d := startDaemon(t, h)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	body := `{"model":"claude-sonnet-4-5","max_tokens":64,"messages":[{"role":"user","content":"notes: ` + note + ` and ` + prod + `"}]}`
	var reply []byte
	eventually(t, "both values redacted", func() bool {
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, d.Addrs().BaseURL+"/anthropic/v1/messages", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("x-api-key", "agent-own-key")
		req.Header.Set("anthropic-version", "2023-06-01")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		reply, _ = io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status %d: %s", resp.StatusCode, reply)
		}
		ex := fake.Exchanges()
		return len(ex[len(ex)-1].Placeholders) == 2
	})
	for _, ex := range fake.Exchanges() {
		if strings.Contains(string(ex.Body), note) || strings.Contains(string(ex.Body), prod) {
			t.Fatal("the provider received a value")
		}
	}
	if !strings.Contains(string(reply), note) {
		t.Fatalf("the unlabelled display value was not restored: %s", reply)
	}
	if strings.Contains(string(reply), prod) {
		t.Fatalf("the value labelled tier=prod was restored despite the rule: %s", reply)
	}
	if !strings.Contains(string(reply), "scrim:prodnote:") {
		t.Fatalf("the prod placeholder did not come back: %s", reply)
	}
}
