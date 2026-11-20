// SPDX-License-Identifier: AGPL-3.0-only

package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const rulesYAML = `default: deny
rules:
  - name: github-read
    decision: allow
    when: secret.ref == "bao://kv/agents/github" && dest.method == "GET"
  - name: github-write
    decision: ask
    when: secret.ref == "bao://kv/agents/github" && dest.method != "GET"
    reason: Writes to GitHub need a human
    grant: {ttl: 30m, max_ttl: 2h, uses: 5}
  - name: night
    decision: deny
    when: now.getHours() < 6
`

func writeRules(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestPolicyCheck(t *testing.T) {
	p := writeRules(t, rulesYAML)
	code, out, errs := runAdmin(t, "", "policy", "check", p)
	if code != 0 || !strings.Contains(out, "ok: 3 rules, default deny, 2 decided entirely in the data plane") {
		t.Fatalf("%d %q %q", code, out, errs)
	}
	bad := writeRules(t, "rules:\n  - name: x\n    decision: allow\n    wehn: op == \"x\"\n")
	if code, _, errs := runAdmin(t, "", "policy", "check", bad); code != 1 || !strings.Contains(errs, "wehn") {
		t.Fatalf("unknown key: %d %q", code, errs)
	}
	typo := writeRules(t, "rules:\n  - name: x\n    decision: allow\n    when: secret.reff == \"x\"\n")
	if code, _, errs := runAdmin(t, "", "policy", "check", typo); code != 1 || !strings.Contains(errs, "reff") {
		t.Fatalf("typo: %d %q", code, errs)
	}
	// The setting form.
	e, out2, _ := newEnv("SCRIM_POLICY_RULES_FILE=" + p)
	if code := Run(t.Context(), e, []string{"policy", "check"}); code != 0 || !strings.Contains(out2.String(), "3 rules") {
		t.Fatalf("from setting: %q", out2.String())
	}
}

func TestPolicyEval(t *testing.T) {
	p := writeRules(t, rulesYAML)
	code, out, errs := runAdmin(t, "", "policy", "eval", p, "--agent", "claude-laptop", "--op", "inject",
		"--ref", "bao://kv/agents/github", "--host", "api.github.com", "--method", "POST")
	if code != 0 {
		t.Fatalf("%d %q", code, errs)
	}
	var res struct {
		Effect    string `json:"effect"`
		Rule      string `json:"rule"`
		DataPlane struct {
			Outcome string `json:"outcome"`
			Ask     string `json:"ask"`
		} `json:"data_plane"`
	}
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatal(err)
	}
	// The night rule is residual, so the data plane has to ask whatever
	// the time.
	if (res.Effect != "ask" && res.Effect != "deny") || res.DataPlane.Outcome != "control_plane" {
		t.Fatalf("%+v", res)
	}
}

func TestPolicySnapshot(t *testing.T) {
	p := writeRules(t, rulesYAML)
	code, out, _ := runAdmin(t, "", "policy", "snapshot", p)
	if code != 0 || !strings.Contains(out, `"field": "secret.ref"`) || !strings.Contains(out, `"residual": true`) {
		t.Fatalf("%q", out)
	}
}
