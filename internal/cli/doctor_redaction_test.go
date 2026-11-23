// SPDX-License-Identifier: AGPL-3.0-only

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/redactscope"
)

// TestDoctorReportsRedactionIdentity: off, doctor says the redaction set
// covers what agents cannot use; on, it warns per store which agents'
// sessions are redacted less, and warns that it does nothing without a
// per-agent credential. No credential is printed.
func TestDoctorReportsRedactionIdentity(t *testing.T) {
	run := func(t *testing.T, creds string, env ...string) string {
		t.Helper()
		dir := t.TempDir()
		p := filepath.Join(dir, "scrim.yaml")
		yaml := "apiVersion: " + config.APIVersion + "\nkind: Config\n" + `
stores:
  bao:
    kind: memory
  plain:
    kind: memory
identity:
  store-credentials:
` + creds
		if err := os.WriteFile(p, []byte(yaml), 0o600); err != nil {
			t.Fatal(err)
		}
		cfg, err := config.Build(config.Options{ConfigPaths: []string{p}, SystemDir: dir,
			Environ: append([]string{"SCRIM_TEST_BAO_A=never-printed"}, env...)})
		if err != nil {
			t.Fatal(err)
		}
		var lines []string
		for _, c := range redactionIdentityChecks(cfg) {
			for _, f := range c.Run(t.Context()) {
				lines = append(lines, string(f.Outcome)+" "+f.Message+" | "+f.Fix)
			}
		}
		got := strings.Join(lines, "\n")
		if strings.Contains(got, "never-printed") {
			t.Fatal("doctor printed a credential")
		}
		return got
	}
	const creds = "    bao/agent-a: env:SCRIM_TEST_BAO_A\n    bao/agent-b: env:SCRIM_TEST_BAO_A\n"
	on := "SCRIM_REDACTION_LIMIT_TO_AGENT_IDENTITY=true"
	if got := run(t, creds); !strings.HasPrefix(got, "pass the redaction set is loaded with each store's own credentials") {
		t.Errorf("off: %s", got)
	}
	got := run(t, creds, on)
	if !strings.Contains(got, "warn weakened ("+redactscope.LimitKey+"): store bao: provider requests of the scrim run sessions of agent-a, agent-b") ||
		strings.Contains(got, "plain") {
		t.Errorf("on: %s", got)
	}
	if got := run(t, "    {}\n", on); !strings.Contains(got, "warn "+redactscope.LimitKey+" is on but has no effect") {
		t.Errorf("on without credentials: %s", got)
	}
}
