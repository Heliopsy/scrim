// SPDX-License-Identifier: AGPL-3.0-only

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/heliopsy/scrim/internal/config"
)

// TestDoctorReportsStoreIdentityPerAgent: doctor says which store identity
// each agent uses (passthrough, static, shared or none) and never prints a
// credential.
func TestDoctorReportsStoreIdentityPerAgent(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "scrim.yaml")
	yaml := "apiVersion: " + config.APIVersion + "\nkind: Config\n" + `
stores:
  bao:
    kind: memory
  vw:
    kind: memory
  plain:
    kind: memory
identity:
  peers:
    laptop: "uid:1000"
  kubernetes:
    enabled: true
    api-server: https://127.0.0.1:6443
    ca-file: ` + filepath.Join(dir, "missing-ca") + `
    agents:
      reviewer: "sa:agents/reviewer"
  store-login:
    bao: "kubernetes role:{namespace}-{service_account}"
  store-credentials:
    vw/laptop: env:SCRIM_TEST_VW_LAPTOP
`
	if err := os.WriteFile(p, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Build(config.Options{ConfigPaths: []string{p}, SystemDir: dir, Environ: []string{"SCRIM_TEST_VW_LAPTOP=never-printed"}})
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	for _, c := range identityChecks(cfg) {
		for _, f := range c.Run(t.Context()) {
			lines = append(lines, string(f.Outcome)+" "+f.Message)
		}
	}
	got := strings.Join(lines, "\n")
	for _, want := range []string{
		"fail identity.kubernetes.ca-file",
		"pass store bao, agent *: kubernetes (role {namespace}-{service_account} at auth/kubernetes)",
		"warn store bao, agent laptop: none",
		"pass store vw, agent laptop: static",
		"warn store vw, agent reviewer: none",
		"pass store plain: every agent uses scrim's own identity",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("doctor lacks %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "never-printed") {
		t.Fatal("doctor printed a credential")
	}
}
