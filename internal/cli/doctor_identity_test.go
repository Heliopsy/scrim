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
// each agent uses (passthrough, token exchange, static, shared or none),
// fails a token exchange login without scrim's issuer, and never prints a
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
  aws:
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
    aws: "aws-web-identity role-arn:arn:aws:iam::000000000000:role/agent-{agent_slug}"
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
		"fail store aws logs agents in with aws-web-identity, which presents a token scrim signs, but scrim's identity issuer is off",
		"pass store aws, agent laptop: token exchange (aws-web-identity audience:sts.amazonaws.com duration:15m role-arn:arn:aws:iam::000000000000:role/agent-{agent_slug})",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("doctor lacks %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "never-printed") {
		t.Fatal("doctor printed a credential")
	}
}

// TestDoctorReportsAgentWriteChecks: per store with per-agent identity,
// doctor says whether agents' writes are checked with the agent's own
// identity, and warns where they are not.
func TestDoctorReportsAgentWriteChecks(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "scrim.yaml")
	yaml := "apiVersion: " + config.APIVersion + "\nkind: Config\n" + `
stores:
  vw:
    kind: vaultwarden
    url: https://vault.example.test
    client-id: user.00000000-0000-0000-0000-000000000000
    client-secret: env:SCRIM_TEST_VW_LAPTOP
    unlock: env:SCRIM_TEST_VW_LAPTOP
  dop:
    kind: doppler
    token: env:SCRIM_TEST_VW_LAPTOP
  op:
    kind: onepassword
    address: http://op-connect.example.test:8080
    token: env:SCRIM_TEST_VW_LAPTOP
  plain:
    kind: memory
identity:
  store-credentials:
    vw/laptop: env:SCRIM_TEST_VW_LAPTOP
    dop/laptop: env:SCRIM_TEST_VW_LAPTOP
    op/laptop: env:SCRIM_TEST_VW_LAPTOP
  refuse-unchecked-writes: [op]
`
	if err := os.WriteFile(p, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	run := func(env ...string) string {
		cfg, err := config.Build(config.Options{ConfigPaths: []string{p}, SystemDir: dir, Environ: append(env, "SCRIM_TEST_VW_LAPTOP=never-printed")})
		if err != nil {
			t.Fatal(err)
		}
		var lines []string
		for _, f := range storeIdentityFindings(cfg) {
			lines = append(lines, string(f.Outcome)+" "+f.Message)
		}
		return strings.Join(lines, "\n")
	}
	got := run()
	for _, want := range []string{
		"pass store vw: agents' writes are checked with the agent's own identity",
		"warn store dop: agents' writes are not checked against the agent's identity (the store cannot tell without writing)",
		"pass store op: agents' writes are refused: the store cannot check the agent's identity (identity.refuse-unchecked-writes)",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("doctor lacks %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "store plain: agents' writes") {
		t.Errorf("doctor reports writes for a store without per-agent identity:\n%s", got)
	}
	got = run("SCRIM_IDENTITY_SKIP_AGENT_WRITE_CHECKS=true")
	if want := "warn store vw: agents' writes are not checked against the agent's identity (identity.skip-agent-write-checks)"; !strings.Contains(got, want) {
		t.Errorf("doctor lacks %q:\n%s", want, got)
	}
}
