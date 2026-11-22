// SPDX-License-Identifier: AGPL-3.0-only

package cli

import (
	"context"
	"strings"
	"testing"

	"github.com/heliopsy/scrim/internal/agenttools"
	"github.com/heliopsy/scrim/internal/identity"
	"github.com/heliopsy/scrim/internal/localapi"
	"github.com/heliopsy/scrim/internal/localapi/localapitest"
)

// TestExecCommand: scrim exec sends the command, --env and --stdin, prints
// the redacted streams, notes a withheld one and exits with the command's
// status; a refusal exits 3.
func TestExecCommand(t *testing.T) {
	got := make(chan agenttools.ExecInput, 2)
	ts := localapitest.StartWith(t, func(s *localapi.Server) {
		s.Exec = func(_ context.Context, _ identity.Identity, in agenttools.ExecInput) (agenttools.ExecOutput, error) {
			got <- in
			if in.Command[0] == "base64" {
				return agenttools.ExecOutput{}, agenttools.Errorf(agenttools.CodeDenied, "base64 is never run by the exec broker")
			}
			return agenttools.ExecOutput{ExitCode: 6, Stdout: "pushed with ⟦scrim:gh:01aa⟧\n",
				Withheld: map[string]string{"stderr": "it still held a secret after redaction"}}, nil
		}
	})
	r := runCLI(ts, strings.NewReader("pw=SCRIM_PW\n"), "exec", "--env", "GITHUB_TOKEN=SCRIM_GITHUB_TOKEN", "--stdin", "--",
		"git", "push", "--force-with-lease")
	in := <-got
	if r.code != 6 || r.stdout != "pushed with ⟦scrim:gh:01aa⟧\n" || !strings.Contains(r.stderr, "stderr withheld") {
		t.Fatalf("result = %+v", r)
	}
	if strings.Join(in.Command, " ") != "git push --force-with-lease" || in.Env["GITHUB_TOKEN"] != "SCRIM_GITHUB_TOKEN" ||
		in.Stdin != "pw=SCRIM_PW\n" {
		t.Fatalf("input = %+v", in)
	}
	r = runCLI(ts, nil, "exec", "--", "base64")
	<-got
	if r.code != ExitDenied || !strings.Contains(r.stderr, "never run") {
		t.Fatalf("refusal = %+v", r)
	}
}
