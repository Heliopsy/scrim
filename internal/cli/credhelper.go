// SPDX-License-Identifier: AGPL-3.0-only

package cli

import (
	"github.com/spf13/cobra"

	"github.com/heliopsy/scrim/internal/credhelper"
)

// CredentialHelper runs scrim's credential helpers for git, docker, AWS
// credential_process and kubectl exec (specs/credential-injection
// "Credential helpers"). Tool profiles point the tools at it; it returns the
// session's placeholders only.
func (Commands) CredentialHelper(e *Env) *cobra.Command {
	return &cobra.Command{
		Use:   "credential-helper <git|docker|aws|kubectl> [args...]",
		Short: "Credential helper for git, docker, AWS credential_process and kubectl exec; returns placeholders only",
		Long: "Tool profiles configure tools to call this helper inside scrim run (docs/cli-tools.md): " +
			"`git` speaks the git credential helper protocol over the session's generated credential file, " +
			"`docker` the docker credential helper protocol over $DOCKER_CONFIG/config.json (also run as " +
			"docker-credential-scrim), `aws` prints credential_process JSON and `kubectl` an ExecCredential. " +
			"It never reads a store or the home directory's credential files, and never stores a credential.",
		Example:            "  printf 'protocol=https\\nhost=github.com\\n\\n' | scrim credential-helper git --file creds get",
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 && (args[0] == "-h" || args[0] == "--help") {
				return cmd.Help()
			}
			if code := credhelper.Main(args, e.Environ, e.Stdin, cmd.OutOrStdout(), e.Stderr); code != 0 {
				return &ExitCodeError{Code: code}
			}
			return nil
		},
	}
}
