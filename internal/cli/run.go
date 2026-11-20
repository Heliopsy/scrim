// SPDX-License-Identifier: AGPL-3.0-only

package cli

import "github.com/spf13/cobra"

// Run runs an agent with its traffic through scrim.
func (Commands) Run(*Env) *cobra.Command {
	return stub("run -- <agent> [args...]", "Run an agent with its traffic through scrim", "9.3")
}
