// SPDX-License-Identifier: AGPL-3.0-only

package cli

import "github.com/spf13/cobra"

// Doctor checks the local setup and suggests fixes.
func (Commands) Doctor(*Env) *cobra.Command {
	return stub("doctor", "Check the local setup and suggest fixes", "5.4")
}
