// SPDX-License-Identifier: AGPL-3.0-only

package cli

import "github.com/spf13/cobra"

// Approve decides a pending approval from the terminal.
func (Commands) Approve(*Env) *cobra.Command {
	return stub("approve <approval-id>", "Approve or deny a pending request", "7.3")
}
