// SPDX-License-Identifier: AGPL-3.0-only

package cli

import "github.com/spf13/cobra"

// Status reports what scrim protects and what is degraded.
func (Commands) Status(*Env) *cobra.Command {
	return stub("status", "Report protections, stores and weakened settings", "5.4")
}
