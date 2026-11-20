// SPDX-License-Identifier: AGPL-3.0-only

package cli

import "github.com/spf13/cobra"

// Config inspects and validates configuration.
func (Commands) Config(*Env) *cobra.Command {
	return stub("config", "Inspect and validate configuration", "4.3")
}
