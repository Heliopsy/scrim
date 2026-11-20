// SPDX-License-Identifier: AGPL-3.0-only

package cli

import "github.com/spf13/cobra"

// Catalog shows and suggests secret catalog entries.
func (Commands) Catalog(*Env) *cobra.Command {
	return stub("catalog", "Show and suggest secret catalog entries", "6.3c")
}
