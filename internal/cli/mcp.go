// SPDX-License-Identifier: AGPL-3.0-only

package cli

import "github.com/spf13/cobra"

// MCP serves the agent tools over MCP on stdio.
func (Commands) MCP(*Env) *cobra.Command {
	return stub("mcp", "Serve the agent tools over MCP (stdio)", "8.2")
}
