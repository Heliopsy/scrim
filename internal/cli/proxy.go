// SPDX-License-Identifier: AGPL-3.0-only

package cli

import "github.com/spf13/cobra"

// Proxy serves the LLM proxy and the tool proxy.
func (Commands) Proxy(*Env) *cobra.Command {
	return stub("proxy", "Serve the LLM proxy and tool proxy", "3.1")
}
