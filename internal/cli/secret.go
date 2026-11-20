// SPDX-License-Identifier: AGPL-3.0-only

package cli

import "github.com/spf13/cobra"

// Secret lists, requests, generates and captures secrets without showing values.
func (Commands) Secret(*Env) *cobra.Command {
	return stub("secret", "Work with secrets without seeing their values", "8.3")
}
