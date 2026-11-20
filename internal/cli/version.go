// SPDX-License-Identifier: AGPL-3.0-only

package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/heliopsy/scrim/internal/version"
)

// Version prints the build version.
func (Commands) Version(*Env) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the version",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, err := fmt.Fprintln(cmd.OutOrStdout(), version.String())
			return err
		},
	}
}
