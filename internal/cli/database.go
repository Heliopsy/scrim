// SPDX-License-Identifier: AGPL-3.0-only

package cli

import (
	"context"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/heliopsy/scrim/internal/localapi"
)

// Database is `scrim database`, the CLI form of the read-only database tool.
func (Commands) Database(e *Env) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "database",
		Short: "List configured databases and run read-only queries by placeholder",
		Long: "The CLI form of the database_list and database_query tools. A placeholder inside a string literal or in " +
			"--param is bound as a query parameter carrying the real value; the result comes back redacted.\n\n" +
			"Exit codes: 0 success, 1 error, 3 refused or denied.",
	}
	cmd.PersistentFlags().StringP("output", "o", "text", "output format: text or json")
	cmd.AddCommand(databaseList(e), databaseQuery(e))
	return cmd
}

func databaseList(e *Env) *cobra.Command {
	return &cobra.Command{
		Use:   "ls",
		Short: "List the configured databases and their local proxy endpoints (database_list)",
		Args:  cobra.NoArgs,
		RunE: run(e, func(ctx context.Context, c *localapi.Client, p printer, _ []string) error {
			out, err := c.DatabaseList(ctx)
			if err != nil {
				return p.fail(err)
			}
			return p.emit(out, func(w io.Writer) {
				if len(out.Databases) == 0 {
					_, _ = fmt.Fprintln(w, "no databases configured")
					return
				}
				tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
				_, _ = fmt.Fprintln(tw, "NAME\tKIND\tHOST\tLISTEN\tTOOL")
				for _, d := range out.Databases {
					_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%v\n", d.Name, d.Kind, d.Host, d.Listen, d.Tool)
				}
				_ = tw.Flush()
			})
		}),
	}
}

func databaseQuery(e *Env) *cobra.Command {
	var (
		params  []string
		maxRows int
	)
	cmd := &cobra.Command{
		Use:   "query DATABASE SQL",
		Short: "Run one read-only statement (database_query)",
		Args:  cobra.ExactArgs(2),
		RunE: run(e, func(ctx context.Context, c *localapi.Client, p printer, args []string) error {
			out, err := c.DatabaseQuery(ctx, localapi.DatabaseQueryInput{Database: args[0], SQL: args[1], Params: params, MaxRows: maxRows})
			if err != nil {
				return p.fail(err)
			}
			return p.emit(out, func(w io.Writer) {
				tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
				_, _ = fmt.Fprintln(tw, strings.Join(out.Columns, "\t"))
				for _, row := range out.Rows {
					cells := make([]string, len(row))
					for i, v := range row {
						cells[i] = "NULL"
						if v != nil {
							cells[i] = *v
						}
					}
					_, _ = fmt.Fprintln(tw, strings.Join(cells, "\t"))
				}
				_ = tw.Flush()
				if out.Truncated {
					_, _ = fmt.Fprintf(w, "(truncated at %d rows)\n", len(out.Rows))
				}
			})
		}),
	}
	cmd.Flags().StringArrayVar(&params, "param", nil, "parameter for $1, $2 or ?, in order; may contain placeholders (repeatable)")
	cmd.Flags().IntVar(&maxRows, "max-rows", 0, "return at most this many rows")
	return cmd
}
