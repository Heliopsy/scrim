// SPDX-License-Identifier: AGPL-3.0-only

package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/heliopsy/scrim/internal/agentapi"
	"github.com/heliopsy/scrim/internal/mcp"
	"github.com/heliopsy/scrim/internal/version"
)

// MCP serves the agent tools over MCP on stdio.
func (Commands) MCP(e *Env) *cobra.Command {
	return &cobra.Command{
		Use:   "mcp",
		Short: "Serve the agent tools over MCP (stdio)",
		Long: "Serves secrets_list, secret_request, secret_gen, secret_capture, secret_ask_human, approval_status " +
			"and grants_list over MCP on standard input and output. Each call goes to the local scrim API with this " +
			"process's identity: its peer credentials, and SCRIM_SESSION_TOKEN when it runs inside scrim run.\n\n" +
			"Register it with an agent, for example: claude mcp add scrim -- scrim mcp",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := agentClient(e)
			if err != nil {
				return err
			}
			defer c.Close()
			return mcp.Serve(cmd.Context(), mcp.NewServer(c, version.Version), e.Stdin, e.Stdout)
		},
	}
}

// API runs and inspects the control plane's local agent API.
func (Commands) API(e *Env) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "api",
		Short: "Run or inspect the local agent API",
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "serve",
		Short: "Serve the local agent API and the human entry page until interrupted",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, stop := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()
			a, err := e.App(ctx)
			if err != nil {
				return err
			}
			rt, err := agentapi.New(a, agentapi.Options{Stderr: e.Stderr})
			if err != nil {
				return err
			}
			rt.LogAddresses(a.Log)
			_, _ = fmt.Fprintf(e.Stderr, "scrim: agent API on %s, entry page on %s\n", rt.Socket, rt.EntryURL)
			if err := rt.Serve(ctx); err != nil && !errors.Is(err, context.Canceled) {
				return err
			}
			return nil
		},
	}, &cobra.Command{
		Use:   "whoami",
		Short: "Show the identity the local agent API gives this process",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			p, err := newPrinter(cmd)
			if err != nil {
				return err
			}
			c, err := agentClient(e)
			if err != nil {
				return err
			}
			defer c.Close()
			id, err := c.WhoAmI(cmd.Context())
			if err != nil {
				return p.fail(err)
			}
			return p.emit(id, func(w io.Writer) {
				if !id.Known() {
					_, _ = fmt.Fprintf(w, "unknown caller (uid %d): this local user is not mapped to an agent\n", id.Peer.UID)
					return
				}
				_, _ = fmt.Fprintf(w, "agent %s via %s (uid %d, pid %d)\n", id.Agent, id.Source, id.Peer.UID, id.Peer.PID)
				if id.SessionID != "" {
					_, _ = fmt.Fprintf(w, "session %s %s expires %s\n", id.SessionID, id.SessionName, ts(id.ExpiresAt))
				}
				_, _ = fmt.Fprintf(w, "scopes %v\n", id.Scopes)
			})
		},
	})
	cmd.PersistentFlags().StringP("output", "o", "text", "output format: text or json")
	return cmd
}
