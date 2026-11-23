// SPDX-License-Identifier: AGPL-3.0-only

package cli

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/heliopsy/scrim/internal/edge"
	"github.com/heliopsy/scrim/internal/obs"
)

// Edge runs the edge forwarder of an agent pod.
func (Commands) Edge(e *Env) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "edge",
		Short: "Forward an agent pod's ssh-agent, database ports and agent API to a central scrim",
		Long: "Serves SSH_AUTH_SOCK, loopback database ports and the agent API socket (the exec broker included) in an " +
			"agent pod and carries every connection to the central scrim's edge listener over TLS, with the pod's " +
			"projected service account token. It holds no secret: keys, database passwords and exec secrets stay in " +
			"the central scrim. A connection the central scrim cannot take is refused. Settings: edge-forwarder.*.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, stop := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()
			f, cfgLog, err := edgeForwarder(e)
			if err != nil {
				return err
			}
			cfg, err := e.Config()
			if err != nil {
				return err
			}
			eps, err := edge.Listen(cfg, f)
			if err != nil {
				return err
			}
			for _, ep := range eps {
				cfgLog.Info("edge forwarder listening", "endpoint", ep.Name, "address", ep.Addr, "central", f.Central)
			}
			if err := edge.Serve(ctx, eps); err != nil && !errors.Is(err, context.Canceled) {
				return err
			}
			return nil
		},
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "check",
		Short: "Check that the central scrim accepts this pod (for a startup probe)",
		Long: "Connects to the central scrim's edge listener with this pod's token and prints the agent it was " +
			"verified as. Exits non-zero when the central scrim is unreachable, its certificate does not verify " +
			"against scrim's CA, or it refuses the token.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			f, _, err := edgeForwarder(e)
			if err != nil {
				return err
			}
			id, err := f.Check(cmd.Context())
			if err != nil {
				return err
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s (%s)\n", id.Agent, id.Source)
			return nil
		},
	})
	return cmd
}

func edgeForwarder(e *Env) (*edge.Forwarder, *slog.Logger, error) {
	cfg, err := e.Config()
	if err != nil {
		return nil, nil, err
	}
	log, err := obs.LoggerFromConfig(e.Stderr, cfg, nil)
	if err != nil {
		return nil, nil, err
	}
	log = obs.WithComponent(log, "edge-forwarder")
	f, err := edge.FromConfig(cfg, log)
	if err != nil {
		return nil, nil, err
	}
	return f, log, nil
}
