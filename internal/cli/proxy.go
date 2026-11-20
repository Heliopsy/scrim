// SPDX-License-Identifier: AGPL-3.0-only

package cli

import (
	"context"
	"errors"
	"fmt"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/daemon"
)

// captureDefault is what a bare --capture parses to.
const captureDefault = "\x00default"

// Proxy serves the LLM proxy and the tool proxy: the scrim daemon.
func (Commands) Proxy(e *Env) *cobra.Command {
	var capture string
	cmd := &cobra.Command{
		Use:   "proxy",
		Short: "Run the scrim daemon: LLM proxy, tool proxy, agent API and admin API",
		Long: "Runs the control plane and the data plane until SIGINT or SIGTERM: the LLM proxy base URL (proxy.listen), " +
			"the optional Unix socket, forward proxy and tool proxy listeners, the agent API socket (api.socket), the " +
			"entry page, the admin API (admin.url) and, when metrics.listen is set, /metrics and health.\n\n" +
			"Traffic is refused until the data plane holds its first snapshot. The configuration reloads on SIGHUP " +
			"and on file changes; listener addresses need a restart.\n\n" +
			"--capture DIR turns on capture mode: every provider request exactly as it left, and the response as " +
			"received, is written to DIR (mode 0700; --capture alone uses $XDG_STATE_HOME/scrim/capture) so you can check what the provider saw. Agent credentials are " +
			"masked in captured headers.",
		Example: "  scrim proxy\n  scrim proxy --capture ~/scrim-capture\n  ANTHROPIC_BASE_URL=http://127.0.0.1:9790/anthropic claude",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if capture == captureDefault {
				cfg, err := e.Config()
				if err != nil {
					return err
				}
				dir, err := cfg.StateDir()
				if err != nil {
					return err
				}
				capture = filepath.Join(dir, "capture")
				e.resetConfig()
			}
			if capture != "" {
				// Same precedence as --proxy-capture-dir.
				if err := e.root.PersistentFlags().Set(config.FlagName(daemon.CaptureDir.Name()), capture); err != nil {
					return err
				}
			}
			if _, err := e.Config(); err != nil {
				return err
			}
			ctx, stop := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()
			err := daemon.Run(ctx, daemon.Options{Config: e.ConfigOptions(), LogOutput: e.Stderr})
			if err != nil && !errors.Is(err, context.Canceled) {
				return fmt.Errorf("proxy: %w", err)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&capture, "capture", "", "capture mode: write every provider request and response to this directory (proxy.capture.dir); --capture alone uses $XDG_STATE_HOME/scrim/capture")
	cmd.Flags().Lookup("capture").NoOptDefVal = captureDefault
	return cmd
}
