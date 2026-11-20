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
	"github.com/heliopsy/scrim/internal/obs"
)

// captureDefault is what a bare --capture parses to.
const captureDefault = "\x00default"

// metricsDefault is what a bare --metrics parses to.
const metricsDefault = "\x00default"

// Proxy serves the LLM proxy and the tool proxy: the scrim daemon.
func (Commands) Proxy(e *Env) *cobra.Command {
	var capture, metrics string
	cmd := &cobra.Command{
		Use:   "proxy",
		Short: "Run the scrim daemon: LLM proxy, tool proxy, agent API and admin API",
		Long: "Runs the control plane and the data plane until SIGINT or SIGTERM: the LLM proxy base URL (proxy.listen), " +
			"the optional Unix socket, forward proxy and tool proxy listeners, the agent API socket (api.socket), the " +
			"entry page, the admin API (admin.url) and, with metrics.enabled, Prometheus metrics and health on metrics.listen.\n\n" +
			"--metrics turns on metrics.enabled for this run on the default 127.0.0.1:9792; --metrics=ADDR also sets " +
			"metrics.listen.\n\n" +
			"Traffic is refused until the data plane holds its first snapshot. The configuration reloads on SIGHUP " +
			"and on file changes; listener addresses need a restart.\n\n" +
			"--capture=DIR turns on capture mode: every provider request exactly as it left, and the response as " +
			"received, is written to DIR (mode 0700; --capture alone uses $XDG_STATE_HOME/scrim/capture) so you can check what the provider saw. " +
			"The value is optional, so it needs the = form; a directory after a space is refused as an extra argument. Agent credentials are " +
			"masked in captured headers.",
		Example: "  scrim proxy\n  scrim proxy --metrics\n  scrim proxy --capture\n  scrim proxy --capture=\"$HOME/scrim-capture\"\n  ANTHROPIC_BASE_URL=http://127.0.0.1:9790/anthropic claude",
		Args: func(_ *cobra.Command, args []string) error {
			// Both flags take an optional value, so a value after a space
			// arrives as an argument; say which form to use.
			if len(args) > 0 && capture == captureDefault {
				return fmt.Errorf("unexpected argument %q: --capture takes its directory as --capture=DIR", args[0])
			}
			if len(args) > 0 && metrics == metricsDefault {
				return fmt.Errorf("unexpected argument %q: --metrics takes its address as --metrics=ADDR", args[0])
			}
			return cobra.NoArgs(nil, args)
		},
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
			if metrics != "" {
				// Same precedence as --metrics-enabled and --metrics-listen.
				flags := e.root.PersistentFlags()
				if err := flags.Set(config.FlagName(obs.MetricsEnabled.Name()), "true"); err != nil {
					return err
				}
				if metrics != metricsDefault {
					if err := flags.Set(config.FlagName(obs.MetricsListen.Name()), metrics); err != nil {
						return err
					}
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
	cmd.Flags().StringVar(&capture, "capture", "", "capture mode: write every provider request and response to this directory, given as --capture=DIR (proxy.capture.dir); --capture alone uses $XDG_STATE_HOME/scrim/capture")
	cmd.Flags().Lookup("capture").NoOptDefVal = captureDefault
	cmd.Flags().StringVar(&metrics, "metrics", "", "serve Prometheus metrics (metrics.enabled); --metrics=ADDR also sets metrics.listen")
	cmd.Flags().Lookup("metrics").NoOptDefVal = metricsDefault
	return cmd
}
