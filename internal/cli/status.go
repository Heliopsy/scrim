// SPDX-License-Identifier: AGPL-3.0-only

package cli

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/dataplane"
	"github.com/heliopsy/scrim/internal/state"
	"github.com/heliopsy/scrim/internal/state/sqlite"
	"github.com/heliopsy/scrim/internal/status"
	"github.com/heliopsy/scrim/internal/version"
)

// Status reports what scrim protects and what is degraded
// (specs/observability "Status command").
func (Commands) Status(e *Env) *cobra.Command {
	var out outputFlags
	c := &cobra.Command{
		Use:   "status",
		Short: "Report protections, interception, stores, state and weakened settings",
		Long: "Report the version, active interception modes and protections, providers, stores with their health, " +
			"the state backend, audit sinks, the data plane, degraded components and every weakened setting in effect.\n\n" +
			"Exits 0 whenever the report could be produced; use `scrim doctor` for a pass or fail answer.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			format, err := out.format()
			if err != nil {
				return err
			}
			src, closeFn, err := statusSources(cmd.Context(), e)
			if err != nil {
				return err
			}
			defer closeFn()
			r := status.Collect(cmd.Context(), src)
			if format == "json" {
				return status.WriteJSON(cmd.OutOrStdout(), r)
			}
			return status.WriteHuman(cmd.OutOrStdout(), r)
		},
	}
	out.bind(c)
	return c
}

// outputFlags is the -o/--output and --json pair shared by status, doctor
// and audit.
type outputFlags struct {
	output string
	json   bool
}

func (o *outputFlags) bind(c *cobra.Command) {
	c.Flags().StringVarP(&o.output, "output", "o", "text", "output format: text or json")
	c.Flags().BoolVar(&o.json, "json", false, "shorthand for --output json")
}

func (o *outputFlags) format() (string, error) {
	if o.json {
		return "json", nil
	}
	switch o.output {
	case "text", "json":
		return o.output, nil
	}
	return "", fmt.Errorf("--output %q is not one of text, json", o.output)
}

// statusSources gathers what this process can see: the effective
// configuration, the state backend and the configured stores. A SQLite file
// held by a running scrim is reported as in use, not as a failure. The data
// plane is checked by starting it once (dataplane.Probe). Interception modes
// and protections are reported by the running daemon; until the admin API
// serves them they show as not reported, never as healthy.
func statusSources(ctx context.Context, e *Env) (status.Sources, func(), error) {
	cfg, err := e.Config()
	if err != nil {
		return status.Sources{}, nil, err
	}
	m, err := config.NewManager(e.ConfigOptions(), nil)
	if err != nil {
		return status.Sources{}, nil, err
	}
	src := status.Sources{Version: version.String(), Config: m}
	src.DataPlane = dataplane.Probe{
		Path:    dataplane.PathSetting.Get(cfg),
		Options: dataplane.StartOptions{Mlock: dataplane.MlockSetting.Get(cfg)},
		Timeout: dataplane.StartTimeout.Get(cfg),
	}
	st, closeFn := openStateForStatus(ctx, cfg)
	src.State = st
	src.Audit = status.DBAuditSink{State: st}
	return src, closeFn, nil
}

func openStateForStatus(ctx context.Context, cfg *config.Config) (status.StateOf, func()) {
	name := state.BackendSetting.Get(cfg)
	s, err := state.Open(ctx, cfg)
	var locked *sqlite.LockedError
	switch {
	case errors.As(err, &locked):
		holder := "another process"
		if locked.PID > 0 {
			holder = fmt.Sprintf("scrim process %d", locked.PID)
		}
		return status.StateOf{Name: name, Info: locked.Path + " is in use by " + holder}, func() {}
	case err != nil:
		return status.StateOf{Name: name, Err: err}, func() {}
	}
	if err := s.Migrate(ctx); err != nil {
		_ = s.Close()
		return status.StateOf{Name: name, Err: err}, func() {}
	}
	return status.StateOf{Store: s}, func() { _ = s.Close() }
}

// writeOut writes v as JSON or through human.
func writeOut(w io.Writer, format string, v any, human func(io.Writer) error) error {
	if format == "json" {
		return status.WriteJSON(w, v)
	}
	return human(w)
}
