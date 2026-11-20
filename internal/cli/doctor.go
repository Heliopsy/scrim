// SPDX-License-Identifier: AGPL-3.0-only

package cli

import (
	"errors"
	"io"
	"time"

	"github.com/spf13/cobra"

	"github.com/heliopsy/scrim/internal/state"
	"github.com/heliopsy/scrim/internal/state/sqlite"
	"github.com/heliopsy/scrim/internal/status"
)

// ErrDoctorFailed is returned when any doctor check fails, so the command
// exits non-zero after printing its findings.
var ErrDoctorFailed = errors.New("one or more checks failed")

// Doctor checks the local setup and suggests fixes
// (specs/observability "Doctor command").
func (Commands) Doctor(e *Env) *cobra.Command {
	var (
		out     outputFlags
		timeout time.Duration
	)
	c := &cobra.Command{
		Use:   "doctor",
		Short: "Check the local setup and suggest a fix for each problem",
		Long: "Check the state location and backend, store reachability, the data plane, audit sinks and weakened " +
			"settings, print each problem with a suggested fix, and exit non-zero when any check fails.",
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
			cfg, _ := e.Config()
			r := status.Collect(cmd.Context(), src)
			checks := status.ReportChecks(r)
			if state.BackendSetting.Get(cfg) == sqlite.Name {
				path, _ := sqlite.PathFor(cfg)
				checks = append(checks, status.StateLocationCheck(path))
			}
			d := status.Diagnose(cmd.Context(), timeout, checks...)
			if err := writeOut(cmd.OutOrStdout(), format, d, func(w io.Writer) error { return status.WriteDiagnosis(w, d) }); err != nil {
				return err
			}
			if !d.OK() {
				return ErrDoctorFailed
			}
			return nil
		},
	}
	out.bind(c)
	c.Flags().DurationVar(&timeout, "timeout", 10*time.Second, "time limit for each check")
	return c
}
