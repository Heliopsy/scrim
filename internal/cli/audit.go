// SPDX-License-Identifier: AGPL-3.0-only

package cli

import (
	"errors"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/heliopsy/scrim/internal/auditlog"
	"github.com/heliopsy/scrim/internal/state"
	"github.com/heliopsy/scrim/internal/state/sqlite"
	"github.com/heliopsy/scrim/internal/status"
)

// Audit groups the audit log commands and the leak suite (`audit run`, in
// audit_run.go).
func (Commands) Audit(e *Env) *cobra.Command {
	c := &cobra.Command{
		Use:   "audit",
		Short: "Query the audit log of decisions, approvals, grants, store writes and injections",
		Args:  cobra.NoArgs,
	}
	c.AddCommand(auditLog(e), newAuditRunCmd(e))
	return c
}

func auditLog(e *Env) *cobra.Command {
	var (
		out          outputFlags
		f            auditlog.Filter
		since, until string
	)
	c := &cobra.Command{
		Use:   "log",
		Short: "List audit entries, newest first",
		Example: "  scrim audit log --agent claude-laptop --decision ask --since 1h\n" +
			"  scrim audit log --ref bao://kv/gh#token --outcome refused -o json",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			format, err := out.format()
			if err != nil {
				return err
			}
			now := time.Now()
			if f.Since, err = auditlog.ParseTime(since, now); err != nil {
				return fmt.Errorf("--since: %w", err)
			}
			if f.Until, err = auditlog.ParseTime(until, now); err != nil {
				return fmt.Errorf("--until: %w", err)
			}
			if _, err := f.Query(); err != nil {
				return err
			}
			cfg, err := e.Config()
			if err != nil {
				return err
			}
			s, err := state.Open(cmd.Context(), cfg)
			var locked *sqlite.LockedError
			if errors.As(err, &locked) {
				return fmt.Errorf("%w; stop it or query its admin API", err)
			}
			if err != nil {
				return err
			}
			defer func() { _ = s.Close() }()
			if err := s.Migrate(cmd.Context()); err != nil {
				return err
			}
			p, err := auditlog.Run(cmd.Context(), s, f)
			if err != nil {
				return err
			}
			if format == "json" {
				return status.WriteJSON(cmd.OutOrStdout(), p)
			}
			return auditlog.WriteHuman(cmd.OutOrStdout(), p)
		},
	}
	out.bind(c)
	fl := c.Flags()
	fl.StringVar(&f.Agent, "agent", "", "only entries about this agent ID")
	fl.StringVar(&f.Ref, "ref", "", "only entries about this secret reference")
	fl.StringVar(&f.Action, "action", "", "only this action, for example decision or grant.revoked")
	fl.StringVar(&f.Decision, "decision", "", "only this decision: allow, deny or ask")
	fl.StringVar(&f.Outcome, "outcome", "", "only this outcome: ok, refused, failed or pending")
	fl.StringVar(&since, "since", "", "entries at or after this RFC 3339 time or duration ago (1h)")
	fl.StringVar(&until, "until", "", "entries before this RFC 3339 time or duration ago")
	fl.Int64Var(&f.Before, "before", 0, "page cursor: entries with an ID below this")
	fl.IntVar(&f.Limit, "limit", auditlog.DefaultLimit, "maximum entries")
	return c
}
