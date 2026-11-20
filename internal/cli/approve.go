// SPDX-License-Identifier: AGPL-3.0-only

package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/heliopsy/scrim/internal/approval"
	"github.com/heliopsy/scrim/internal/breakglass"
)

// Operator commands for approvals, grants and break-glass. They talk to the
// running control plane through the admin API (admin.url), which identifies
// the operator from the connection.

func adminClient(e *Env) (*approval.Client, error) {
	cfg, err := e.Config()
	if err != nil {
		return nil, err
	}
	return approval.NewClient(approval.AdminURL.Get(cfg))
}

// printer writes formatted output and keeps the first write error.
type printer struct {
	w   io.Writer
	err error
}

func (p *printer) f(format string, a ...any) {
	if p.err == nil {
		_, p.err = fmt.Fprintf(p.w, format, a...)
	}
}

func printJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// Approve approves a pending approval from the terminal.
func (Commands) Approve(e *Env) *cobra.Command {
	return decideCommand(e, true)
}

// Deny denies a pending approval from the terminal.
func (Commands) Deny(e *Env) *cobra.Command {
	return decideCommand(e, false)
}

func decideCommand(e *Env, approve bool) *cobra.Command {
	var (
		ttl    time.Duration
		reason string
		asJSON bool
	)
	verb, short := "deny", "Deny a pending approval"
	if approve {
		verb, short = "approve", "Approve a pending approval and create its grant"
	}
	c := &cobra.Command{
		Use:   verb + " <approval-id>",
		Short: short,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			o := &printer{w: e.Stdout}
			cl, err := adminClient(e)
			if err != nil {
				return err
			}
			res, err := cl.Decide(cmd.Context(), args[0], approve, ttl, reason)
			if err != nil {
				switch {
				case errors.Is(err, approval.ErrSettled):
					return fmt.Errorf("approval %s was already decided: %w", args[0], err)
				case errors.Is(err, breakglass.ErrActive):
					return fmt.Errorf("break-glass deny-all is active; nothing can be approved: %w", err)
				}
				return err
			}
			if asJSON {
				return printJSON(e.Stdout, res)
			}
			o.f("%s %s (%s, rule %s)\n", res.Approval.ID, res.Approval.Status, res.Approval.Agent, res.Approval.Rule)
			if res.GrantID != "" {
				o.f("grant %s for %s", res.GrantID, res.GrantTTL)
				if res.Capped {
					o.f(" (capped at the rule's maximum)")
				}
				o.f("\n")
			}
			return o.err
		},
	}
	if approve {
		c.Flags().DurationVar(&ttl, "ttl", 0, "grant duration (default: the rule's grant ttl; capped at its maximum)")
	}
	c.Flags().StringVar(&reason, "reason", "", "reason recorded in the audit log")
	c.Flags().BoolVar(&asJSON, "json", false, "print the result as JSON")
	return c
}

// Approvals lists and shows approvals.
func (Commands) Approvals(e *Env) *cobra.Command {
	c := &cobra.Command{Use: "approvals", Short: "List and inspect approvals"}
	var (
		status, agent string
		asJSON        bool
	)
	list := &cobra.Command{
		Use:   "list",
		Short: "List approvals (pending by default)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			o := &printer{w: e.Stdout}
			cl, err := adminClient(e)
			if err != nil {
				return err
			}
			if status == "all" {
				status = ""
			}
			as, err := cl.ListApprovals(cmd.Context(), status, agent)
			if err != nil {
				return err
			}
			if asJSON {
				return printJSON(e.Stdout, as)
			}
			if len(as) == 0 {
				o.f("no approvals\n")
				return o.err
			}
			tw := tabwriter.NewWriter(e.Stdout, 0, 4, 2, ' ', 0)
			t := &printer{w: tw}
			t.f("ID\tSTATUS\tAGENT\tSECRET\tDESTINATION\tRULE\tEXPIRES\n")
			for _, a := range as {
				t.f("%s\t%s\t%s\t%s\t%s\t%s\t%s\n", a.ID, a.Status, a.Agent, dash(a.Ref), dash(destination(a)), a.Rule,
					a.ExpiresAt.Local().Format(time.DateTime))
			}
			return errors.Join(t.err, tw.Flush())
		},
	}
	list.Flags().StringVar(&status, "status", "pending", "pending, approved, denied, expired or all")
	list.Flags().StringVar(&agent, "agent", "", "only approvals of this agent")
	list.Flags().BoolVar(&asJSON, "json", false, "print JSON")
	show := &cobra.Command{
		Use:   "show <approval-id>",
		Short: "Show one approval",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cl, err := adminClient(e)
			if err != nil {
				return err
			}
			a, err := cl.GetApproval(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			return printJSON(e.Stdout, a)
		},
	}
	c.AddCommand(list, show)
	return c
}

func destination(a approval.ApprovalView) string {
	switch {
	case a.Host != "":
		return strings.TrimSpace(a.Method + " " + a.Host + a.Path)
	case a.Tool != "":
		return strings.TrimSpace(a.Tool + " " + a.Command)
	}
	return a.Provider
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// Grants lists and revokes just-in-time grants.
func (Commands) Grants(e *Env) *cobra.Command {
	c := &cobra.Command{Use: "grants", Short: "List and revoke just-in-time grants"}
	var (
		agent  string
		all    bool
		asJSON bool
		reason string
	)
	list := &cobra.Command{
		Use:   "list",
		Short: "List active grants",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			o := &printer{w: e.Stdout}
			cl, err := adminClient(e)
			if err != nil {
				return err
			}
			gs, err := cl.ListGrants(cmd.Context(), agent, all)
			if err != nil {
				return err
			}
			if asJSON {
				return printJSON(e.Stdout, gs)
			}
			if len(gs) == 0 {
				o.f("no grants\n")
				return o.err
			}
			tw := tabwriter.NewWriter(e.Stdout, 0, 4, 2, ' ', 0)
			t := &printer{w: tw}
			t.f("ID\tAGENT\tSECRET\tSCOPE\tUSES\tEXPIRES\tACTIVE\n")
			for _, g := range gs {
				uses := fmt.Sprint(g.Uses)
				if g.MaxUses > 0 {
					uses += "/" + fmt.Sprint(g.MaxUses)
				}
				scope := strings.Join(append(append([]string{}, g.Hosts...), g.Tools...), ",")
				t.f("%s\t%s\t%s\t%s\t%s\t%s\t%v\n", g.ID, g.Agent, g.Ref, dash(scope), uses,
					g.ExpiresAt.Local().Format(time.DateTime), g.Active)
			}
			return errors.Join(t.err, tw.Flush())
		},
	}
	list.Flags().StringVar(&agent, "agent", "", "only grants of this agent")
	list.Flags().BoolVar(&all, "all", false, "include expired, revoked and used-up grants")
	list.Flags().BoolVar(&asJSON, "json", false, "print JSON")
	revoke := &cobra.Command{
		Use:   "revoke <grant-id>",
		Short: "Revoke a grant at once",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			o := &printer{w: e.Stdout}
			cl, err := adminClient(e)
			if err != nil {
				return err
			}
			g, err := cl.RevokeGrant(cmd.Context(), args[0], reason)
			if err != nil {
				return err
			}
			o.f("grant %s revoked\n", g.ID)
			return o.err
		},
	}
	revoke.Flags().StringVar(&reason, "reason", "", "reason recorded in the audit log")
	c.AddCommand(list, revoke)
	return c
}

// DenyAll engages, releases or shows the break-glass switch.
func (Commands) DenyAll(e *Env) *cobra.Command {
	var reason string
	c := &cobra.Command{
		Use:       "deny-all <on|off|status>",
		Short:     "Break-glass: deny every injection, grant and approval while redaction continues",
		Args:      cobra.ExactArgs(1),
		ValidArgs: []string{"on", "off", "status"},
		RunE: func(cmd *cobra.Command, args []string) error {
			o := &printer{w: e.Stdout}
			cl, err := adminClient(e)
			if err != nil {
				return err
			}
			var st breakglass.Status
			switch args[0] {
			case "on":
				st, err = cl.SetDenyAll(cmd.Context(), true, reason)
			case "off":
				st, err = cl.SetDenyAll(cmd.Context(), false, reason)
				if errors.Is(err, breakglass.ErrConfigured) {
					return fmt.Errorf("deny-all is set by policy.deny-all in configuration; change it there: %w", err)
				}
			case "status":
				st, err = cl.DenyAll(cmd.Context())
			default:
				return fmt.Errorf("want on, off or status, not %q", args[0])
			}
			if err != nil {
				return err
			}
			switch {
			case !st.Active:
				o.f("deny-all is off\n")
			case st.Configured:
				o.f("deny-all is ON (policy.deny-all in configuration)\n")
			default:
				o.f("deny-all is ON since %s by %s", st.Since.Local().Format(time.DateTime), st.By)
				if st.Reason != "" {
					o.f(": %s", st.Reason)
				}
				o.f("\n")
			}
			return o.err
		},
	}
	c.Flags().StringVar(&reason, "reason", "", "reason recorded in the audit log")
	return c
}
