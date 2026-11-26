// SPDX-License-Identifier: AGPL-3.0-only

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/heliopsy/scrim/internal/catalog"
	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/fsview"
	"github.com/heliopsy/scrim/internal/obs"
	"github.com/heliopsy/scrim/internal/profiles"
	agentrun "github.com/heliopsy/scrim/internal/run"
)

// ExitRunRefused is scrim run's exit code when it refuses to start the
// agent, following env(1) and timeout(1): 125 is the wrapper's own failure,
// so any other code is the agent's.
const ExitRunRefused = 125

// runDaemon returns the scrim that serves scrim run: the daemon behind
// admin.url, or one started in this process for the run. Tests replace it.
var runDaemon = func(_ context.Context, e *Env) (agentrun.Daemon, error) {
	return runDaemonFor(e), nil
}

// Run runs an agent with its traffic through scrim.
func (Commands) Run(e *Env) *cobra.Command {
	var (
		agent, name, output string
		printEnv            bool
		ttl                 time.Duration
	)
	cmd := &cobra.Command{
		Use:   "run [flags] -- <agent> [args...]",
		Short: "Run an agent with its traffic through scrim",
		Long: "Starts the agent as a child process with its provider base URLs pointed at scrim's LLM proxy, " +
			"its tool traffic through scrim's forward proxy with scrim's CA trusted for that process only, " +
			"a session token bound to this process tree, scrim mcp registered and declared placeholders exported. " +
			"Nothing outside the session changes, and the session ends when the agent exits.\n\n" +
			"scrim run refuses to start the agent (exit 125) when scrim cannot serve it; run.allow-unredacted-start " +
			"weakens that. Otherwise it exits with the agent's status.\n\n" +
			"Presets: claude (Claude Code), codex (Codex CLI), opencode (OpenCode), generic. See docs/run.md.",
		Example: "  scrim run -- claude\n  scrim run -- codex exec 'fix the failing test'\n  scrim run -- opencode run 'fix the failing test'\n  scrim run --print-env -- claude",
		Args:    cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := e.Config()
			if err != nil {
				return err
			}
			o := agentrun.Options{
				Command: args, Environ: e.Environ, Stdin: e.Stdin, Stdout: e.Stdout, Stderr: e.Stderr,
				MCP: agentrun.MCP.Get(cfg), SessionName: name, SessionTTL: ttl,
				AllowUnredacted: agentrun.AllowUnredactedStart.Get(cfg),
				Reserved:        agentrun.ReservedBy(e.Registry),
				ScanProject:     agentrun.ScanProject.Get(cfg),
				ScanInterval:    agentrun.ScanInterval.Get(cfg),
				FSView:          agentrun.FSViewOptions{Mode: fsview.Setting.Get(cfg), Hide: fsview.Hide.Get(cfg)},
				SSHAgent:        agentrun.SSHAgent.Get(cfg),
			}
			if log, err := obs.LoggerFromConfig(e.Stderr, cfg, nil); err == nil {
				o.Log = obs.WithComponent(log, "run")
			}
			if agent != "" {
				if o.Preset, err = agentrun.PresetNamed(agent); err != nil {
					return &ExitCodeError{Code: ExitRunRefused, Err: err}
				}
			}
			if agentrun.PlaceholderEnv.Get(cfg) {
				o.Placeholders = func(ctx context.Context, agentName string) ([]string, error) {
					sel := catalog.SelectionFrom(cfg)
					sel.Agent = agentName
					cat, err := catalog.Load(ctx, cfg, nil, sel)
					if err != nil {
						return nil, err
					}
					return cat.Placeholders(), nil
				}
			}
			want := profiles.Enabled.Get(cfg)
			if !slices.Contains(want, profiles.None) {
				o.Profiles = func(ctx context.Context, agentName string, sess profiles.Session) (*profiles.Rendered, error) {
					return renderProfiles(ctx, cfg, agentName, want, sess)
				}
			}
			ctx := cmd.Context()
			d, err := runDaemon(ctx, e)
			if err != nil {
				return &ExitCodeError{Code: ExitRunRefused, Err: err}
			}
			o.Daemon = d
			if printEnv {
				plan, err := agentrun.PrintEnv(ctx, o)
				if err != nil {
					return &ExitCodeError{Code: ExitRunRefused, Err: err}
				}
				return writePlan(cmd.OutOrStdout(), plan, output)
			}
			return runExit(agentrun.Run(ctx, o))
		},
	}
	f := cmd.Flags()
	// Everything after the agent's name is the agent's.
	f.SetInterspersed(false)
	f.StringVar(&agent, "agent", "", "agent preset: claude, codex, opencode or generic (default: from the command name)")
	f.BoolVar(&printEnv, "print-env", false, "print what would be set for the agent and exit; the session token is never printed")
	f.StringVarP(&output, "output", "o", "text", "--print-env format: text or json")
	f.StringVar(&name, "name", "", "session name shown in audit and whoami (default: the agent's command name)")
	f.DurationVar(&ttl, "ttl", 0, "session token lifetime (default session.ttl); the session ends earlier when the agent exits")
	return cmd
}

// renderProfiles selects and renders the session's tool profiles against the
// catalog the agent's session resolves.
func renderProfiles(ctx context.Context, cfg *config.Config, agentName string, want []string, sess profiles.Session) (*profiles.Rendered, error) {
	set, err := profiles.Load(cfg)
	if err != nil {
		return nil, err
	}
	sel := catalog.SelectionFrom(cfg)
	sel.Agent = agentName
	cat, err := catalog.Load(ctx, cfg, nil, sel)
	if err != nil {
		return nil, err
	}
	chosen, err := set.Select(want, cat)
	if err != nil {
		return nil, err
	}
	r, err := profiles.Render(chosen.Profiles, cat, sess)
	if err != nil {
		return nil, err
	}
	r.Warnings = append(chosen.Warnings, r.Warnings...)
	return r, nil
}

// runExit maps the run's outcome to scrim's exit code.
func runExit(err error) error {
	if err == nil {
		return nil
	}
	var xe *agentrun.ExitError
	if errors.As(err, &xe) {
		return &ExitCodeError{Code: xe.Code}
	}
	return &ExitCodeError{Code: ExitRunRefused, Err: err}
}

func writePlan(w io.Writer, p *agentrun.Plan, format string) error {
	switch format {
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(planJSON(p))
	case "text", "":
	default:
		return fmt.Errorf("unknown output format %q (text, json)", format)
	}
	_, _ = fmt.Fprintf(w, "preset   %s\ncommand  %s\n\nset\n", p.Preset, strings.Join(p.Args, " "))
	width := 0
	for _, v := range p.Set {
		width = max(width, len(v.Name)+1+len(v.Value))
	}
	for _, v := range p.Set {
		kv := v.Name + "=" + v.Value
		if v.Secret && v.Value == "" {
			kv = v.Name + "=<secret>"
		}
		_, _ = fmt.Fprintf(w, "  %-*s  # %s\n", width, kv, v.Why)
	}
	if len(p.Profiles) > 0 {
		_, _ = fmt.Fprintf(w, "\ntool profiles\n  %s\n", strings.Join(p.Profiles, "\n  "))
	}
	if len(p.Project) > 0 {
		_, _ = fmt.Fprintf(w, "\nproject values (redacted for the session; scrim project move moves them into a store)\n  %s\n", strings.Join(p.Project, "\n  "))
	}
	if len(p.Unset) > 0 {
		_, _ = fmt.Fprintf(w, "\nunset\n  %s\n", strings.Join(p.Unset, "\n  "))
	}
	if files := fileNames(p); len(files) > 0 {
		_, _ = fmt.Fprintf(w, "\nsession files (in <session-dir>, removed when the agent exits)\n  %s\n", strings.Join(files, "\n  "))
	}
	writeView(w, p.FSView)
	if len(p.Warnings) > 0 {
		_, _ = fmt.Fprintf(w, "\nwarnings\n  %s\n", strings.Join(p.Warnings, "\n  "))
	}
	return nil
}

// writeView prints the session filesystem view.
func writeView(w io.Writer, v *fsview.Plan) {
	if v == nil {
		return
	}
	head := v.Mode
	switch {
	case v.Fallback != "":
		head += " (fallback: " + v.Fallback + ")"
	case v.Mode == fsview.ModeNamespace:
		head += " (user and mount namespace)"
	}
	_, _ = fmt.Fprintf(w, "\nfilesystem view: %s\n", head)
	if v.Mode != fsview.ModeOff && len(v.Entries) == 0 {
		_, _ = fmt.Fprintln(w, "  nothing to cover")
	}
	for _, e := range v.Entries {
		what := "hidden"
		if !e.Hidden() {
			what = "shows " + e.Source
		}
		_, _ = fmt.Fprintf(w, "  %s  %s  (%s)\n", e.Target, what, e.Origin)
	}
	for _, g := range v.Gaps {
		_, _ = fmt.Fprintf(w, "  not covered: %s\n", g)
	}
}

func fileNames(p *agentrun.Plan) []string {
	files := make([]string, 0, len(p.Files))
	for n := range p.Files {
		files = append(files, n)
	}
	sort.Strings(files)
	return files
}

func planJSON(p *agentrun.Plan) any {
	return struct {
		*agentrun.Plan
		Files []string `json:"files,omitempty"`
	}{p, fileNames(p)}
}
