// SPDX-License-Identifier: AGPL-3.0-only

package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/heliopsy/scrim/internal/catalog"
	"github.com/heliopsy/scrim/internal/profiles"
)

// Profiles lists, shows and tests tool profiles.
func (Commands) Profiles(e *Env) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "profiles",
		Short: "List, show and test tool profiles for command-line tools",
		Long: "A tool profile says where a command-line tool (gh, git, kubectl, aws, ...) reads its credentials and " +
			"which hosts it sends them to. scrim run generates that configuration with placeholders in the session " +
			"directory, points the tool at it with the tool's own override variables and removes it when the agent " +
			"exits. A catalog entry fills a profile by naming it in its tools list. See docs/cli-tools.md.",
	}
	cmd.AddCommand(profilesList(e), profilesShow(e), profilesTest(e))
	return cmd
}

func loadProfiles(cmd *cobra.Command, e *Env) (*profiles.Set, *catalog.Catalog, []string, error) {
	cfg, err := e.Config()
	if err != nil {
		return nil, nil, nil, err
	}
	set, err := profiles.Load(cfg)
	if err != nil {
		return nil, nil, nil, err
	}
	cat, err := catalog.Load(cmd.Context(), cfg, nil, catalog.SelectionFrom(cfg))
	if err != nil {
		return nil, nil, nil, err
	}
	return set, cat, profiles.Enabled.Get(cfg), nil
}

type profileRow struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Builtin     bool     `json:"builtin"`
	Overridden  bool     `json:"overridden,omitempty"`
	Applied     bool     `json:"applied"`
	Entries     []string `json:"entries,omitempty"`
}

func profilesList(e *Env) *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List tool profiles and whether scrim run applies them",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			set, cat, want, err := loadProfiles(cmd, e)
			if err != nil {
				return err
			}
			sel, err := set.Select(want, cat)
			if err != nil {
				return err
			}
			var rows []profileRow
			for _, p := range set.All() {
				r := profileRow{Name: p.Name, Description: p.Description, Builtin: p.Builtin, Overridden: p.Overridden,
					Applied: slices.Contains(sel.Profiles, p)}
				for _, cs := range profiles.Filled(p, cat) {
					for _, c := range cs {
						r.Entries = append(r.Entries, c.Name)
					}
				}
				slices.Sort(r.Entries)
				rows = append(rows, r)
			}
			w := cmd.OutOrStdout()
			if asJSON {
				return writeJSON(w, map[string]any{"profiles": rows, "warnings": sel.Warnings})
			}
			tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
			_, _ = fmt.Fprintln(tw, "NAME\tAPPLIED\tENTRIES\tSOURCE\tDESCRIPTION")
			for _, r := range rows {
				src := "built-in"
				switch {
				case r.Overridden:
					src = "built-in, overridden"
				case !r.Builtin:
					src = "configuration"
				}
				_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", r.Name, yesNo(r.Applied), dash(strings.Join(r.Entries, ",")), src, r.Description)
			}
			_ = tw.Flush()
			for _, wn := range sel.Warnings {
				_, _ = fmt.Fprintf(w, "warning: %s\n", wn)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "print JSON")
	return cmd
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func profilesShow(e *Env) *cobra.Command {
	var (
		asJSON bool
		sample bool
	)
	cmd := &cobra.Command{
		Use:   "show <profile>",
		Short: "Show a tool profile and what it generates for the current catalog",
		Long: "Shows the profile's credential slots, the hosts and the catalog entries that fill them, and the " +
			"variables and files scrim run would generate (rendered under <session-dir>/profiles). With --sample, " +
			"every slot is filled with a sample placeholder. Only placeholders are ever shown.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			set, cat, _, err := loadProfiles(cmd, e)
			if err != nil {
				return err
			}
			p, ok := set.Get(args[0])
			if !ok {
				return fmt.Errorf("tool profile %q is not defined; scrim profiles list shows the profiles", args[0])
			}
			var b profiles.Bindings = cat
			if sample {
				b = profiles.SampleBindings(p, "SAMPLE")
			}
			r, err := profiles.Render([]*profiles.Profile{p}, b, profiles.Session{Dir: "<session-dir>/profiles",
				CABundle: "<session-dir>/ca-bundle.pem", Home: "~"})
			if err != nil {
				return err
			}
			w := cmd.OutOrStdout()
			if asJSON {
				files := map[string]string{}
				for _, f := range r.Files {
					files[f.Path] = string(f.Data)
				}
				return writeJSON(w, map[string]any{"profile": p, "filled": profiles.Filled(p, b), "rendered": r, "files": files})
			}
			_, _ = fmt.Fprintf(w, "%s: %s\n", p.Name, p.Description)
			if len(p.Tools) > 0 {
				_, _ = fmt.Fprintf(w, "tools     %s\n", strings.Join(p.Tools, ", "))
			}
			if len(p.Requires) > 0 {
				_, _ = fmt.Fprintf(w, "requires  %s\n", strings.Join(p.Requires, ", "))
			}
			filled := profiles.Filled(p, b)
			_, _ = fmt.Fprintln(w, "\ncredentials (catalog tools entry, default hosts, filled by)")
			for _, s := range p.Credentials {
				var by []string
				for _, c := range filled[s.Name] {
					by = append(by, c.Name+" ("+c.Placeholder+")")
				}
				req := ""
				if s.Required {
					req = " required"
				}
				_, _ = fmt.Fprintf(w, "  %s%s: tools [%s], hosts [%s], filled by %s\n", s.Name, req, p.ToolName(s.Name),
					strings.Join(s.Hosts, ", "), dash(strings.Join(by, ", ")))
			}
			if len(r.Env) > 0 {
				_, _ = fmt.Fprintln(w, "\nset")
				for _, v := range r.Env {
					_, _ = fmt.Fprintf(w, "  %s=%s\n", v.Name, v.Value)
				}
			}
			if len(r.Unset) > 0 {
				_, _ = fmt.Fprintf(w, "\nunset\n  %s\n", strings.Join(r.Unset, "\n  "))
			}
			for _, f := range r.Files {
				_, _ = fmt.Fprintf(w, "\nfile <session-dir>/profiles/%s\n", f.Path)
				for _, line := range strings.Split(strings.TrimRight(string(f.Data), "\n"), "\n") {
					_, _ = fmt.Fprintf(w, "  | %s\n", line)
				}
			}
			if len(r.Paths) > 0 {
				_, _ = fmt.Fprintln(w, "\nfixed paths (session filesystem view)")
				for _, pv := range r.Paths {
					show := "hidden"
					if pv.Generated != "" {
						show = "shows " + pv.Generated
					}
					_, _ = fmt.Fprintf(w, "  ~/%s: %s\n", pv.Home, show)
				}
			}
			for _, n := range p.Notes {
				_, _ = fmt.Fprintf(w, "\nnote: %s\n", n)
			}
			for _, wn := range r.Warnings {
				_, _ = fmt.Fprintf(w, "warning: %s\n", wn)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "print JSON")
	cmd.Flags().BoolVar(&sample, "sample", false, "fill every slot with a sample placeholder instead of the catalog")
	return cmd
}

func profilesTest(e *Env) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "test [profile...]",
		Short: "Check that installed tools read only the generated placeholder configuration",
		Long: "Runs each profile's test command (for example gh auth token, aws configure get, kubectl config view " +
			"--raw) with an empty home directory and the profile applied with sample placeholders. Decoys sit at the " +
			"tool's fixed credential paths and in the variables the profile removes; the test fails if the tool " +
			"prints a decoy or not the generated placeholder. Profiles without a test command or whose tool is not " +
			"installed are skipped. No real credential is read or sent anywhere.",
		RunE: func(cmd *cobra.Command, args []string) error {
			set, _, _, err := loadProfiles(cmd, e)
			if err != nil {
				return err
			}
			names := args
			if len(names) == 0 {
				names = set.Names()
			}
			w := cmd.OutOrStdout()
			var failed []string
			for _, n := range names {
				p, ok := set.Get(n)
				if !ok {
					return fmt.Errorf("tool profile %q is not defined", n)
				}
				if p.Test == nil {
					_, _ = fmt.Fprintf(w, "skip  %-10s no test command\n", n)
					continue
				}
				res, err := profiles.Check(cmd.Context(), p, envValue(e.Environ, "PATH"))
				switch {
				case errors.Is(err, profiles.ErrToolMissing):
					_, _ = fmt.Fprintf(w, "skip  %-10s %s\n", n, res.Skipped)
				case err != nil:
					failed = append(failed, n)
					_, _ = fmt.Fprintf(w, "FAIL  %-10s %v\n", n, err)
					for _, line := range strings.Split(strings.TrimSpace(res.Output), "\n") {
						_, _ = fmt.Fprintf(w, "      | %s\n", line)
					}
				default:
					_, _ = fmt.Fprintf(w, "ok    %-10s %s\n", n, strings.Join(res.Command, " "))
				}
			}
			if len(failed) > 0 {
				return fmt.Errorf("tool profiles failed: %s", strings.Join(failed, ", "))
			}
			return nil
		},
	}
	return cmd
}

func envValue(environ []string, name string) string {
	for _, kv := range environ {
		if k, v, ok := strings.Cut(kv, "="); ok && k == name {
			return v
		}
	}
	return ""
}
