// SPDX-License-Identifier: AGPL-3.0-only

package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/heliopsy/scrim/internal/catalog"
	"github.com/heliopsy/scrim/internal/stores"
)

// Catalog shows and suggests secret catalog entries.
func (Commands) Catalog(e *Env) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "catalog",
		Short: "Show and suggest secret catalog entries",
		Long: "The secret catalog maps logical names and declared placeholders to store references and the " +
			"hosts they may be injected toward. It never holds values.",
	}
	cmd.AddCommand(catalogShow(e), catalogSuggest(e))
	return cmd
}

// lister returns the configured stores, or nil when none is configured or
// the composition root cannot be built (the catalog then loads without
// store listings and says so in its warnings).
func lister(cmd *cobra.Command, e *Env) catalog.Lister {
	a, err := e.App(cmd.Context())
	if err != nil || len(a.Stores.Adapters()) == 0 {
		return nil
	}
	return a.Stores
}

func catalogShow(e *Env) *cobra.Command {
	var (
		asJSON          bool
		agent, ns, prof string
	)
	cmd := &cobra.Command{
		Use:   "show",
		Short: "Show the effective catalog and which reference each entry selects",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := e.Config()
			if err != nil {
				return err
			}
			sel := catalog.SelectionFrom(cfg)
			if prof != "" {
				sel.Profile = prof
			}
			sel.Agent, sel.Namespace = agent, ns
			cat, err := catalog.Load(cmd.Context(), cfg, lister(cmd, e), sel)
			if err != nil {
				return err
			}
			if asJSON {
				return writeCatalogJSON(e.Stdout, cat)
			}
			return writeCatalogTable(e.Stdout, cat)
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "print JSON")
	cmd.Flags().StringVar(&prof, "for-profile", "", "show the selection for this catalog profile instead of catalog.profile")
	cmd.Flags().StringVar(&agent, "agent", "", "show the selection for this agent")
	cmd.Flags().StringVar(&ns, "namespace", "", "show the selection for this namespace")
	return cmd
}

type catalogRow struct {
	Name     string            `json:"name"`
	Resolved bool              `json:"resolved"`
	Binding  *catalog.Binding  `json:"binding,omitempty"`
	Source   string            `json:"source"`
	Variants map[string]string `json:"variants,omitempty"`
	Prefix   string            `json:"prefix,omitempty"`
	Template string            `json:"template,omitempty"`
	Overrode []string          `json:"overrides,omitempty"`
}

func writeCatalogJSON(w io.Writer, cat *catalog.Catalog) error {
	out := struct {
		Selection string       `json:"selection"`
		Entries   []catalogRow `json:"entries"`
		Warnings  []string     `json:"warnings,omitempty"`
	}{Selection: cat.Selection().String(), Warnings: cat.Warnings(), Entries: []catalogRow{}}
	for _, r := range cat.Entries() {
		x := catalogRow{Name: r.Entry.Name, Resolved: r.OK, Source: r.Entry.Source.String(), Variants: variants(r.Entry),
			Prefix: r.Entry.Prefix, Template: r.Entry.Template}
		if r.OK {
			b := r.Binding
			x.Binding = &b
		}
		for _, s := range r.Overridden {
			x.Overrode = append(x.Overrode, s.String())
		}
		out.Entries = append(out.Entries, x)
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

func variants(e catalog.Entry) map[string]string {
	m := map[string]string{}
	if e.Ref != "" {
		m["default"] = e.Ref
	}
	for p, r := range e.Profiles {
		m["profile="+p] = r
	}
	for _, v := range e.Variants {
		var parts []string
		for _, k := range []string{catalog.KeyAgent, catalog.KeyNamespace, catalog.KeyProfile, catalog.KeyEnvironment} {
			if val, ok := v.When[k]; ok {
				parts = append(parts, k+"="+val)
			}
		}
		m[strings.Join(parts, ",")] = v.Ref
	}
	if len(m) == 0 {
		return nil
	}
	return m
}

func writeCatalogTable(w io.Writer, cat *catalog.Catalog) error {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintf(tw, "selection: %s\n", cat.Selection())
	_, _ = fmt.Fprintln(tw, "NAME\tPLACEHOLDER\tREFERENCE\tSELECTED\tHOSTS\tCLASS\tSOURCE")
	for _, r := range cat.Entries() {
		ref, selected, hosts := "-", "none", "-"
		if r.OK {
			ref, selected = r.Binding.Ref.String(), r.Binding.Selected
			if len(r.Binding.Hosts) > 0 {
				hosts = strings.Join(r.Binding.Hosts, ",")
			}
		}
		ph := r.Entry.Placeholder
		if r.Entry.Prefix != "" {
			ref, ph = r.Entry.Prefix, r.Entry.Template
		}
		if ph == "" {
			ph = "-"
		}
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", r.Entry.Name, ph, ref, selected, hosts, r.Entry.Class, r.Entry.Source)
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	if cat.Len() == 0 {
		if _, err := fmt.Fprintln(w, "(no entries: store references and {{scrim:<ref>}} placeholders still work without a catalog)"); err != nil {
			return err
		}
	}
	for _, warn := range cat.Warnings() {
		if _, err := fmt.Fprintf(w, "warning: %s\n", warn); err != nil {
			return err
		}
	}
	return nil
}

func catalogSuggest(e *Env) *cobra.Command {
	var (
		dir, store string
		prefixes   []string
	)
	cmd := &cobra.Command{
		Use:   "suggest",
		Short: "Print draft catalog entries from the project, tool profiles and store contents; nothing is applied",
		Long: "Scans the project's .env files, configured tool profiles and the names of secrets under the given " +
			"store prefixes (and catalog.metadata-from), and prints draft catalog entries for whatever the catalog " +
			"does not map yet. Values are never printed or read from stores, and nothing is written: review the " +
			"draft and save it yourself.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := e.Config()
			if err != nil {
				return err
			}
			o := catalog.SuggestOptions{Dir: dir, Store: store}
			for _, p := range append(prefixes, catalog.MetadataFrom.Get(cfg)...) {
				r, err := stores.ParseRef(p)
				if err != nil {
					return fmt.Errorf("--prefix: %w", err)
				}
				o.Prefixes = append(o.Prefixes, r)
			}
			if len(o.Prefixes) > 0 {
				o.Lister = lister(cmd, e)
			}
			cat, err := catalog.Load(cmd.Context(), cfg, o.Lister, catalog.SelectionFrom(cfg))
			if err != nil {
				return fmt.Errorf("the current catalog is invalid; fix it before asking for suggestions: %w", err)
			}
			o.Catalog = cat
			sugg, warnings, err := catalog.Suggest(cmd.Context(), o)
			if err != nil {
				return err
			}
			return catalog.WriteSuggestions(e.Stdout, sugg, warnings)
		},
	}
	cmd.Flags().StringVar(&dir, "dir", ".", "project directory to scan")
	cmd.Flags().StringVar(&store, "store", "", "base reference for candidate references (default bao://kv/agents)")
	cmd.Flags().StringSliceVar(&prefixes, "prefix", nil, "store prefix to list secret names from (repeatable)")
	return cmd
}
