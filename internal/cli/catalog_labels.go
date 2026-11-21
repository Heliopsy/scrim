// SPDX-License-Identifier: AGPL-3.0-only

package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"slices"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/heliopsy/scrim/internal/catalog"
	"github.com/heliopsy/scrim/internal/stores"
)

func catalogLabels(e *Env) *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "labels <name|reference>",
		Short: "List every label a secret has, as policy rules see it in secret.labels",
		Long: "Reads the secret's metadata from its store (never its value) and prints the labels rules see as " +
			"secret.labels: the store's native labels (<kind>.*), user metadata (<kind>.meta.*), scrim.* keys, the " +
			"generic store.* labels and the labels the store's `labels` option derives. A secret the store does not " +
			"hold yet shows the labels a new item there would get. Paste any line into `scrim policy eval --label`.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := e.Config()
			if err != nil {
				return err
			}
			ref, err := stores.ParseRef(args[0])
			if err != nil {
				cat, cerr := catalog.Load(cmd.Context(), cfg, lister(cmd, e), catalog.SelectionFrom(cfg))
				if cerr != nil {
					return cerr
				}
				b, nerr := cat.Name(args[0])
				if nerr != nil {
					return fmt.Errorf("%s is neither a reference nor a catalog name: %w", args[0], nerr)
				}
				ref = b.Ref
			}
			l, err := secretLabels(cmd.Context(), e, ref)
			if err != nil {
				return err
			}
			if asJSON {
				return writeJSON(e.Stdout, map[string]any{"ref": ref.String(), "exists": l.exists, "labels": l.labels})
			}
			return l.write(e.Stdout, ref)
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "print JSON")
	return cmd
}

// labelSet is a secret's labels and where each came from.
type labelSet struct {
	labels map[string]string
	native map[string]string
	exists bool
}

// secretLabels reads ref's metadata from its store (a listing, else a read
// whose values are wiped at once) and composes the labels policy sees.
func secretLabels(ctx context.Context, e *Env, ref stores.Ref) (labelSet, error) {
	a, err := e.App(ctx)
	if err != nil {
		return labelSet{}, err
	}
	ad, err := a.Stores.Lookup(ref)
	if err != nil {
		return labelSet{}, err
	}
	var out labelSet
	if ad.Capabilities().Has(stores.CapList) {
		if metas, err := a.Stores.List(ctx, ref.Secret()); err == nil {
			for _, m := range metas {
				if m.Ref.Path == ref.Path {
					out.native, out.exists = m.Labels, true
					break
				}
			}
		}
	}
	if !out.exists && ad.Capabilities().Has(stores.CapRead) {
		s, err := a.Stores.Read(ctx, ref.Secret())
		switch {
		case err == nil:
			s.Wipe()
			out.native, out.exists = s.Meta.Labels, true
		case !errors.Is(err, stores.ErrNotFound):
			return labelSet{}, err
		}
	}
	if out.exists {
		out.labels = a.Stores.Labels(ref, out.native)
	} else {
		out.labels = a.Stores.WriteLabels(ref)
		if wl, ok := ad.(stores.WriteLabeler); ok {
			out.native = wl.WriteLabels(ref)
		}
	}
	return out, nil
}

// origin says where label k came from.
func (l labelSet) origin(k string) string {
	switch {
	case strings.HasPrefix(k, stores.StoreLabelPrefix):
		return "store"
	case strings.HasPrefix(k, stores.ScrimLabelPrefix):
		return "scrim"
	}
	if _, ok := l.native[k]; !ok {
		return "derived"
	}
	if _, rest, ok := strings.Cut(k, "."); ok && strings.HasPrefix(rest, "meta.") {
		return "user"
	}
	return "native"
}

func (l labelSet) write(w io.Writer, ref stores.Ref) error {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintf(tw, "ref: %s\n", ref)
	if !l.exists {
		_, _ = fmt.Fprintln(tw, "(not in the store: the labels a new item there would get)")
	}
	_, _ = fmt.Fprintln(tw, "LABEL\tVALUE\tFROM")
	for _, k := range slices.Sorted(maps.Keys(l.labels)) {
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\n", k, l.labels[k], l.origin(k))
	}
	return tw.Flush()
}

// showEntry prints one catalog entry with its secret's labels.
func showEntry(cmd *cobra.Command, e *Env, cat *catalog.Catalog, name string, asJSON bool) error {
	var res *catalog.Resolved
	for _, r := range cat.Entries() {
		if r.Entry.Name == name {
			res = &r
			break
		}
	}
	if res == nil {
		return fmt.Errorf("catalog: %q: %w", name, catalog.ErrUnknown)
	}
	var l labelSet
	if res.OK && !res.Binding.Ref.IsZero() {
		var err error
		if l, err = secretLabels(cmd.Context(), e, res.Binding.Ref); err != nil {
			return err
		}
	}
	if asJSON {
		x := catalogRow{Name: name, Resolved: res.OK, Source: res.Entry.Source.String(), Variants: variants(res.Entry),
			Prefix: res.Entry.Prefix, Template: res.Entry.Template}
		if res.OK {
			b := res.Binding
			x.Binding = &b
		}
		return writeJSON(e.Stdout, struct {
			catalogRow
			Labels map[string]string `json:"labels,omitempty"`
		}{x, l.labels})
	}
	w := e.Stdout
	_, _ = fmt.Fprintf(w, "name: %s\nsource: %s\n", name, res.Entry.Source)
	if !res.OK {
		_, err := fmt.Fprintf(w, "reference: none for selection %s\n", cat.Selection())
		return err
	}
	b := res.Binding
	_, _ = fmt.Fprintf(w, "reference: %s (%s)\nclass: %s\n", b.Ref, b.Selected, b.Class)
	if b.Placeholder != "" {
		_, _ = fmt.Fprintf(w, "placeholder: %s\n", b.Placeholder)
	}
	if len(b.Hosts) > 0 {
		_, _ = fmt.Fprintf(w, "hosts: %s\n", strings.Join(b.Hosts, ","))
	}
	if l.labels == nil {
		return nil
	}
	_, _ = fmt.Fprintln(w)
	return l.write(w, b.Ref)
}
