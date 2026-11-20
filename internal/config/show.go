// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"slices"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/heliopsy/scrim/internal/secret"
)

// EffectiveEntry is one row of `scrim config show --effective`. A secret-ref
// setting shows its reference form and a masked value, never the value.
type EffectiveEntry struct {
	Key   string `json:"key"`
	Type  Kind   `json:"type"`
	Value any    `json:"value"`
	// Reference is the safe reference form of a set secret-ref setting.
	Reference string `json:"reference,omitempty"`
	Source    string `json:"source"`
	// Sources gives the source of each entry of a map setting.
	Sources map[string]string `json:"sources,omitempty"`
	Env     string            `json:"env"`
	// Collection names the collection a field belongs to.
	Collection      string `json:"collection,omitempty"`
	Flag            string `json:"flag,omitempty"`
	Weakening       bool   `json:"weakening,omitempty"`
	Weakened        bool   `json:"weakened,omitempty"`
	RestartRequired bool   `json:"restartRequired,omitempty"`
	PendingRestart  bool   `json:"pendingRestart,omitempty"`
}

// Effective returns every setting of c with its effective value and source,
// sorted by key, with secret-ref values masked.
func Effective(c *Config) []EffectiveEntry {
	weakened := map[string]bool{}
	for _, e := range c.Weakened() {
		weakened[e.Setting.Key] = true
	}
	out := make([]EffectiveEntry, 0, len(c.values))
	for _, e := range c.Entries() {
		s := e.Setting
		row := EffectiveEntry{
			Key: s.Key, Type: s.Kind, Value: displayValue(e.Value), Source: e.Source.String(),
			Env: s.EnvVar(), Weakening: s.Weakening, Weakened: weakened[s.Key],
			RestartRequired: s.RestartRequired, PendingRestart: slices.Contains(c.pending, s.Key),
		}
		if s.Flag {
			row.Flag = "--" + s.FlagName()
		}
		if s.Kind == KindSecretRef {
			row.Value = ""
			if ref := e.Value.(SecretRef); ref.Kind() != RefNone {
				row.Value = secret.Marker
				row.Reference = ref.Display()
			}
		}
		if len(e.Sources) > 0 {
			row.Sources = make(map[string]string, len(e.Sources))
			for k, src := range e.Sources {
				row.Sources[k] = src.String()
			}
		}
		out = append(out, row)
	}
	for _, col := range c.reg.Collections() {
		st := c.collections[col.Key]
		for _, name := range slices.Sorted(maps.Keys(st)) {
			inst := st[name]
			for _, leaf := range inst.leaves() {
				key := inst.Key(col.Key, leaf)
				v := lookupPath(inst.Fields, strings.Split(leaf, "."))
				row := EffectiveEntry{
					Key: key, Type: treeKind(v), Value: v, Source: inst.Sources[leaf].String(),
					Env: EnvVar(key), Collection: col.Key, RestartRequired: col.RestartRequired,
					PendingRestart: slices.Contains(c.pending, col.Key),
				}
				if isSecretField(col, leaf) {
					row.Type = KindSecretRef
					row.Value = ""
					if s, ok := v.(string); ok && s != "" {
						row.Value = secret.Marker
						row.Reference = SecretRef(s).Display()
					}
				}
				out = append(out, row)
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

// treeKind names the type of a collection field value.
func treeKind(v any) Kind {
	switch v.(type) {
	case bool:
		return KindBool
	case int:
		return KindInt
	case float64:
		return KindFloat
	case []any:
		return KindList
	case map[string]any:
		return KindMap
	}
	return KindString
}

func displayValue(v any) any {
	switch t := v.(type) {
	case time.Duration:
		return t.String()
	case []string:
		return slices.Clone(t)
	case map[string]string:
		return clone(t)
	}
	return v
}

// ShowOptions controls [WriteEffective].
type ShowOptions struct {
	// Format is "text" (a table, the default) or "json".
	Format string
	// OnlySet leaves out settings at their built-in default.
	OnlySet bool
}

// WriteEffective writes the effective configuration with the source of every
// value. Secret values are masked; only their reference form is shown.
func WriteEffective(w io.Writer, c *Config, opts ShowOptions) error {
	rows := Effective(c)
	if opts.OnlySet {
		rows = slices.DeleteFunc(rows, func(r EffectiveEntry) bool { return r.Source == string(SourceDefault) })
	}
	format := opts.Format
	switch format {
	case "json":
		doc := struct {
			APIVersion string           `json:"apiVersion"`
			Profile    string           `json:"profile"`
			Version    uint64           `json:"version"`
			Files      []string         `json:"files"`
			Settings   []EffectiveEntry `json:"settings"`
			Warnings   []Warning        `json:"warnings,omitempty"`
		}{APIVersion, c.profile, c.version, nonNil(c.files), rows, c.warnings}
		enc := json.NewEncoder(w)
		enc.SetEscapeHTML(false)
		enc.SetIndent("", "  ")
		return enc.Encode(doc)
	case "text", "":
	default:
		return fmt.Errorf("unknown output format %q (text, json)", format)
	}

	ew := &errWriter{w: w}
	// errWriter keeps the first write error, returned at the end.
	pf := func(w io.Writer, format string, args ...any) { _, _ = fmt.Fprintf(w, format, args...) }
	pf(ew, "# profile: %s\n", c.profile)
	if len(c.files) == 0 {
		pf(ew, "# files: none\n")
	}
	for _, f := range c.files {
		pf(ew, "# file: %s\n", f)
	}
	tw := tabwriter.NewWriter(ew, 0, 0, 2, ' ', 0)
	pf(tw, "KEY\tVALUE\tSOURCE\tNOTES\n")
	for _, r := range rows {
		notes := rowNotes(r)
		if r.Type == KindMap && len(r.Sources) > 0 {
			m := r.Value.(map[string]string)
			for _, k := range slices.Sorted(maps.Keys(m)) {
				pf(tw, "%s.%s\t%s\t%s\t%s\n", r.Key, k, textValue(m[k]), r.Sources[k], notes)
			}
			continue
		}
		val := textValue(r.Value)
		if r.Reference != "" {
			val = fmt.Sprintf("%s (%s)", secret.Marker, r.Reference)
		}
		pf(tw, "%s\t%s\t%s\t%s\n", r.Key, val, r.Source, notes)
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	for _, warn := range c.warnings {
		pf(ew, "warning: %s\n", warn)
	}
	return ew.err
}

func rowNotes(r EffectiveEntry) string {
	var n []string
	if r.Weakened {
		n = append(n, "WEAKENED")
	} else if r.Weakening {
		n = append(n, "weakening")
	}
	if r.PendingRestart {
		n = append(n, "pending-restart")
	} else if r.RestartRequired {
		n = append(n, "restart")
	}
	if len(n) == 0 {
		return "-"
	}
	return strings.Join(n, ",")
}

func textValue(v any) string {
	switch t := v.(type) {
	case string:
		if t == "" || strings.ContainsAny(t, " \t\n\"") {
			b, _ := json.Marshal(t)
			return string(b)
		}
		return t
	case []string, map[string]string, []any, map[string]any:
		b, _ := json.Marshal(t)
		return string(b)
	}
	return fmt.Sprint(v)
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// errWriter remembers the first write error so formatting code can ignore
// errors until the end.
type errWriter struct {
	w   io.Writer
	err error
}

func (e *errWriter) Write(p []byte) (int, error) {
	if e.err != nil {
		return len(p), nil //nolint:nilerr // the first error is kept in e.err and reported by the caller
	}
	n, err := e.w.Write(p)
	if err != nil {
		e.err = err
	}
	return n, nil
}
