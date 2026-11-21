// SPDX-License-Identifier: AGPL-3.0-only

package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/spf13/cobra"

	"github.com/heliopsy/scrim/internal/agenttools"
	"github.com/heliopsy/scrim/internal/catalog"
	"github.com/heliopsy/scrim/internal/projectscan"
	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/status"
	"github.com/heliopsy/scrim/internal/stores"
)

// defaultMoveStore is the base reference values are moved under when
// --store is not given.
const defaultMoveStore = "bao://kv/agents"

// Project finds secret values in project files and moves them into a store
// (specs/credential-injection "Secrets in project files").
func (Commands) Project(e *Env) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "project",
		Short: "Find secret values in project files and move them into a store",
		Long: "scrim run scans the agent's working directory for secret values in project files (.env*, *.tfvars, " +
			"application config, compose files, .npmrc) and redacts them from the first request. These commands show " +
			"what it finds and move values into a store, replacing each in its file with a {{scrim:<ref>}} reference. " +
			"Values are never printed.",
	}
	cmd.AddCommand(projectScan(e), projectMove(e))
	return cmd
}

func projectScan(e *Env) *cobra.Command {
	var (
		dir string
		out outputFlags
	)
	cmd := &cobra.Command{
		Use:   "scan",
		Short: "List the secret values in project files, by file, line and key; values are never printed",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			format, err := out.format()
			if err != nil {
				return err
			}
			r, err := projectscan.Scan(dir, projectscan.Options{})
			if err != nil {
				return err
			}
			defer r.Wipe()
			m := r.Movable()
			w := cmd.OutOrStdout()
			if format == "json" {
				enc := json.NewEncoder(w)
				enc.SetIndent("", "  ")
				return enc.Encode(struct {
					Dir      string                `json:"dir"`
					Findings []projectscan.Finding `json:"findings"`
					Skipped  []string              `json:"skipped,omitempty"`
				}{r.Dir, m, r.Skipped})
			}
			if len(m) == 0 {
				_, _ = fmt.Fprintf(w, "no secret values in the project files of %s (%d files scanned)\n", r.Dir, len(r.Files))
				return nil
			}
			for _, f := range m {
				_, _ = fmt.Fprintf(w, "%s\n", f)
			}
			_, _ = fmt.Fprintf(w, "\n%d secret values in %d files; scrim run redacts them, `scrim project move` moves them into a store\n",
				len(m), len(r.Files))
			for _, s := range r.Skipped {
				_, _ = fmt.Fprintf(w, "not scanned: %s\n", s)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&dir, "dir", ".", "project directory to scan")
	out.bind(cmd)
	return cmd
}

func projectMove(e *Env) *cobra.Command {
	var (
		dir, store string
		yes        bool
		keys       []string
	)
	cmd := &cobra.Command{
		Use:   "move",
		Short: "Move secret values from project files into a store, asking before each one",
		Long: "For each secret value in the project files, asks whether to write it into the store under " +
			"<store>/<name>#value (through the agent API, so policy and audit apply) and replace it in the file with " +
			"{{scrim:<ref>}}. Nothing is written or rewritten without a yes; --yes answers yes to every value. " +
			"Add a catalog entry for the reference so scrim injects it where the file's value was sent.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := agentClient(e)
			if err != nil {
				return err
			}
			defer c.Close()
			return moveProject(cmd.Context(), cmd.OutOrStdout(), e.Stdin, c, moveOptions{dir: dir, store: store, yes: yes, keys: keys})
		},
	}
	cmd.Flags().StringVar(&dir, "dir", ".", "project directory to scan")
	cmd.Flags().StringVar(&store, "store", defaultMoveStore, "base reference the values are written under")
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "move every value without asking")
	cmd.Flags().StringSliceVar(&keys, "key", nil, "only move values of these keys (repeatable)")
	return cmd
}

type moveOptions struct {
	dir, store string
	yes        bool
	keys       []string
}

// putter writes a value into a store; *localapi.Client implements it.
type putter interface {
	Put(ctx context.Context, in agenttools.PutInput, v secret.Value) (agenttools.WriteOutput, error)
}

// copyValue returns a copy for Put, which wipes what it sends.
func copyValue(v secret.Value) secret.Value {
	var out secret.Value
	_ = v.Expose(func(b []byte) error { out = secret.New(b); return nil })
	return out
}

func moveProject(ctx context.Context, w io.Writer, in io.Reader, c putter, o moveOptions) error {
	base, err := stores.ParseRef(strings.TrimSuffix(o.store, "/") + "/x")
	if err != nil {
		return fmt.Errorf("--store: %w", err)
	}
	base.Path = strings.TrimSuffix(base.Path, "/x")
	r, err := projectscan.Scan(o.dir, projectscan.Options{})
	if err != nil {
		return err
	}
	defer r.Wipe()
	answers := bufio.NewReader(in)
	moved, skipped := 0, 0
	for _, f := range r.Movable() {
		if len(o.keys) > 0 && !containsFold(o.keys, f.Key) {
			continue
		}
		ref := stores.Ref{Scheme: base.Scheme, Path: base.Path + "/" + moveName(f.Key), Field: "value"}
		repl := catalog.ReferencePlaceholder(ref)
		if !o.yes {
			_, _ = fmt.Fprintf(w, "move %s into %s and replace it with %s? [y/N] ", f, ref, repl)
			line, _ := answers.ReadString('\n')
			if a := strings.ToLower(strings.TrimSpace(line)); a != "y" && a != "yes" {
				_, _ = fmt.Fprintln(w, "  left in place")
				skipped++
				continue
			}
		}
		// The application reads the decoded form of a quoted value.
		v := f.Value
		for _, d := range r.Findings {
			if d.Decoded() && d.File == f.File && d.Line == f.Line && d.Key == f.Key {
				v = d.Value
			}
		}
		if _, err := c.Put(ctx, agenttools.PutInput{Ref: ref.String()}, copyValue(v)); err != nil {
			return fmt.Errorf("writing %s into %s: %w; the file is unchanged", f, ref, err)
		}
		if err := projectscan.Replace(r.Dir, f, repl); err != nil {
			return fmt.Errorf("%s was written into %s, but replacing it in the file failed: %w", f, ref, err)
		}
		_, _ = fmt.Fprintf(w, "  moved into %s\n", ref)
		moved++
	}
	_, _ = fmt.Fprintf(w, "%d moved, %d left in place\n", moved, skipped)
	if moved > 0 {
		_, _ = fmt.Fprintf(w, "add catalog entries for the moved references (scrim catalog suggest --dir %s) so their placeholders are injected\n", o.dir)
	}
	return nil
}

var nonName = regexp.MustCompile(`[^a-z0-9]+`)

// moveName is the store name for a key: OPENAI_API_KEY is openai-api-key.
func moveName(key string) string {
	n := strings.Trim(nonName.ReplaceAllString(strings.ToLower(key), "-"), "-")
	if n == "" {
		return "secret"
	}
	return n
}

func containsFold(list []string, s string) bool {
	for _, x := range list {
		if strings.EqualFold(x, s) {
			return true
		}
	}
	return false
}

// projectChecks is the doctor check listing secret values in the current
// directory's project files with the offer to move them.
func projectChecks(dir string) []status.Check {
	const name = "project: secret values in files"
	return []status.Check{{Name: name, Run: func(context.Context) []status.Finding {
		r, err := projectscan.Scan(dir, projectscan.Options{})
		if err != nil {
			return []status.Finding{{Check: name, Outcome: status.Skip, Message: "the working directory could not be scanned: " + err.Error()}}
		}
		defer r.Wipe()
		m := r.Movable()
		if len(m) == 0 {
			return []status.Finding{{Check: name, Outcome: status.Pass, Message: fmt.Sprintf("none in %d project files", len(r.Files))}}
		}
		out := make([]status.Finding, 0, len(m))
		for _, f := range m {
			out = append(out, status.Finding{Check: name, Outcome: status.Warn,
				Message: f.String() + " holds a secret value in plain text; scrim run redacts it from LLM traffic",
				Fix:     "scrim project move --key " + f.Key + " writes it into a store and replaces it with a reference"})
		}
		return out
	}}}
}
