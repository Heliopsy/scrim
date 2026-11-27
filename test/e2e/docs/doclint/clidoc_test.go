// SPDX-License-Identifier: AGPL-3.0-only

package doclint

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// cliDocDir holds the generated CLI reference.
const cliDocDir = "docs/reference/cli"

const cliDocNote = "<!-- Generated from the command tree by `just cli-docs`. Do not edit. -->"

// documented reports whether a command gets a section: visible, and not
// cobra's own help and completion commands.
func documented(c *cobra.Command) bool {
	return c.IsAvailableCommand() && c.Name() != "help" && c.Name() != "completion"
}

func anchor(c *cobra.Command) string { return slug(c.CommandPath()) }

// cliReference renders the command tree as Markdown: README.md with the
// root command, the global flags and an index, and one page per top-level
// command holding it and every subcommand below it. Global flags (the
// settings flags and --config) are listed once, in README.md.
func cliReference(root *cobra.Command) map[string][]byte {
	out := map[string][]byte{}
	global := root.PersistentFlags()

	var idx bytes.Buffer
	fmt.Fprintf(&idx, "# scrim command line\n\n%s\n\n", cliDocNote)
	wrap(&idx, root.Short+".")
	idx.WriteString("\nThe settings reference is [configuration.md](../../configuration.md); every setting declared\n" +
		"with a flag is a global flag below.\n\n## Usage\n\n```text\n")
	idx.WriteString(root.UseLine() + " [command]\n```\n\n## Commands\n\n")
	idx.WriteString("| Command | Description |\n| --- | --- |\n")
	for _, top := range root.Commands() {
		if !documented(top) {
			continue
		}
		var page bytes.Buffer
		fmt.Fprintf(&page, "# %s\n\n%s\n\n", top.CommandPath(), cliDocNote)
		page.WriteString("Global flags are listed in [the CLI reference](README.md#global-flags).\n")
		walk(top, func(c *cobra.Command) {
			fmt.Fprintf(&idx, "| [`%s`](%s.md#%s) | %s |\n", c.CommandPath(), top.Name(), anchor(c),
				strings.ReplaceAll(c.Short, "|", "\\|"))
			section(&page, c, global)
		})
		out[top.Name()+".md"] = page.Bytes()
	}
	idx.WriteString("\n## Global flags\n\nEvery command accepts these.\n\n```text\n")
	idx.WriteString(flagUsages(global))
	idx.WriteString("```\n")
	out["README.md"] = idx.Bytes()
	return out
}

func walk(c *cobra.Command, fn func(*cobra.Command)) {
	if !documented(c) {
		return
	}
	fn(c)
	for _, s := range c.Commands() {
		walk(s, fn)
	}
}

func section(w *bytes.Buffer, c *cobra.Command, global *pflag.FlagSet) {
	fmt.Fprintf(w, "\n## %s\n\n", c.CommandPath())
	if c.Short != "" {
		wrap(w, c.Short+".")
		w.WriteString("\n")
	}
	w.WriteString("```text\n")
	if c.Runnable() {
		w.WriteString(c.UseLine() + "\n")
	}
	if c.HasAvailableSubCommands() {
		w.WriteString(c.CommandPath() + " [command]\n")
	}
	if len(c.Aliases) > 0 {
		w.WriteString("\nAliases: " + strings.Join(c.Aliases, ", ") + "\n")
	}
	if long := strings.TrimSpace(c.Long); long != "" {
		w.WriteString("\n" + wrapLines(long) + "\n")
	}
	if ex := strings.TrimRight(c.Example, " \n"); ex != "" {
		w.WriteString("\nExamples:\n" + ex + "\n")
	}
	w.WriteString("```\n")
	if subs := visibleSubs(c); len(subs) > 0 {
		w.WriteString("\n| Subcommand | Description |\n| --- | --- |\n")
		for _, s := range subs {
			fmt.Fprintf(w, "| [`%s`](#%s) | %s |\n", s.CommandPath(), anchor(s), strings.ReplaceAll(s.Short, "|", "\\|"))
		}
	}
	if own := flagUsages(c.NonInheritedFlags()); own != "" {
		w.WriteString("\nFlags:\n\n```text\n" + own + "```\n")
	}
	inherited := pflag.NewFlagSet("inherited", pflag.ContinueOnError)
	c.InheritedFlags().VisitAll(func(f *pflag.Flag) {
		if global.Lookup(f.Name) == nil {
			inherited.AddFlag(f)
		}
	})
	if s := flagUsages(inherited); s != "" {
		w.WriteString("\nFlags inherited from parent commands:\n\n```text\n" + s + "```\n")
	}
}

func visibleSubs(c *cobra.Command) []*cobra.Command {
	var out []*cobra.Command
	for _, s := range c.Commands() {
		if documented(s) {
			out = append(out, s)
		}
	}
	return out
}

// flagUsages is pflag's help text for the flags, without the help flag
// cobra adds to every command.
func flagUsages(fs *pflag.FlagSet) string {
	clean := pflag.NewFlagSet("doc", pflag.ContinueOnError)
	clean.SortFlags = true
	fs.VisitAll(func(f *pflag.Flag) {
		if f.Name != "help" && !f.Hidden {
			clean.AddFlag(f)
		}
	})
	// A NUL in a NoOptDefVal would make git treat the page as binary.
	return strings.ReplaceAll(clean.FlagUsagesWrapped(120), "\x00", `\x00`)
}

// wrapLines wraps every line of preformatted text longer than 120
// characters at spaces.
func wrapLines(text string) string {
	var out []string
	for line := range strings.SplitSeq(text, "\n") {
		for len(line) > 120 {
			cut := strings.LastIndexByte(line[:121], ' ')
			if cut <= 0 {
				break
			}
			out = append(out, line[:cut])
			line = line[cut+1:]
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n")
}

// wrap writes text as a paragraph of lines of at most 120 characters.
func wrap(w *bytes.Buffer, text string) {
	line := 0
	for i, word := range strings.Fields(text) {
		if i > 0 && line+1+len(word) > 120 {
			w.WriteString("\n")
			line = 0
		} else if i > 0 {
			w.WriteString(" ")
			line++
		}
		w.WriteString(word)
		line += len(word)
	}
	w.WriteString("\n")
}

// TestCLIReference fails when docs/reference/cli is not what the command
// tree generates. `just cli-docs` (SCRIM_CLI_DOCS=update) rewrites it.
func TestCLIReference(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the reference is generated on Linux; some commands and flags are per platform")
	}
	root := repoRoot(t)
	dir := filepath.Join(root, filepath.FromSlash(cliDocDir))
	want := cliReference(cliRoot())
	if os.Getenv("SCRIM_CLI_DOCS") == "update" {
		if err := os.RemoveAll(dir); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(dir, 0o755); err != nil { // #nosec G301 -- documentation directory
			t.Fatal(err)
		}
		for name, b := range want {
			if err := os.WriteFile(filepath.Join(dir, name), b, 0o644); err != nil { // #nosec G306 -- documentation, world-readable on purpose
				t.Fatal(err)
			}
		}
		return
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("%v: run `just cli-docs`", err)
	}
	var have []string
	for _, e := range entries {
		have = append(have, e.Name())
	}
	var names []string
	for name := range want {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		got, err := os.ReadFile(filepath.Join(dir, name)) // #nosec G304 -- fixed directory in the repository
		if err != nil || !bytes.Equal(got, want[name]) {
			t.Errorf("%s/%s is out of date: run `just cli-docs`", cliDocDir, name)
		}
	}
	for _, name := range have {
		if !slices.Contains(names, name) {
			t.Errorf("%s/%s is for a command that no longer exists: run `just cli-docs`", cliDocDir, name)
		}
	}
}
