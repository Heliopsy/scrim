// SPDX-License-Identifier: AGPL-3.0-only

package doclint

import (
	"io"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/heliopsy/scrim/internal/cli"
	"github.com/heliopsy/scrim/internal/config"
)

// cliRoot is the command tree of the scrim binary, with the settings flags of
// every package it links in.
func cliRoot() *cobra.Command {
	e := &cli.Env{Stdin: strings.NewReader(""), Stdout: io.Discard, Stderr: io.Discard, Environ: []string{}, Registry: config.Default}
	root := cli.NewRoot(e)
	root.InitDefaultHelpCmd()
	root.InitDefaultHelpFlag()
	return root
}

// referenceDocs are the hand-written docs the reference lint reads. The
// generated references (settings, Helm values, CLI) come from the code they
// would be checked against; the changelog and the OpenSpec changes describe
// other versions of scrim.
func referenceDocs(t *testing.T, root string) []string {
	var out []string
	for _, f := range markdownFiles(t, root) {
		switch {
		case f == "CHANGELOG.md", f == "docs/helm-values.md",
			strings.HasPrefix(f, "openspec/"), strings.HasPrefix(f, "docs/reference/cli/"):
			continue
		}
		out = append(out, f)
	}
	return out
}

// segments returns the parts of a line that may hold a command or key: the
// inline code spans of prose, the whole line in a code block.
func segments(l Line) []string {
	if l.Fence {
		return []string{l.Text}
	}
	return codeSpans(l.Text)
}

// shellLang reports whether a code block holds commands.
func shellLang(lang string) bool {
	switch lang {
	case "", "sh", "bash", "shell", "console", "zsh", "text", "powershell", "pwsh":
		return true
	}
	return false
}

var (
	cmdSep     = regexp.MustCompile(`\|\||&&|[|;&()]|\$\(`)
	assignment = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=`)
)

// invocations returns the arguments of every command in seg whose program
// is scrim: the first word of a command, after a prompt, sudo, env, exec or
// variable assignments.
func invocations(seg string) [][]string {
	var out [][]string
	for _, part := range cmdSep.Split(seg, -1) {
		toks := strings.Fields(part)
		for len(toks) > 0 && (toks[0] == "$" || toks[0] == ">" || toks[0] == "sudo" || toks[0] == "exec" ||
			toks[0] == "env" || toks[0] == "time" || toks[0] == "-E" || assignment.MatchString(toks[0])) {
			toks = toks[1:]
		}
		if len(toks) == 0 {
			continue
		}
		if prog := toks[0]; prog == "scrim" || prog == "./scrim" || strings.HasSuffix(prog, "/bin/scrim") || prog == "scrim.exe" {
			args := toks[1:]
			for i, a := range args {
				if strings.HasPrefix(a, "#") || a == ">" || a == "2>" || strings.HasPrefix(a, ">") || strings.HasPrefix(a, "2>") || a == "<" {
					args = args[:i]
					break
				}
			}
			out = append(out, args)
		}
	}
	return out
}

// generatedRange returns the lines of docs/configuration.md that
// `just config-docs` writes (they come from the registry), as [from, to).
func generatedRange(f string, ls []Line) (int, int) {
	if f != "docs/configuration.md" {
		return 0, 0
	}
	from, to := 0, 0
	for _, l := range ls {
		switch {
		case strings.Contains(l.Text, "<!-- BEGIN GENERATED"):
			from = l.N
		case strings.Contains(l.Text, "<!-- END GENERATED"):
			to = l.N
		}
	}
	return from, to
}

var (
	wordArg  = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)
	longFlag = regexp.MustCompile(`^--([a-z0-9][a-z0-9-]*)`)
	// "with --system: ..." or "with --transparent, --ebpf or --dns: ..."
	needsFlags = regexp.MustCompile(`^with ((?:--[a-z0-9-]+(?:, | or )?)+):`)
	flagName   = regexp.MustCompile(`--([a-z0-9-]+)`)
)

func subcommand(c *cobra.Command, name string) *cobra.Command {
	for _, s := range c.Commands() {
		if s.Name() == name || slices.Contains(s.Aliases, name) {
			return s
		}
	}
	return nil
}

func lookupFlag(c *cobra.Command, name string) *pflag.Flag {
	if f := c.Flags().Lookup(name); f != nil {
		return f
	}
	return c.InheritedFlags().Lookup(name)
}

// TestCommandReferences checks every `scrim ...` invocation in the docs, in
// code spans and code blocks, against the cobra tree: the command path
// exists, every long flag exists on that command, and a flag documented as
// "with --x: ..." comes with one of the flags it names.
func TestCommandReferences(t *testing.T) {
	root := repoRoot(t)
	tree := cliRoot()
	var found []Violation
	seen := 0
	for _, f := range referenceDocs(t, root) {
		ls := lines(readFile(t, root, f))
		genFrom, genTo := generatedRange(f, ls)
		for _, l := range ls {
			if l.N > genFrom && l.N < genTo {
				continue
			}
			segs := segments(l)
			if l.Fence && !shellLang(l.Lang) {
				segs = codeSpans(l.Text) // `scrim ...` in a comment of other code
			}
			for _, seg := range segs {
				for _, args := range invocations(seg) {
					seen++
					found = append(found, checkInvocation(tree, f, l.N, args)...)
				}
			}
		}
	}
	t.Logf("%d scrim invocations checked", seen)
	report(t, root, "command", found)
}

func checkInvocation(tree *cobra.Command, f string, line int, toks []string) []Violation {
	c, j := tree, 0
	for j < len(toks) {
		s := subcommand(c, toks[j])
		if s == nil {
			break
		}
		c, j = s, j+1
	}
	path := c.CommandPath()
	rest := toks[j:]
	var out []Violation
	if len(rest) > 0 && wordArg.MatchString(rest[0]) && c.HasAvailableSubCommands() && !c.Runnable() {
		subj := path + " " + rest[0]
		return append(out, violation("command", f, line, subj, "unknown command %q", subj))
	}
	if len(rest) > 0 && wordArg.MatchString(rest[0]) && c == tree {
		subj := "scrim " + rest[0]
		return append(out, violation("command", f, line, subj, "unknown command %q", subj))
	}
	if c.DisableFlagParsing {
		return out // the command parses its own arguments
	}
	given := map[string]bool{}
	var flags []string
	for _, tok := range rest {
		if tok == "--" {
			break
		}
		m := longFlag.FindStringSubmatch(tok)
		if m == nil {
			continue
		}
		given[m[1]] = true
		flags = append(flags, m[1])
	}
	for _, name := range flags {
		fl := lookupFlag(c, name)
		if fl == nil {
			subj := path + " --" + name
			out = append(out, violation("command", f, line, subj, "%q has no flag --%s", path, name))
			continue
		}
		m := needsFlags.FindStringSubmatch(fl.Usage)
		if m == nil {
			continue
		}
		var need []string
		ok := false
		for _, n := range flagName.FindAllStringSubmatch(m[1], -1) {
			need = append(need, "--"+n[1])
			ok = ok || given[n[1]]
		}
		if !ok {
			subj := path + " --" + name + " without " + strings.Join(need, "/")
			out = append(out, violation("command", f, line, subj, "%s --%s needs %s", path, name, strings.Join(need, " or ")))
		}
	}
	return out
}
