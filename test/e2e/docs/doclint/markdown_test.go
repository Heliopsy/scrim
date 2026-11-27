// SPDX-License-Identifier: AGPL-3.0-only

// Package doclint checks the Markdown in the repository against the tree and
// the code, without the network:
//
//   - TestLinks: every relative link and #anchor in every Markdown file, and
//     every docs/*.md reference (with its #anchor or "Section" title) in code,
//     resolves.
//   - TestCommandReferences: every `scrim ...` invocation in the docs names a
//     command and flags of the cobra tree, with the flags a "with --x:" flag
//     needs.
//   - TestSettingReferences: every SCRIM_* variable and dotted setting key in
//     the docs is in the settings registry or is read by the code.
//   - TestReleaseVersions: every scrim release version the docs name was
//     released (a v* tag or a CHANGELOG.md heading) or is the release-please
//     manifest version.
//   - TestCLIReference: docs/reference/cli is what the cobra tree generates.
//
// Known violations, each with the docs audit item that covers it, are listed
// in known-violations.txt. An entry that no longer matches fails the test, so
// it is deleted in the change that fixes the doc. Run it with
// `just docs-lint`.
package doclint

import (
	"bufio"
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"unicode"
)

// excluded are trees whose Markdown is not checked: build output, tools and
// agent skills installed by other programs, and generated results.
var excluded = regexp.MustCompile(`^(\.worktrees|\.tools|\.agents|\.claude|node_modules|target|dataplane/target|load-results)/|^bench/[^/]+/results/|/node_modules/`)

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("no go.mod above the test directory")
		}
		dir = parent
	}
}

// repoFiles lists the files git tracks or would track (untracked but not
// ignored), relative to root, filtered by keep.
func repoFiles(t *testing.T, root string, keep func(string) bool) []string {
	t.Helper()
	cmd := exec.Command("git", "ls-files", "-z", "--cached", "--others", "--exclude-standard")
	cmd.Dir = root
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("git ls-files: %v", err)
	}
	seen := map[string]bool{}
	var files []string
	for f := range strings.SplitSeq(string(out), "\x00") {
		if f == "" || seen[f] || excluded.MatchString(f) || !keep(f) {
			continue
		}
		if _, err := os.Stat(filepath.Join(root, f)); err != nil {
			continue // deleted in the work tree
		}
		seen[f] = true
		files = append(files, f)
	}
	sort.Strings(files)
	return files
}

func markdownFiles(t *testing.T, root string) []string {
	return repoFiles(t, root, func(f string) bool { return strings.HasSuffix(f, ".md") })
}

// Line is one line of a Markdown document with its fence context.
type Line struct {
	N     int    // 1-based
	Text  string // the line, with backslash continuations joined in fences
	Fence bool   // inside a fenced code block
	Lang  string // the fence's language
}

var fenceRe = regexp.MustCompile("^\\s*(`{3,}|~{3,})\\s*([^\\s`]*)")

// lines splits a Markdown document, marking fenced code. Fence lines
// themselves are dropped.
func lines(data []byte) []Line {
	var out []Line
	var marker, lang string
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	n := 0
	for sc.Scan() {
		n++
		text := sc.Text()
		if m := fenceRe.FindStringSubmatch(text); m != nil {
			switch {
			case marker == "":
				marker, lang = m[1], m[2]
				continue
			case strings.HasPrefix(m[1], marker[:1]) && len(m[1]) >= len(marker) && m[2] == "":
				marker, lang = "", ""
				continue
			}
		}
		out = append(out, Line{N: n, Text: text, Fence: marker != "", Lang: lang})
	}
	// Join shell continuations so one command is one line.
	for i := len(out) - 2; i >= 0; i-- {
		if out[i].Fence && out[i+1].Fence && strings.HasSuffix(strings.TrimRight(out[i].Text, " "), "\\") {
			t := strings.TrimRight(out[i].Text, " ")
			out[i].Text = t[:len(t)-1] + " " + strings.TrimSpace(out[i+1].Text)
		}
	}
	return out
}

var inlineCode = regexp.MustCompile("(`+)(.+?)(`+)")

// codeSpans returns the inline code spans of a prose line.
func codeSpans(text string) []string {
	var out []string
	for _, m := range inlineCode.FindAllStringSubmatch(text, -1) {
		if m[1] == m[3] {
			out = append(out, strings.TrimSpace(m[2]))
		}
	}
	return out
}

// stripCode removes the inline code spans of a prose line.
func stripCode(text string) string { return inlineCode.ReplaceAllString(text, "") }

var (
	headingRe = regexp.MustCompile(`^(#{1,6})\s+(.*?)\s*#*\s*$`)
	htmlTag   = regexp.MustCompile(`<[^>]+>`)
	mdLink    = regexp.MustCompile(`\[([^\]]*)\]\([^)]*\)`)
	htmlAnch  = regexp.MustCompile(`<a\s+(?:name|id)="([^"]+)"`)
)

// slug is GitHub's anchor for a heading: tags and link targets dropped,
// lower-cased, everything but letters, digits, `_`, `-` and spaces removed,
// spaces as dashes.
func slug(h string) string {
	// Tags are markup outside code spans and text inside them.
	parts := strings.Split(h, "`")
	for i := 0; i < len(parts); i += 2 {
		parts[i] = htmlTag.ReplaceAllString(parts[i], "")
	}
	h = strings.Join(parts, "")
	h = mdLink.ReplaceAllString(h, "$1")
	h = strings.ToLower(strings.TrimSpace(h))
	var b strings.Builder
	for _, r := range h {
		switch {
		case r == ' ':
			b.WriteByte('-')
		case r == '-' || r == '_' || unicode.IsLetter(r) || unicode.IsDigit(r) || unicode.Is(unicode.Mn, r):
			b.WriteRune(r)
		}
	}
	return b.String()
}

// Headings holds the anchors and the plain titles of a document.
type Headings struct {
	Anchors map[string]bool
	Titles  []string // lower-cased, without backticks
}

func headings(data []byte) Headings {
	h := Headings{Anchors: map[string]bool{}}
	count := map[string]int{}
	for _, l := range lines(data) {
		if l.Fence {
			continue
		}
		if m := headingRe.FindStringSubmatch(l.Text); m != nil {
			s := slug(m[2])
			if n := count[s]; n > 0 {
				h.Anchors[s+"-"+strconv.Itoa(n)] = true
			} else {
				h.Anchors[s] = true
			}
			count[s]++
			h.Titles = append(h.Titles, strings.ToLower(strings.ReplaceAll(strings.TrimSpace(m[2]), "`", "")))
		}
		for _, m := range htmlAnch.FindAllStringSubmatch(l.Text, -1) {
			h.Anchors[m[1]] = true
		}
	}
	return h
}

func readFile(t *testing.T, root, f string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, f)) // #nosec G304 -- the repository's own files
	if err != nil {
		t.Fatal(err)
	}
	return b
}
