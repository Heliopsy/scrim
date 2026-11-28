// SPDX-License-Identifier: AGPL-3.0-only

package doclint

import (
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var (
	// [text](target "title") and ![alt](target), and reference definitions.
	inlineLink = regexp.MustCompile(`\]\(\s*<?([^)\s>]+)>?(?:\s+"[^"]*")?\s*\)`)
	refDef     = regexp.MustCompile(`^\s{0,3}\[[^\]]+\]:\s*<?(\S+?)>?(?:\s+"[^"]*")?\s*$`)
	hrefAttr   = regexp.MustCompile(`<(?:a|img)\s[^>]*?(?:href|src)="([^"]+)"`)
	external   = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9+.-]*:`)
)

type linkChecker struct {
	t     *testing.T
	root  string
	heads map[string]*Headings
}

func (c *linkChecker) headings(f string) *Headings {
	if h, ok := c.heads[f]; ok {
		return h
	}
	h := headings(readFile(c.t, c.root, f))
	c.heads[f] = &h
	return &h
}

// check resolves target (relative to the file from) and returns a problem,
// or "".
func (c *linkChecker) check(from, target string) string {
	if external.MatchString(target) || strings.HasPrefix(target, "//") {
		return ""
	}
	p, frag, _ := strings.Cut(target, "#")
	if q := strings.IndexByte(p, '?'); q >= 0 {
		p = p[:q]
	}
	tgt := from
	if p != "" {
		if strings.HasPrefix(p, "/") {
			tgt = path.Clean(strings.TrimPrefix(p, "/"))
		} else {
			tgt = path.Clean(path.Join(path.Dir(from), p))
		}
		if strings.HasPrefix(tgt, "../") || tgt == ".." {
			return "target " + target + " is outside the repository"
		}
		if _, err := os.Stat(filepath.Join(c.root, filepath.FromSlash(tgt))); err != nil {
			return "missing target " + target
		}
	}
	if frag == "" || !strings.HasSuffix(tgt, ".md") {
		return ""
	}
	if !c.headings(tgt).Anchors[frag] {
		return "missing anchor #" + frag + " in " + tgt
	}
	return ""
}

// TestLinks checks every relative link and anchor in the repository's
// Markdown, as GitHub renders it.
func TestLinks(t *testing.T) {
	root := repoRoot(t)
	c := &linkChecker{t: t, root: root, heads: map[string]*Headings{}}
	var found []Violation
	files := markdownFiles(t, root)
	targets := 0
	for _, f := range files {
		for _, l := range lines(readFile(t, root, f)) {
			if l.Fence {
				continue
			}
			text := stripCode(l.Text)
			var ts []string
			for _, m := range inlineLink.FindAllStringSubmatch(text, -1) {
				ts = append(ts, m[1])
			}
			for _, m := range hrefAttr.FindAllStringSubmatch(text, -1) {
				ts = append(ts, m[1])
			}
			if m := refDef.FindStringSubmatch(text); m != nil {
				ts = append(ts, m[1])
			}
			for _, target := range ts {
				targets++
				if msg := c.check(f, target); msg != "" {
					found = append(found, violation("links", f, l.N, target, "%s", msg))
				}
			}
		}
	}
	t.Logf("%d links in %d Markdown files", targets, len(files))
	report(t, root, "links", found)
}

// A docs/*.md reference in code, optionally with an #anchor or followed by a
// quoted section title: docs/run.md, docs/run.md#tests, docs/run.md, "Tests"
// or docs/run.md "Tests".
var codeDocRef = regexp.MustCompile(`((?:docs|deploy|test|dataplane)/[A-Za-z0-9_/.-]+?\.md)(#[\w-]+)?(?:,?\s*"([A-Z` + "`" + `][^"$]*)")?`)

// codeExts are the files whose doc references are checked.
var codeExts = regexp.MustCompile(`(\.(go|rs|sh|ya?ml|json|toml|proto|tpl|txt|bash|py|js|ts)|/justfile|^justfile|Containerfile[^/]*)$`)

// TestCodeDocRefs checks the Markdown paths code and configuration point
// readers to (error messages, help text, comments): the file exists, and so
// does the #anchor or the quoted section heading after it.
func TestCodeDocRefs(t *testing.T) {
	root := repoRoot(t)
	c := &linkChecker{t: t, root: root, heads: map[string]*Headings{}}
	var found []Violation
	refs := 0
	for _, f := range repoFiles(t, root, func(f string) bool {
		return codeExts.MatchString(f) && !strings.HasPrefix(f, "test/e2e/docs/doclint/")
	}) {
		data := readFile(t, root, f)
		for i, line := range strings.Split(string(data), "\n") {
			for _, m := range codeDocRef.FindAllStringSubmatch(line, -1) {
				refs++
				doc := m[1]
				if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(doc))); err != nil {
					found = append(found, violation("coderefs", f, i+1, doc, "missing %s", doc))
					continue
				}
				h := c.headings(doc)
				if m[2] != "" && !h.Anchors[m[2][1:]] {
					found = append(found, violation("coderefs", f, i+1, doc+m[2], "missing anchor %s in %s", m[2], doc))
				}
				if title := strings.ToLower(m[3]); title != "" && !containsTitle(h.Titles, title) {
					found = append(found, violation("coderefs", f, i+1, doc+` "`+m[3]+`"`,
						"section %q is not a heading of %s", m[3], doc))
				}
			}
		}
	}
	t.Logf("%d doc references in code", refs)
	report(t, root, "coderefs", found)
}

func containsTitle(titles []string, want string) bool {
	for _, h := range titles {
		if strings.Contains(h, want) {
			return true
		}
	}
	return false
}
