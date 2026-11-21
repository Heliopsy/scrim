package main

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// crateDep is one dependency entry of a Cargo manifest.
type crateDep struct {
	key       string // the name in the manifest
	crate     string // the crates.io name (package = "..." or the key)
	req       string // version requirement, "" when none
	path      string
	git       string
	registry  string
	workspace bool // `x.workspace = true`: the version comes from [workspace.dependencies]
	table     string
	manifest  string
}

var (
	// [dependencies], [dev-dependencies], [build-dependencies], their
	// target-specific forms and [workspace.dependencies].
	depTable = regexp.MustCompile(`^(workspace\.)?(target\..+\.)?(dependencies|dev-dependencies|dev_dependencies|build-dependencies|build_dependencies)$`)
	// [dependencies.foo] and friends: one dependency as its own table.
	depSubTable = regexp.MustCompile(`^((?:workspace\.)?(?:target\..+\.)?(?:dependencies|dev-dependencies|dev_dependencies|build-dependencies|build_dependencies))\.("[^"]+"|'[^']+'|[A-Za-z0-9_-]+)$`)
)

// findManifests returns every Cargo.toml under root, skipping build output
// and hidden directories.
func findManifests(root string) ([]string, error) {
	var out []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && p != root && (d.Name() == "target" || strings.HasPrefix(d.Name(), ".")) {
			return filepath.SkipDir
		}
		if !d.IsDir() && d.Name() == "Cargo.toml" {
			out = append(out, p)
		}
		return nil
	})
	sort.Strings(out)
	return out, err
}

// parseManifest reads the dependency tables of a Cargo manifest. It handles
// the TOML Cargo manifests use (tables, dotted keys, strings, inline tables,
// arrays over several lines) and refuses anything in a dependency table it
// does not understand, so a dependency is never skipped silently.
func parseManifest(name string, data []byte) ([]crateDep, error) {
	var (
		deps  []crateDep
		table string
		sub   *crateDep // set inside [dependencies.foo]
	)
	flush := func() {
		if sub != nil {
			deps = append(deps, *sub)
			sub = nil
		}
	}
	lines := strings.Split(string(data), "\n")
	for i := 0; i < len(lines); i++ {
		lineNo := i + 1
		line := strings.TrimSpace(stripComment(lines[i]))
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") {
			flush()
			if strings.HasPrefix(line, "[[") {
				table = ""
				continue
			}
			if !strings.HasSuffix(line, "]") {
				return nil, fmt.Errorf("%s:%d: cannot read table header", name, lineNo)
			}
			table = strings.TrimSpace(line[1 : len(line)-1])
			if m := depSubTable.FindStringSubmatch(table); m != nil {
				key := unquote(m[2])
				sub = &crateDep{key: key, crate: key, table: m[1], manifest: name}
			}
			continue
		}
		inDeps := depTable.MatchString(table)
		if !inDeps && sub == nil {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("%s:%d: expected key = value in [%s]", name, lineNo, table)
		}
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		// A value that opens a bracket or brace runs until it is balanced.
		for !balanced(value) {
			i++
			if i >= len(lines) {
				return nil, fmt.Errorf("%s:%d: unterminated value", name, lineNo)
			}
			value += " " + strings.TrimSpace(stripComment(lines[i]))
		}
		if sub != nil {
			setField(sub, unquote(key), value)
			continue
		}
		dep := crateDep{table: table, manifest: name}
		// name = ..., name.workspace = true, name.version = "..."
		dk, field, dotted := splitDotted(key)
		dep.key, dep.crate = dk, dk
		switch {
		case dotted:
			setField(&dep, field, value)
			// Merge with an earlier dotted key for the same dependency.
			if j := indexDep(deps, dep.table, dep.key); j >= 0 {
				setField(&deps[j], field, value)
				continue
			}
		case strings.HasPrefix(value, `"`) || strings.HasPrefix(value, `'`):
			dep.req = unquote(value)
		case strings.HasPrefix(value, "{"):
			fields, err := splitInline(value)
			if err != nil {
				return nil, fmt.Errorf("%s:%d: %w", name, lineNo, err)
			}
			for _, f := range fields {
				k, v, ok := strings.Cut(f, "=")
				if !ok {
					return nil, fmt.Errorf("%s:%d: cannot read %q", name, lineNo, f)
				}
				setField(&dep, unquote(strings.TrimSpace(k)), strings.TrimSpace(v))
			}
		default:
			return nil, fmt.Errorf("%s:%d: cannot read the value of %s", name, lineNo, key)
		}
		deps = append(deps, dep)
	}
	flush()
	return deps, nil
}

func indexDep(deps []crateDep, table, key string) int {
	for i, d := range deps {
		if d.table == table && d.key == key {
			return i
		}
	}
	return -1
}

func setField(d *crateDep, field, value string) {
	switch field {
	case "version":
		d.req = unquote(value)
	case "package":
		d.crate = unquote(value)
	case "path":
		d.path = unquote(value)
	case "git":
		d.git = unquote(value)
	case "registry", "registry-index":
		d.registry = unquote(value)
	case "workspace":
		d.workspace = value == "true"
	}
}

// splitDotted splits `name.field` (either part may be quoted).
func splitDotted(key string) (name, field string, dotted bool) {
	if strings.HasPrefix(key, `"`) || strings.HasPrefix(key, `'`) {
		q := key[:1]
		end := strings.Index(key[1:], q)
		if end < 0 {
			return key, "", false
		}
		name = key[1 : end+1]
		rest := strings.TrimSpace(key[end+2:])
		if f, ok := strings.CutPrefix(rest, "."); ok {
			return name, unquote(strings.TrimSpace(f)), true
		}
		return name, "", false
	}
	if n, f, ok := strings.Cut(key, "."); ok {
		return strings.TrimSpace(n), unquote(strings.TrimSpace(f)), true
	}
	return key, "", false
}

func unquote(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && (s[0] == '"' && s[len(s)-1] == '"' || s[0] == '\'' && s[len(s)-1] == '\'') {
		return s[1 : len(s)-1]
	}
	return s
}

// stripComment removes a # comment that is not inside a string.
func stripComment(line string) string {
	var quote byte
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case quote != 0:
			if c == '\\' && quote == '"' {
				i++
			} else if c == quote {
				quote = 0
			}
		case c == '"' || c == '\'':
			quote = c
		case c == '#':
			return line[:i]
		}
	}
	return line
}

// balanced reports whether every [ and { outside strings is closed.
func balanced(s string) bool {
	depth := 0
	var quote byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case quote != 0:
			if c == '\\' && quote == '"' {
				i++
			} else if c == quote {
				quote = 0
			}
		case c == '"' || c == '\'':
			quote = c
		case c == '[' || c == '{':
			depth++
		case c == ']' || c == '}':
			depth--
		}
	}
	return depth <= 0
}

// splitInline splits the fields of an inline table at top-level commas.
func splitInline(s string) ([]string, error) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "{") || !strings.HasSuffix(s, "}") {
		return nil, fmt.Errorf("cannot read inline table %q", s)
	}
	s = s[1 : len(s)-1]
	var (
		out   []string
		depth int
		quote byte
		start int
	)
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case quote != 0:
			if c == '\\' && quote == '"' {
				i++
			} else if c == quote {
				quote = 0
			}
		case c == '"' || c == '\'':
			quote = c
		case c == '[' || c == '{':
			depth++
		case c == ']' || c == '}':
			depth--
		case c == ',' && depth == 0:
			out = append(out, strings.TrimSpace(s[start:i]))
			start = i + 1
		}
	}
	if last := strings.TrimSpace(s[start:]); last != "" {
		out = append(out, last)
	}
	return out, nil
}

// reqVersion returns the lowest version a Cargo requirement admits, which
// names the release line it is on: "0.13" is 0.13.0, "^1.2" is 1.2.0,
// "~1.2" is 1.2.0. Ranges and wildcards are refused: they name no single
// line, and the gate fails closed on what it cannot judge.
func reqVersion(req string) (version, error) {
	first := strings.TrimSpace(req)
	first = strings.TrimLeft(first, "^~=")
	first = strings.TrimSpace(first)
	if first == "" || strings.ContainsAny(first, "*xX<>,") {
		return version{}, fmt.Errorf("requirement %q names no version line; use a caret requirement", req)
	}
	v, ok := parseVersion(first)
	if !ok {
		return version{}, fmt.Errorf("cannot read requirement %q", req)
	}
	return v, nil
}

// readCargo returns the registry dependencies of every manifest under root.
// Path-only and workspace-inherited entries are left out: a path crate is
// local, and an inherited one is checked where [workspace.dependencies]
// declares it.
func readCargo(root string) (deps []crateDep, skipped []string, err error) {
	manifests, err := findManifests(root)
	if err != nil {
		return nil, nil, err
	}
	if len(manifests) == 0 {
		return nil, nil, fmt.Errorf("no Cargo.toml under %s", root)
	}
	for _, m := range manifests {
		data, err := os.ReadFile(m)
		if err != nil {
			return nil, nil, err
		}
		all, err := parseManifest(m, data)
		if err != nil {
			return nil, nil, err
		}
		for _, d := range all {
			switch {
			case d.workspace:
			case d.git != "":
				skipped = append(skipped, fmt.Sprintf("%s: %s is a git dependency, not checked", m, d.key))
			case d.registry != "":
				skipped = append(skipped, fmt.Sprintf("%s: %s comes from registry %s, not checked", m, d.key, d.registry))
			case d.req == "" && d.path != "":
			case d.req == "":
				return nil, nil, fmt.Errorf("%s: %s in [%s] has no version", m, d.key, d.table)
			default:
				deps = append(deps, d)
			}
		}
	}
	return deps, skipped, nil
}
