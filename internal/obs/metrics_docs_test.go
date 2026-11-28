// SPDX-License-Identifier: AGPL-3.0-only

package obs_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

const repoRoot = "../.."

// TestMetricsDocumented keeps docs/monitoring.md, the alert rules and the
// dashboard in step with the metrics the code registers: every scrim_* metric
// registered in Go or exported by the data plane has a row in the reference
// tables, every row names a registered metric, and every scrim_* name in the
// rules and the dashboard exists.
func TestMetricsDocumented(t *testing.T) {
	code := goMetrics(t)
	for name := range rustMetrics(t) {
		code[name] = true
	}
	if len(code) < 60 {
		t.Fatalf("found only %d metrics in the code; the source scan is broken", len(code))
	}

	doc := documentedMetrics(t)
	for _, name := range sortedKeys(code) {
		if !doc[name] {
			t.Errorf("metric %s is registered but has no row in docs/monitoring.md", name)
		}
	}
	for _, name := range sortedKeys(doc) {
		if !code[name] {
			t.Errorf("docs/monitoring.md lists %s, which the code does not register", name)
		}
	}

	for _, file := range []string{
		"deploy/monitoring/rules/scrim.rules.yaml",
		"deploy/monitoring/grafana/scrim-dashboard.json",
	} {
		data, err := os.ReadFile(filepath.Join(repoRoot, file))
		if err != nil {
			t.Fatal(err)
		}
		for _, name := range regexp.MustCompile(`\bscrim_[a-z0-9_]+\*?`).FindAllString(string(data), -1) {
			if strings.HasSuffix(name, "*") { // a prefix in prose, such as scrim_dataplane_*
				continue
			}
			if !code[name] && !code[strings.TrimSuffix(strings.TrimSuffix(strings.TrimSuffix(name, "_bucket"), "_sum"), "_count")] {
				t.Errorf("%s uses %s, which the code does not register", file, name)
			}
		}
	}
}

// goMetrics finds the metrics registered in Go: Metrics.Counter, Gauge and
// Histogram calls (scrim_<subsystem>_<name>) and prometheus.NewDesc with a
// constant name.
func goMetrics(t *testing.T) map[string]bool {
	t.Helper()
	names := map[string]bool{}
	fset := token.NewFileSet()
	for _, dir := range []string{"internal", "pkg"} {
		err := filepath.WalkDir(filepath.Join(repoRoot, dir), func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return err
			}
			f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
			if err != nil {
				return err
			}
			ast.Inspect(f, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				switch sel.Sel.Name {
				case "Counter", "Gauge", "Histogram":
					if len(call.Args) < 3 {
						return true
					}
					sub, ok1 := stringLit(call.Args[0])
					name, ok2 := stringLit(call.Args[1])
					if !ok1 || !ok2 {
						t.Errorf("%s: %s with a name that is not a string literal", fset.Position(call.Pos()), sel.Sel.Name)
						return true
					}
					parts := []string{"scrim"}
					if sub != "" {
						parts = append(parts, sub)
					}
					names[strings.Join(append(parts, name), "_")] = true
				case "NewDesc":
					if name, ok := descName(call.Args[0]); ok {
						names[name] = true
					}
				}
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return names
}

// descName reads a NewDesc name: a literal, or Namespace + a literal.
// Anything else (the data plane collector forwarding its families) is not a
// fixed metric.
func descName(e ast.Expr) (string, bool) {
	if s, ok := stringLit(e); ok {
		return s, strings.HasPrefix(s, "scrim_")
	}
	if b, ok := e.(*ast.BinaryExpr); ok && b.Op == token.ADD {
		if id, ok := b.X.(*ast.Ident); ok && id.Name == "Namespace" {
			if s, ok := stringLit(b.Y); ok {
				return "scrim" + s, true
			}
		}
	}
	return "", false
}

func stringLit(e ast.Expr) (string, bool) {
	lit, ok := e.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return "", false
	}
	s, err := strconv.Unquote(lit.Value)
	return s, err == nil
}

// rustMetrics finds the families the data plane exports
// (Family::counter, gauge and histogram).
func rustMetrics(t *testing.T) map[string]bool {
	t.Helper()
	re := regexp.MustCompile(`Family::(?:counter|gauge|histogram)\(\s*"([a-z0-9_]+)"`)
	names := map[string]bool{}
	err := filepath.WalkDir(filepath.Join(repoRoot, "dataplane", "crates"), func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == "target" || d.Name() == "tests" || d.Name() == "benches") {
			return filepath.SkipDir
		}
		if d.IsDir() || !strings.HasSuffix(path, ".rs") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		src := string(data)
		// Unit tests build families of their own.
		if i := strings.Index(src, "#[cfg(test)]"); i >= 0 {
			src = src[:i]
		}
		for _, m := range re.FindAllStringSubmatch(src, -1) {
			names[m[1]] = true
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return names
}

// documentedMetrics reads the metric names in the first column of the
// reference tables in docs/monitoring.md.
func documentedMetrics(t *testing.T) map[string]bool {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(repoRoot, "docs", "monitoring.md"))
	if err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompile("(?m)^\\| `(scrim_[a-z0-9_]+)` \\|")
	names := map[string]bool{}
	for _, m := range re.FindAllStringSubmatch(string(data), -1) {
		names[m[1]] = true
	}
	return names
}

func sortedKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}
