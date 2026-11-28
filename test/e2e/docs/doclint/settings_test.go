// SPDX-License-Identifier: AGPL-3.0-only

package doclint

import (
	"regexp"
	"strings"
	"testing"

	"go.yaml.in/yaml/v4"

	"github.com/heliopsy/scrim/internal/config"
)

var (
	envName = regexp.MustCompile(`\bSCRIM_[A-Z0-9_]*[A-Z0-9]\b`)
	// A dotted key: lower-case segments, `<name>` or `*` for a free segment.
	// Underscores are accepted so that a snake_case name is caught.
	dottedKey = regexp.MustCompile(`^[a-z][a-z0-9-]*(?:\.(?:[a-z0-9_][a-z0-9_-]*|<[a-z-]+>|\*))+$`)
	// Last segments that make a dotted word a file or host name, not a key.
	fileOrHost = regexp.MustCompile(`\.(com|org|net|io|dev|ai|example|local|internal|svc|cluster|md|go|rs|sh|yaml|yml|json|toml|txt|pem|crt|key|sock|db|lock|service|socket|slice|conf|d|j2|tpl|py|js|ts|html|svg|png|log|tar|gz|zst|exe|plist|proto|sum)$`)
)

// codeEnvNames are the SCRIM_* names the code itself uses outside the
// settings registry (SCRIM_CONFIG, SCRIM_DP_FD, test switches): names that
// appear in a Go or Rust string literal or in a script, configuration or
// workflow file (in Go and Rust, the whole literal, so that "SCRIM_X=1" in
// a test does not count).
//
// It also returns the dotted names in Go and Rust string literals (audit
// actions and events such as "config.reloaded"), which docs may quote in code
// spans like keys.
func codeEnvNames(t *testing.T, root string) (envs, dotted map[string]bool) {
	literal := regexp.MustCompile(`"(SCRIM_[A-Z0-9_]*[A-Z0-9])"`)
	dottedLit := regexp.MustCompile(`"([a-z][a-z0-9_-]*(?:\.[a-z0-9_][a-z0-9_-]*)+)"`)
	envs, dotted = map[string]bool{}, map[string]bool{}
	for _, f := range repoFiles(t, root, func(f string) bool {
		// The registry's own tests and fixtures use made-up settings.
		registryTest := strings.HasPrefix(f, "internal/config/") &&
			(strings.HasSuffix(f, "_test.go") || strings.HasPrefix(f, "internal/config/testdata/"))
		return codeExts.MatchString(f) && !registryTest && !strings.HasPrefix(f, "test/e2e/docs/doclint/")
	}) {
		data := string(readFile(t, root, f))
		if strings.HasSuffix(f, ".go") || strings.HasSuffix(f, ".rs") {
			for _, m := range literal.FindAllStringSubmatch(data, -1) {
				envs[m[1]] = true
			}
			for _, m := range dottedLit.FindAllStringSubmatch(data, -1) {
				dotted[m[1]] = true
			}
			continue
		}
		for _, m := range envName.FindAllString(data, -1) {
			envs[m] = true
		}
	}
	return envs, dotted
}

// helmPaths returns every dotted path of the chart's values.yaml.
func helmPaths(t *testing.T, root string) map[string]bool {
	var doc map[string]any
	if err := yaml.Unmarshal(readFile(t, root, "deploy/helm/scrim/values.yaml"), &doc); err != nil {
		t.Fatal(err)
	}
	out := map[string]bool{}
	var walk func(prefix string, v any)
	walk = func(prefix string, v any) {
		m, ok := v.(map[string]any)
		if !ok {
			return
		}
		for k, sub := range m {
			p := k
			if prefix != "" {
				p = prefix + "." + k
			}
			out[p] = true
			walk(p, sub)
		}
	}
	walk("", doc)
	return out
}

// settingIndex answers whether an environment variable or a dotted key names
// something in the registry.
type settingIndex struct {
	reg      *config.Registry
	top      map[string]bool   // first segments of every key
	prefixes map[string]bool   // every proper prefix of a key (sections)
	colKeys  []string          // collection keys
	mapKeys  []*config.Setting // map settings, whose entries are free
}

func newSettingIndex(reg *config.Registry) *settingIndex {
	ix := &settingIndex{reg: reg, top: map[string]bool{}, prefixes: map[string]bool{}}
	add := func(key string) {
		segs := strings.Split(key, ".")
		ix.top[segs[0]] = true
		for i := 1; i < len(segs); i++ {
			ix.prefixes[strings.Join(segs[:i], ".")] = true
		}
	}
	for _, s := range reg.Settings() {
		add(s.Key)
		if s.Kind == config.KindMap {
			ix.mapKeys = append(ix.mapKeys, s)
		}
	}
	for _, c := range reg.Collections() {
		add(c.Key + ".x")
		ix.colKeys = append(ix.colKeys, c.Key)
	}
	return ix
}

// env reports whether name is read by the configuration loader: a setting,
// an entry of a map setting, or a collection (whole or one field).
func (ix *settingIndex) env(name string) bool {
	if name == "SCRIM_CONFIG" {
		return true
	}
	if _, ok := ix.reg.LookupEnv(name); ok {
		return true
	}
	for _, s := range ix.mapKeys {
		if strings.HasPrefix(name, s.EnvVar()+"_") {
			return true
		}
	}
	for _, c := range ix.colKeys {
		if v := config.EnvVar(c); name == v || strings.HasPrefix(name, v+"_") {
			return true
		}
	}
	return false
}

// key reports whether a dotted key names a setting, a section, an entry of a
// map setting or a field of a collection instance.
func (ix *settingIndex) key(k string) bool {
	k = strings.TrimSuffix(k, ".*")
	if _, ok := ix.reg.Lookup(k); ok || ix.prefixes[k] {
		return true
	}
	if strings.ContainsAny(k, "<*") {
		// audit.<sink>.queue-size: any key or section the pattern matches.
		segs := strings.Split(k, ".")
		for i, s := range segs {
			if strings.HasPrefix(s, "<") || s == "*" {
				segs[i] = `[^.]+`
			} else {
				segs[i] = regexp.QuoteMeta(s)
			}
		}
		re := regexp.MustCompile(`^` + strings.Join(segs, `\.`) + `(\..+)?$`)
		for _, s := range ix.reg.Settings() {
			if re.MatchString(s.Key) {
				return true
			}
		}
	}
	for _, s := range ix.mapKeys {
		if strings.HasPrefix(k, s.Key+".") {
			return true
		}
	}
	for _, c := range ix.colKeys {
		if strings.HasPrefix(k, c+".") {
			return true
		}
	}
	return false
}

// TestSettingReferences checks the SCRIM_* variables (anywhere in the docs)
// and the dotted setting keys (in code spans) against the settings registry.
// A variable the registry does not know must be one the code reads itself.
func TestSettingReferences(t *testing.T) {
	root := repoRoot(t)
	ix := newSettingIndex(config.Default)
	codeNames, codeDotted := codeEnvNames(t, root)
	helm := helmPaths(t, root)
	var found []Violation
	envs, keys := 0, 0
	for _, f := range referenceDocs(t, root) {
		ls := lines(readFile(t, root, f))
		genFrom, genTo := generatedRange(f, ls)
		for _, l := range ls {
			if l.N > genFrom && l.N < genTo {
				continue
			}
			for _, loc := range envName.FindAllStringIndex(l.Text, -1) {
				name := l.Text[loc[0]:loc[1]]
				if before := l.Text[:loc[0]]; strings.HasSuffix(before, "env:") || strings.HasSuffix(before, "://") {
					continue // a secret reference to a variable the user names
				}
				envs++
				if !ix.env(name) && !codeNames[name] {
					found = append(found, violation("setting", f, l.N, name,
						"%s is not a setting's variable and no code reads it", name))
				}
			}
			if l.Fence {
				continue
			}
			for _, span := range codeSpans(l.Text) {
				span = strings.TrimSuffix(strings.TrimSpace(span), ".")
				if !dottedKey.MatchString(span) || fileOrHost.MatchString(span) || strings.Contains(span, "__") {
					continue
				}
				if !ix.top[strings.SplitN(span, ".", 2)[0]] {
					continue // not under a settings section: a host, a type, a field
				}
				keys++
				if codeDotted[span] {
					continue // an audit action, event or other name the code defines
				}
				if helm[span] {
					continue // a Helm value of the chart
				}
				if rest, ok := strings.CutPrefix(span, "config."); ok && helm["config"] && ix.key(rest) {
					continue // the chart's config value holds scrim's configuration
				}
				if !ix.key(span) {
					found = append(found, violation("setting", f, l.N, span, "%s is not a setting key%s", span, closest(ix.reg, span)))
				}
			}
		}
	}
	t.Logf("%d variables and %d dotted keys checked", envs, keys)
	report(t, root, "setting", found)
}

func closest(r *config.Registry, k string) string {
	if c := r.Closest(k); c != "" {
		return " (did you mean " + c + "?)"
	}
	return ""
}
