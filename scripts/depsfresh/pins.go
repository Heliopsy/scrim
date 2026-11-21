package main

// Pinned tools, images and actions (-pins).
//
// The pins are the ones Renovate keeps current: depsfresh reads the custom
// regex managers of renovate.json and extracts the same dependencies from the
// same files, so an annotation Renovate cannot see is one this check cannot
// see either (TestRenovateSeesEveryAnnotation guards that). The GitHub Actions
// a workflow uses, pinned by SHA with a version comment, are read from
// .github directly; Dependabot updates those.
//
// A pin is BEHIND when a newer stable release than the pinned one has been
// out for longer than the grace period (-pins-grace), which leaves the weekly
// Renovate and Dependabot pull requests time to land. A newer release inside
// the grace period is "pending" and does not fail. Only the parts of
// Renovate's configuration the pins here use are understood: regex managers
// with the "any" and "recursive" strategies, {{name}} templates, and package
// rules matching depNames or package names that set enabled, versioning
// ("ubuntu") or allowedVersions ("<x.y.z", "/regex/").

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

type pin struct {
	datasource, depName, packageName string
	currentValue, currentDigest      string
	extractVersion, versioning       string
	registryURL, allowedVersions     string
	action                           bool
	where                            []string
}

type renovateConfig struct {
	PackageRules   []packageRule   `json:"packageRules"`
	CustomManagers []customManager `json:"customManagers"`
}

type customManager struct {
	CustomType             string   `json:"customType"`
	ManagerFilePatterns    []string `json:"managerFilePatterns"`
	MatchStrings           []string `json:"matchStrings"`
	MatchStringsStrategy   string   `json:"matchStringsStrategy"`
	DatasourceTemplate     string   `json:"datasourceTemplate"`
	DepNameTemplate        string   `json:"depNameTemplate"`
	PackageNameTemplate    string   `json:"packageNameTemplate"`
	VersioningTemplate     string   `json:"versioningTemplate"`
	ExtractVersionTemplate string   `json:"extractVersionTemplate"`
	RegistryURLTemplate    string   `json:"registryUrlTemplate"`
	CurrentValueTemplate   string   `json:"currentValueTemplate"`
}

type packageRule struct {
	MatchDepNames     []string `json:"matchDepNames"`
	MatchPackageNames []string `json:"matchPackageNames"`
	MatchCurrentValue string   `json:"matchCurrentValue"`
	Enabled           *bool    `json:"enabled"`
	Versioning        string   `json:"versioning"`
	AllowedVersions   string   `json:"allowedVersions"`
}

func readRenovate(path string) (*renovateConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c renovateConfig
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &c, nil
}

// slashRegex compiles Renovate's "/.../" pattern form.
func slashRegex(s string) (*regexp.Regexp, error) {
	if len(s) < 2 || s[0] != '/' {
		return nil, fmt.Errorf("pattern %q is not /regex/", s)
	}
	end := strings.LastIndexByte(s, '/')
	if end == 0 {
		return nil, fmt.Errorf("pattern %q is not /regex/", s)
	}
	expr, flags := s[1:end], s[end+1:]
	switch flags {
	case "":
	case "i":
		expr = "(?i)" + expr
	default:
		return nil, fmt.Errorf("pattern %q: flags %q not supported", s, flags)
	}
	return regexp.Compile(expr)
}

// matchName matches an exact name or a /regex/.
func matchName(pattern, name string) bool {
	if strings.HasPrefix(pattern, "/") {
		re, err := slashRegex(pattern)
		return err == nil && re.MatchString(name)
	}
	return pattern == name
}

var templateRef = regexp.MustCompile(`\{\{\{?\s*([A-Za-z]+)\s*\}?\}\}`)

func expand(tmpl string, groups map[string]string) string {
	return templateRef.ReplaceAllStringFunc(tmpl, func(m string) string {
		return groups[templateRef.FindStringSubmatch(m)[1]]
	})
}

// trackedFiles lists the regular files git tracks under root, relative to it
// (no symbolic links, which OpenSpec's skill links are, and nothing deleted
// in the working tree).
func trackedFiles(root string) ([]string, error) {
	out, err := exec.Command("git", "-C", root, "ls-files", "-z").Output()
	if err != nil {
		return nil, fmt.Errorf("git ls-files in %s: %w", root, err)
	}
	var files []string
	for _, f := range strings.Split(string(out), "\x00") {
		if f == "" {
			continue
		}
		if fi, err := os.Lstat(filepath.Join(root, f)); err == nil && fi.Mode().IsRegular() {
			files = append(files, f)
		}
	}
	return files, nil
}

type extracted struct {
	manager int
	pin     pin
}

// extractPins applies every custom regex manager to the files it selects.
func extractPins(root string, files []string, cfg *renovateConfig) ([]extracted, error) {
	var out []extracted
	for mi, m := range cfg.CustomManagers {
		if m.CustomType != "regex" {
			continue
		}
		var pats []*regexp.Regexp
		for _, p := range m.ManagerFilePatterns {
			re, err := slashRegex(p)
			if err != nil {
				return nil, fmt.Errorf("customManagers[%d]: %w", mi, err)
			}
			pats = append(pats, re)
		}
		var res []*regexp.Regexp
		for _, s := range m.MatchStrings {
			re, err := regexp.Compile(s)
			if err != nil {
				return nil, fmt.Errorf("customManagers[%d]: matchString %q: %w", mi, s, err)
			}
			res = append(res, re)
		}
		for _, f := range files {
			if !slices.ContainsFunc(pats, func(re *regexp.Regexp) bool { return re.MatchString(f) }) {
				continue
			}
			data, err := os.ReadFile(filepath.Join(root, f))
			if err != nil {
				return nil, err
			}
			text := string(data)
			for _, g := range applyStrategy(m.MatchStringsStrategy, res, text) {
				p := pin{
					datasource:     pick(g.groups["datasource"], m.DatasourceTemplate, g.groups),
					depName:        pick(g.groups["depName"], m.DepNameTemplate, g.groups),
					packageName:    pick(g.groups["packageName"], m.PackageNameTemplate, g.groups),
					currentValue:   pick(g.groups["currentValue"], m.CurrentValueTemplate, g.groups),
					currentDigest:  g.groups["currentDigest"],
					extractVersion: pick(g.groups["extractVersion"], m.ExtractVersionTemplate, g.groups),
					versioning:     pick(g.groups["versioning"], m.VersioningTemplate, g.groups),
					registryURL:    pick(g.groups["registryUrl"], m.RegistryURLTemplate, g.groups),
					where:          []string{f + ":" + strconv.Itoa(1+strings.Count(text[:g.offset], "\n"))},
				}
				if p.packageName == "" {
					p.packageName = p.depName
				}
				out = append(out, extracted{manager: mi, pin: p})
			}
		}
	}
	return out, nil
}

func pick(group, tmpl string, groups map[string]string) string {
	if group != "" {
		return group
	}
	return expand(tmpl, groups)
}

type match struct {
	groups map[string]string
	offset int
}

// applyStrategy runs matchStrings the way Renovate does: "any" (the default)
// applies each one to the whole file; "recursive" applies the next one to
// each match of the previous one.
func applyStrategy(strategy string, res []*regexp.Regexp, text string) []match {
	collect := func(re *regexp.Regexp, s string, base int, inherited map[string]string) []match {
		var ms []match
		for _, idx := range re.FindAllStringSubmatchIndex(s, -1) {
			g := map[string]string{}
			for k, v := range inherited {
				g[k] = v
			}
			off := idx[0]
			for i, name := range re.SubexpNames() {
				if name == "" || idx[2*i] < 0 {
					continue
				}
				g[name] = s[idx[2*i]:idx[2*i+1]]
				if name == "currentDigest" || (name == "currentValue" && g["currentDigest"] == "") {
					off = idx[2*i]
				}
			}
			ms = append(ms, match{groups: g, offset: base + off})
		}
		return ms
	}
	if strategy != "recursive" {
		var all []match
		for _, re := range res {
			all = append(all, collect(re, text, 0, nil)...)
		}
		return all
	}
	type span struct {
		text   string
		base   int
		groups map[string]string
	}
	spans := []span{{text: text}}
	var last []match
	for i, re := range res {
		var next []span
		last = nil
		for _, sp := range spans {
			for _, idx := range re.FindAllStringSubmatchIndex(sp.text, -1) {
				g := map[string]string{}
				for k, v := range sp.groups {
					g[k] = v
				}
				off := idx[0]
				for j, name := range re.SubexpNames() {
					if name != "" && idx[2*j] >= 0 {
						g[name] = sp.text[idx[2*j]:idx[2*j+1]]
						if name == "currentDigest" || (name == "currentValue" && g["currentDigest"] == "") {
							off = idx[2*j]
						}
					}
				}
				if i == len(res)-1 {
					last = append(last, match{groups: g, offset: sp.base + off})
				} else {
					next = append(next, span{text: sp.text[idx[0]:idx[1]], base: sp.base + idx[0], groups: g})
				}
			}
		}
		spans = next
	}
	return last
}

var actionUse = regexp.MustCompile(`uses:\s+([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)(?:/[^@\s]+)?@([0-9a-f]{40})\s+#\s+(v?[0-9][^\s]*)`)

// extractActions reads the SHA-pinned actions of every workflow and local
// action.
func extractActions(root string, files []string) ([]pin, error) {
	var out []pin
	for _, f := range files {
		if !strings.HasPrefix(f, ".github/") || (!strings.HasSuffix(f, ".yml") && !strings.HasSuffix(f, ".yaml")) {
			continue
		}
		data, err := os.ReadFile(filepath.Join(root, f))
		if err != nil {
			return nil, err
		}
		text := string(data)
		for _, idx := range actionUse.FindAllStringSubmatchIndex(text, -1) {
			out = append(out, pin{
				datasource: "github-releases", depName: text[idx[2]:idx[3]], packageName: text[idx[2]:idx[3]],
				currentDigest: text[idx[4]:idx[5]], currentValue: text[idx[6]:idx[7]], action: true,
				where: []string{f + ":" + strconv.Itoa(1+strings.Count(text[:idx[0]], "\n"))},
			})
		}
	}
	return out, nil
}

// applyRules applies the package rules depsfresh understands. It reports
// false for a pin Renovate does not manage (enabled: false).
func applyRules(p *pin, rules []packageRule) bool {
	for _, r := range rules {
		hit := len(r.MatchDepNames) > 0 || len(r.MatchPackageNames) > 0
		if len(r.MatchDepNames) > 0 && !slices.ContainsFunc(r.MatchDepNames, func(n string) bool { return matchName(n, p.depName) }) {
			hit = false
		}
		if len(r.MatchPackageNames) > 0 && !slices.ContainsFunc(r.MatchPackageNames, func(n string) bool { return matchName(n, p.packageName) }) {
			hit = false
		}
		if hit && r.MatchCurrentValue != "" && !matchName(r.MatchCurrentValue, p.currentValue) {
			hit = false
		}
		if !hit {
			continue
		}
		if r.Enabled != nil && !*r.Enabled {
			return false
		}
		if r.Versioning != "" {
			p.versioning = r.Versioning
		}
		if r.AllowedVersions != "" {
			p.allowedVersions = r.AllowedVersions
		}
	}
	return true
}

// groupPins merges the same dependency at the same version across files.
func groupPins(ps []pin) []pin {
	idx := map[string]int{}
	var out []pin
	for _, p := range ps {
		k := strings.Join([]string{p.datasource, p.packageName, p.currentValue, p.currentDigest, p.extractVersion, p.versioning, p.registryURL, p.allowedVersions, strconv.FormatBool(p.action)}, "\x00")
		if i, ok := idx[k]; ok {
			out[i].where = append(out[i].where, p.where...)
			continue
		}
		idx[k] = len(out)
		out = append(out, p)
	}
	return out
}

// ---------------------------------------------------------------- versions

// loose is a version as pins write it: a numeric part ("1.37.2", "26.04",
// "v0.33.0") and whatever follows ("-alpine3.24"). Releases only replace a pin
// with the same number of components and the same suffix, as Renovate's
// docker versioning does.
type loose struct {
	nums   []int64
	suffix string
}

var looseRe = regexp.MustCompile(`^v?([0-9]+(?:\.[0-9]+)*)(.*)$`)

func parseLoose(s string) (loose, bool) {
	m := looseRe.FindStringSubmatch(s)
	if m == nil {
		return loose{}, false
	}
	var l loose
	for _, p := range strings.Split(m[1], ".") {
		n, err := strconv.ParseInt(p, 10, 64)
		if err != nil {
			return loose{}, false
		}
		l.nums = append(l.nums, n)
	}
	l.suffix = m[2]
	return l, true
}

func (a loose) compare(b loose) int {
	for i := range min(len(a.nums), len(b.nums)) {
		if a.nums[i] != b.nums[i] {
			if a.nums[i] < b.nums[i] {
				return -1
			}
			return 1
		}
	}
	return len(a.nums) - len(b.nums)
}

// compatible reports whether a release can replace the pinned version.
func (a loose) compatible(cur loose) bool {
	return len(a.nums) == len(cur.nums) && a.suffix == cur.suffix
}

// allowed applies allowedVersions and the ubuntu versioning (LTS only).
func allowed(p pin, v loose) bool {
	if p.versioning == "ubuntu" && (len(v.nums) != 2 || v.nums[1] != 4 || v.nums[0]%2 != 0) {
		return false
	}
	a := strings.TrimSpace(p.allowedVersions)
	switch {
	case a == "":
		return true
	case strings.HasPrefix(a, "/"):
		return matchName(a, v.String())
	case strings.HasPrefix(a, "<="):
		lim, ok := parseLoose(strings.TrimSpace(a[2:]))
		return ok && v.compare(lim) <= 0
	case strings.HasPrefix(a, "<"):
		lim, ok := parseLoose(strings.TrimSpace(a[1:]))
		return ok && v.compare(lim) < 0
	}
	return true
}

func (a loose) String() string {
	parts := make([]string, len(a.nums))
	for i, n := range a.nums {
		parts[i] = strconv.FormatInt(n, 10)
	}
	return strings.Join(parts, ".") + a.suffix
}

// release is one version a datasource offers, after extractVersion.
type release struct {
	version string
	date    time.Time // zero when the datasource has none
	pre     bool
}

// newer returns the releases that may replace the pin and are newer than it,
// newest first.
func newer(p pin, rels []release) ([]release, error) {
	cur, ok := parseLoose(p.currentValue)
	if !ok {
		return nil, fmt.Errorf("cannot read version %q", p.currentValue)
	}
	var out []release
	for _, r := range rels {
		v, ok := parseLoose(r.version)
		if !ok || r.pre || !v.compatible(cur) || !allowed(p, v) || v.compare(cur) <= 0 {
			continue
		}
		out = append(out, r)
	}
	slices.SortFunc(out, func(a, b release) int {
		va, _ := parseLoose(a.version)
		vb, _ := parseLoose(b.version)
		return vb.compare(va)
	})
	return out, nil
}

// ---------------------------------------------------------------- check

func checkPin(ctx context.Context, src *sources, p pin, now time.Time, grace time.Duration) result {
	eco := "pin"
	if p.action {
		eco = "action"
	}
	r := result{eco: eco, name: p.depName, used: p.currentValue, latest: p.currentValue, status: statusOK, note: whereNote(p.where)}
	if p.datasource == "git-refs" {
		return checkCommit(ctx, src, p, r, now, grace)
	}
	if p.action {
		sha, err := src.githubTagCommit(ctx, p.packageName, p.currentValue)
		if err != nil {
			return fail(r, err)
		}
		if sha != p.currentDigest {
			r.status = statusError
			r.note = join(r.note, fmt.Sprintf("pinned SHA %s is not %s (%s)", short(p.currentDigest), p.currentValue, short(sha)))
			return r
		}
	}
	rels, supported, err := src.releases(ctx, p)
	if err != nil {
		return fail(r, err)
	}
	if !supported {
		r.status = statusSkipped
		r.latest = "-"
		r.note = join(r.note, "datasource "+p.datasource+" is not checked here; Renovate tracks it")
		return r
	}
	if _, ok := parseLoose(p.currentValue); !ok {
		r.status = statusSkipped
		r.note = join(r.note, "tag is not a version; its digest is Renovate's")
		return r
	}
	cands, err := newer(p, rels)
	if err != nil {
		return fail(r, err)
	}
	if len(cands) == 0 {
		return r
	}
	r.latest = cands[0].version
	limit := now.Add(-grace)
	for i, c := range cands {
		if i >= 5 {
			break // older candidates are older still
		}
		d := c.date
		if d.IsZero() {
			d, err = src.releaseDate(ctx, p, c.version)
			if err != nil {
				return fail(r, err)
			}
		}
		if !d.After(limit) {
			r.status = statusBehind
			if i > 0 {
				r.note = join(r.note, c.version+" is past the grace period")
			}
			return r
		}
		if i == 0 {
			r.status = statusPending
			r.note = join(r.note, fmt.Sprintf("released %s, within the %s grace period", d.Format(time.DateOnly), graceString(grace)))
		}
	}
	return r
}

func checkCommit(ctx context.Context, src *sources, p pin, r result, now time.Time, grace time.Duration) result {
	r.used = short(p.currentDigest)
	r.latest = r.used
	ahead, firstDate, head, err := src.commitsAfter(ctx, p.packageName, p.currentDigest, p.currentValue)
	if err != nil {
		return fail(r, err)
	}
	if ahead == 0 {
		return r
	}
	r.latest = short(head)
	if !firstDate.After(now.Add(-grace)) {
		r.status = statusBehind
		r.note = join(r.note, fmt.Sprintf("%d commits on %s since the pin", ahead, p.currentValue))
		return r
	}
	r.status = statusPending
	r.note = join(r.note, fmt.Sprintf("%d new commits on %s, within the grace period", ahead, p.currentValue))
	return r
}

func whereNote(where []string) string {
	if len(where) <= 2 {
		return strings.Join(where, ", ")
	}
	return fmt.Sprintf("%s, %s and %d more", where[0], where[1], len(where)-2)
}

func short(sha string) string {
	if len(sha) > 12 {
		return sha[:12]
	}
	return sha
}

func graceString(d time.Duration) string {
	if d%(24*time.Hour) == 0 {
		return strconv.Itoa(int(d/(24*time.Hour))) + "d"
	}
	return d.String()
}

// parseGrace reads "14d" or a Go duration.
func parseGrace(s string) (time.Duration, error) {
	if n, ok := strings.CutSuffix(s, "d"); ok {
		d, err := strconv.Atoi(n)
		if err != nil || d < 0 {
			return 0, fmt.Errorf("grace %q: want <days>d or a duration", s)
		}
		return time.Duration(d) * 24 * time.Hour, nil
	}
	return time.ParseDuration(s)
}

// pinTasks extracts every pin and action and returns one check per distinct
// dependency.
func pinTasks(ctx context.Context, opts options, now time.Time) ([]func() result, error) {
	cfg, err := readRenovate(filepath.Join(opts.root, opts.renovate))
	if err != nil {
		return nil, err
	}
	files, err := trackedFiles(opts.root)
	if err != nil {
		return nil, err
	}
	ex, err := extractPins(opts.root, files, cfg)
	if err != nil {
		return nil, err
	}
	var ps []pin
	for _, e := range ex {
		p := e.pin
		if applyRules(&p, cfg.PackageRules) {
			ps = append(ps, p)
		}
	}
	acts, err := extractActions(opts.root, files)
	if err != nil {
		return nil, err
	}
	ps = append(ps, acts...)
	src := newSources(opts)
	var tasks []func() result
	for _, p := range groupPins(ps) {
		tasks = append(tasks, func() result { return checkPin(ctx, src, p, now, opts.grace) })
	}
	return tasks, nil
}
