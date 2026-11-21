// Command depsfresh is the dependency freshness gate (`just deps-fresh`,
// scripts/deps-fresh.sh). It fails when a direct dependency is behind its
// latest stable major release:
//
//   - Go: every require in go.mod that is not // indirect, plus the modules
//     that provide a `tool`. Behind means a newer major module path exists
//     (/v2, /v3, ...) with a stable release, or the same path has a stable
//     release of a higher major (v0 to v1). A module whose latest go.mod is
//     marked Deprecated (renamed or replaced) fails too.
//   - Rust: every registry entry of [dependencies], [dev-dependencies],
//     [build-dependencies] (and their target forms) and
//     [workspace.dependencies] in every Cargo.toml under dataplane/. Behind
//     means the requirement is on an older breaking line than the newest
//     stable release: the major from 1.0 on, the 0.x minor before that.
//
// Minor and patch lag on a post-1.0 line is left to Dependabot. Exceptions
// live in .deps-fresh-ignore, each with an expiry date and a reason.
//
// The only network calls go to the Go module proxy and the crates.io sparse
// index.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"text/tabwriter"
	"time"
)

type status string

const (
	statusOK         status = "ok"
	statusBehind     status = "BEHIND"
	statusDeprecated status = "DEPRECATED"
	statusIgnored    status = "ignored"
	statusError      status = "ERROR"
)

func (s status) fails() bool {
	return s == statusBehind || s == statusDeprecated || s == statusError
}

type result struct {
	eco, name, used, latest string
	status                  status
	note                    string
}

type options struct {
	goMod       string
	cargoRoot   string
	ignore      string
	goProxy     string
	cratesIndex string
	jobs        int
	now         func() time.Time
}

func main() {
	opts := options{now: time.Now}
	fs := flag.NewFlagSet("deps-fresh", flag.ContinueOnError)
	fs.StringVar(&opts.goMod, "go-mod", "go.mod", "go.mod to check (empty to skip Go)")
	fs.StringVar(&opts.cargoRoot, "cargo-root", "dataplane", "directory whose Cargo.toml files are checked (empty to skip Rust)")
	fs.StringVar(&opts.ignore, "ignore", ".deps-fresh-ignore", "ignore list")
	fs.StringVar(&opts.goProxy, "go-proxy", defaultGoProxy, "Go module proxy (tests only)")
	fs.StringVar(&opts.cratesIndex, "crates-index", defaultCratesIndex, "crates.io sparse index (tests only)")
	fs.IntVar(&opts.jobs, "jobs", 8, "parallel registry lookups")
	if err := fs.Parse(os.Args[1:]); err != nil {
		os.Exit(2)
	}
	code, err := run(context.Background(), opts, os.Stdout)
	if err != nil {
		fmt.Fprintln(os.Stderr, "deps-fresh:", err)
		os.Exit(2)
	}
	os.Exit(code)
}

// run checks everything and writes the report to w. It returns 1 when the
// gate fails and an error when it cannot run at all.
func run(ctx context.Context, opts options, w io.Writer) (int, error) {
	ignores, err := readIgnore(opts.ignore)
	if err != nil {
		return 0, err
	}
	reg := newRegistry(opts.goProxy, opts.cratesIndex)
	var tasks []func() result

	if opts.goMod != "" {
		mods, err := readGoMod(opts.goMod)
		if err != nil {
			return 0, err
		}
		for _, m := range mods {
			tasks = append(tasks, func() result { return checkGo(ctx, reg, m) })
		}
	}
	var skipped []string
	if opts.cargoRoot != "" {
		deps, sk, err := readCargo(opts.cargoRoot)
		if err != nil {
			return 0, err
		}
		skipped = sk
		for _, g := range groupCrates(deps) {
			tasks = append(tasks, func() result { return checkCrate(ctx, reg, g) })
		}
	}

	results := make([]result, len(tasks))
	sem := make(chan struct{}, max(1, opts.jobs))
	var wg sync.WaitGroup
	for i, t := range tasks {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			results[i] = t()
		}()
	}
	wg.Wait()

	now := opts.now()
	var problems []string
	for i := range results {
		r := &results[i]
		e := ignores.find(r.eco, r.name)
		if e == nil {
			continue
		}
		if !r.status.fails() || r.status == statusError {
			continue
		}
		e.used = true
		if e.expired(now) {
			r.note = join(r.note, "ignore entry expired "+e.expires.Format(time.DateOnly))
			continue
		}
		r.status = statusIgnored
		r.note = join(r.note, "ignored until "+e.expires.Format(time.DateOnly)+": "+e.reason)
	}
	for _, e := range ignores {
		if e.expired(now) {
			problems = append(problems, fmt.Sprintf("%s:%d: entry for %s %s expired on %s; upgrade or renew it with a new reason",
				opts.ignore, e.line, e.eco, e.name, e.expires.Format(time.DateOnly)))
		}
	}

	sort.Slice(results, func(i, j int) bool {
		if results[i].eco != results[j].eco {
			return results[i].eco > results[j].eco // go before cargo
		}
		if results[i].name != results[j].name {
			return results[i].name < results[j].name
		}
		return results[i].used < results[j].used
	})
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "STATUS\tECOSYSTEM\tDEPENDENCY\tUSED\tLATEST\tNOTE")
	failed := 0
	for _, r := range results {
		if r.status.fails() {
			failed++
		}
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", r.status, r.eco, r.name, r.used, r.latest, r.note)
	}
	if err := tw.Flush(); err != nil {
		return 0, err
	}
	for _, s := range skipped {
		_, _ = fmt.Fprintln(w, "note:", s)
	}
	for _, e := range ignores {
		if !e.used {
			_, _ = fmt.Fprintf(w, "warning: %s:%d: %s %s matches no dependency that is behind; remove the entry\n", opts.ignore, e.line, e.eco, e.name)
		}
	}
	for _, p := range problems {
		_, _ = fmt.Fprintln(w, "error:", p)
	}
	if failed > 0 || len(problems) > 0 {
		_, _ = fmt.Fprintf(w, "deps-fresh: %d of %d direct dependencies fail the gate, %d expired ignore entries.\n", failed, len(results), len(problems))
		_, _ = fmt.Fprintln(w, "Look the latest stable release up in the registry and move to it; .deps-fresh-ignore takes a dated, explained exception.")
		return 1, nil
	}
	_, _ = fmt.Fprintf(w, "deps-fresh: all %d direct dependencies are on their latest major.\n", len(results))
	return 0, nil
}

// ---------------------------------------------------------------- Go

type goModule struct {
	path, version string
	tool          bool
}

// readGoMod returns the direct requirements of a go.mod and the modules that
// provide its tools, using `go mod edit -json` (no network).
func readGoMod(path string) ([]goModule, error) {
	out, err := exec.Command("go", "mod", "edit", "-json", path).Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return nil, fmt.Errorf("go mod edit -json %s: %s", path, strings.TrimSpace(string(ee.Stderr)))
		}
		return nil, fmt.Errorf("go mod edit -json %s: %w", path, err)
	}
	return parseGoModJSON(out)
}

func parseGoModJSON(data []byte) ([]goModule, error) {
	var mf struct {
		Require []struct {
			Path, Version string
			Indirect      bool
		}
		Tool []struct{ Path string }
	}
	if err := json.Unmarshal(data, &mf); err != nil {
		return nil, err
	}
	toolMod := map[string]bool{}
	for _, t := range mf.Tool {
		best := ""
		for _, r := range mf.Require {
			if (t.Path == r.Path || strings.HasPrefix(t.Path, r.Path+"/")) && len(r.Path) > len(best) {
				best = r.Path
			}
		}
		if best != "" {
			toolMod[best] = true
		}
	}
	var mods []goModule
	for _, r := range mf.Require {
		if r.Indirect && !toolMod[r.Path] {
			continue
		}
		mods = append(mods, goModule{path: r.Path, version: r.Version, tool: toolMod[r.Path]})
	}
	return mods, nil
}

var (
	majorSuffix  = regexp.MustCompile(`^(.+)/v([0-9]+)$`)
	gopkgSuffix  = regexp.MustCompile(`^(gopkg\.in/.+)\.v([0-9]+)$`)
	errNoRelease = errors.New("no stable release")
)

// splitMajor returns the path without its major suffix, the major the path
// names (1 for a path without one) and how to spell another major's path.
func splitMajor(path string) (base string, major int64, pathFor func(int64) string) {
	if m := gopkgSuffix.FindStringSubmatch(path); m != nil {
		n, _ := strconv.ParseInt(m[2], 10, 64)
		return m[1], n, func(k int64) string { return m[1] + ".v" + strconv.FormatInt(k, 10) }
	}
	if m := majorSuffix.FindStringSubmatch(path); m != nil {
		if n, _ := strconv.ParseInt(m[2], 10, 64); n >= 2 {
			return m[1], n, func(k int64) string { return m[1] + "/v" + strconv.FormatInt(k, 10) }
		}
	}
	return path, 1, func(k int64) string { return path + "/v" + strconv.FormatInt(k, 10) }
}

func checkGo(ctx context.Context, reg *registry, m goModule) result {
	r := result{eco: "go", name: m.path, used: m.version, status: statusOK}
	if m.tool {
		r.note = "tool"
	}
	used, ok := parseVersion(m.version)
	if !ok {
		return fail(r, fmt.Errorf("cannot read version %q", m.version))
	}
	same, err := goLatestStable(ctx, reg, m.path)
	if err != nil && !errors.Is(err, errNoRelease) {
		return fail(r, err)
	}
	if errors.Is(err, errNoRelease) {
		r.latest = "(no stable release)"
		r.note = join(r.note, "module has no tagged stable release")
	} else {
		r.latest = "v" + same.String()
		if same.major > used.major {
			r.status = statusBehind
		}
		dep, err := reg.goDeprecation(ctx, m.path, "v"+same.String())
		if err != nil {
			return fail(r, err)
		}
		if dep != "" {
			r.status = statusDeprecated
			r.note = join(r.note, "Deprecated: "+dep)
		}
	}

	_, major, pathFor := splitMajor(m.path)
	if major < 1 {
		major = 1
	}
	// Probe /v(N+1), /v(N+2), ... until the proxy has no such module.
	for k := major + 1; k <= major+20; k++ {
		p := pathFor(k)
		v, err := goLatestStable(ctx, reg, p)
		if errors.Is(err, errNotFound) {
			break
		}
		if errors.Is(err, errNoRelease) {
			continue // a new major with pre-releases only does not count yet
		}
		if err != nil {
			return fail(r, err)
		}
		r.status = statusBehind
		r.latest = p + "@v" + v.String()
	}
	return r
}

var errNotFound = errors.New("module not found")

// goLatestStable returns the newest stable version of a module path,
// errNotFound when the proxy has no such module and errNoRelease when it has
// no stable release.
func goLatestStable(ctx context.Context, reg *registry, path string) (version, error) {
	list, found, err := reg.goVersions(ctx, path)
	if err != nil {
		return version{}, err
	}
	if found {
		if v, ok := latestStable(list); ok {
			return v, nil
		}
		return version{}, errNoRelease
	}
	// No tags: @latest still names a pseudo-version if the module exists.
	_, found, err = reg.goLatestQuery(ctx, path)
	if err != nil {
		return version{}, err
	}
	if !found {
		return version{}, errNotFound
	}
	return version{}, errNoRelease
}

// ---------------------------------------------------------------- Rust

// crateGroup is one crate at one requirement, with every manifest that
// requires it so.
type crateGroup struct {
	crate, req string
	where      []string
}

func groupCrates(deps []crateDep) []crateGroup {
	idx := map[string]int{}
	var out []crateGroup
	for _, d := range deps {
		k := d.crate + "\x00" + d.req
		i, ok := idx[k]
		if !ok {
			i = len(out)
			idx[k] = i
			out = append(out, crateGroup{crate: d.crate, req: d.req})
		}
		w := d.manifest + " [" + d.table + "]"
		if !slices.Contains(out[i].where, w) {
			out[i].where = append(out[i].where, w)
		}
	}
	return out
}

func checkCrate(ctx context.Context, reg *registry, g crateGroup) result {
	r := result{eco: "cargo", name: g.crate, used: g.req, status: statusOK}
	req, err := reqVersion(g.req)
	if err != nil {
		return fail(r, err)
	}
	vs, err := reg.crateVersions(ctx, g.crate)
	if err != nil {
		return fail(r, err)
	}
	latest, ok := latestStable(vs)
	if !ok {
		r.latest = "(no stable release)"
		return r
	}
	r.latest = latest.String()
	if lineOf(req).less(lineOf(latest)) {
		r.status = statusBehind
		r.note = strings.Join(g.where, ", ")
	}
	return r
}

// ---------------------------------------------------------------- helpers

func fail(r result, err error) result {
	r.status = statusError
	r.note = join(r.note, err.Error())
	return r
}

func join(a, b string) string {
	if a == "" {
		return b
	}
	return a + "; " + b
}
