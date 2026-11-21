package main

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestBreakingLine(t *testing.T) {
	cases := []struct {
		req, latest string
		behind      bool
	}{
		{"0.13", "0.14.10", true},
		{"0.12", "0.13.0", true},
		{"0.14", "0.14.10", false},
		{"^0.14.2", "0.14.10", false},
		{"1", "1.99.0", false},
		{"1.1", "2.0.0", true},
		{"8", "9.1.3", true},
		{"0.0.3", "0.0.4", true},
		{"~1.2", "1.9.0", false},
		{"=0.9.1", "0.10.0", true},
	}
	for _, c := range cases {
		req, err := reqVersion(c.req)
		if err != nil {
			t.Fatalf("%s: %v", c.req, err)
		}
		latest, ok := parseVersion(c.latest)
		if !ok {
			t.Fatalf("parse %s", c.latest)
		}
		if got := lineOf(req).less(lineOf(latest)); got != c.behind {
			t.Errorf("%s against %s: behind = %v, want %v", c.req, c.latest, got, c.behind)
		}
	}
	for _, bad := range []string{"*", "1.*", "", "<2", ">=0.5, <0.7", ">=1"} {
		if _, err := reqVersion(bad); err == nil {
			t.Errorf("reqVersion(%q) accepted", bad)
		}
	}
}

func TestLatestStableSkipsPreReleases(t *testing.T) {
	v, ok := latestStable([]string{"v1.2.0", "v1.10.0", "v2.0.0-rc.1", "v1.9.9", "garbage"})
	if !ok || v.String() != "1.10.0" {
		t.Fatalf("got %v %v", v, ok)
	}
	if _, ok := latestStable([]string{"v1.0.0-beta"}); ok {
		t.Fatal("pre-release counted as stable")
	}
}

func TestParseManifest(t *testing.T) {
	src := `
[package]
name = "x" # not a dependency
version = "1.0.0"

[workspace.dependencies]
tokio = "1.54.1"
local = { path = "crates/local" }

[dependencies]
serde = { version = "1", features = ["derive"] } # comment
tokio.workspace = true
md5 = { package = "md-5", version = "0.10" }
hyper = { version = "1", features = [
  "client", # one
  "server",
] }
"quoted" = "0.2"
dotted.version = "0.3"
dotted.default-features = false
gitdep = { git = "https://example.invalid/x" }

[target.'cfg(unix)'.dependencies]
rustix = "1"

[dev-dependencies.rcgen]
version = "0.13"
features = ["pem"]

[build-dependencies]
cc = "1.2"

[features]
default = ["std"]

[[bench]]
name = "b"
`
	deps, err := parseManifest("Cargo.toml", []byte(src))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, d := range deps {
		switch {
		case d.workspace:
			got[d.key] = "workspace"
		case d.git != "":
			got[d.key] = "git"
		case d.req == "":
			got[d.key] = "path"
		default:
			got[d.crate] = d.req
		}
	}
	want := map[string]string{
		"tokio": "workspace", "local": "path", "serde": "1", "md-5": "0.10", "hyper": "1",
		"quoted": "0.2", "dotted": "0.3", "gitdep": "git", "rustix": "1", "rcgen": "0.13", "cc": "1.2",
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
	// tokio appears twice: once in [workspace.dependencies] with a version.
	n := 0
	for _, d := range deps {
		if d.key == "tokio" && d.req == "1.54.1" && d.table == "workspace.dependencies" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("workspace tokio entries = %d, want 1", n)
	}
	if len(deps) != len(want)+1 {
		t.Errorf("got %d entries, want %d: %+v", len(deps), len(want)+1, deps)
	}
}

func TestParseManifestRefusesWhatItCannotRead(t *testing.T) {
	for _, src := range []string{
		"[dependencies]\nfoo\n",
		"[dependencies]\nfoo = 1\n",
		"[dependencies]\nfoo = { version = \"1\"\n",
	} {
		if _, err := parseManifest("Cargo.toml", []byte(src)); err == nil {
			t.Errorf("accepted %q", src)
		}
	}
}

func TestPaths(t *testing.T) {
	for name, want := range map[string]string{"a": "1/a", "ab": "2/ab", "abc": "3/a/abc", "Rcgen": "rc/ge/rcgen", "md-5": "md/-5/md-5"} {
		if got := crateIndexPath(name); got != want {
			t.Errorf("crateIndexPath(%s) = %s, want %s", name, got, want)
		}
	}
	if got := escapeModulePath("github.com/BurntSushi/toml"); got != "github.com/!burnt!sushi/toml" {
		t.Errorf("escape = %s", got)
	}
	for path, want := range map[string]string{
		"github.com/jackc/pgx/v5": "github.com/jackc/pgx/v6",
		"golang.org/x/sys":        "golang.org/x/sys/v2",
		"gopkg.in/yaml.v3":        "gopkg.in/yaml.v4",
		"example.com/m/v1":        "example.com/m/v1/v2",
	} {
		_, major, pathFor := splitMajor(path)
		if got := pathFor(major + 1); got != want {
			t.Errorf("next major of %s = %s, want %s", path, got, want)
		}
	}
}

func TestDeprecation(t *testing.T) {
	if got := deprecationOf("// Deprecated: use cel.dev/cel-go.\nmodule github.com/google/cel-go\n"); got != "use cel.dev/cel-go." {
		t.Errorf("got %q", got)
	}
	if got := deprecationOf("module example.com/m // Deprecated: gone\n"); got != "gone" {
		t.Errorf("got %q", got)
	}
	if got := deprecationOf("// Deprecated: not the module comment\n\nmodule example.com/m\n"); got != "" {
		t.Errorf("got %q", got)
	}
}

func TestParseIgnore(t *testing.T) {
	l, err := parseIgnore("f", []byte("# c\ncargo rcgen 2027-01-31 waiting for x509-parser\n\ngo example.com/m 2026-01-01 reason here\n"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	if e := l.find("cargo", "rcgen"); e == nil || e.expired(now) || e.reason != "waiting for x509-parser" {
		t.Errorf("rcgen entry: %+v", e)
	}
	if e := l.find("go", "example.com/m"); e == nil || !e.expired(now) {
		t.Errorf("go entry should have expired: %+v", e)
	}
	// The expiry day itself is still valid.
	e := l.find("cargo", "rcgen")
	if e.expired(time.Date(2027, 1, 31, 23, 0, 0, 0, time.UTC)) || !e.expired(time.Date(2027, 2, 1, 0, 0, 0, 0, time.UTC)) {
		t.Error("expiry is not end of day UTC")
	}
	for _, bad := range []string{"cargo rcgen 2027-01-31\n", "npm x 2027-01-01 r\n", "cargo x 31.01.2027 r\n", "cargo x 2027-01-01 a\ncargo x 2027-01-01 b\n"} {
		if _, err := parseIgnore("f", []byte(bad)); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestToolModulesCountAsDirect(t *testing.T) {
	mods, err := parseGoModJSON([]byte(`{"Require":[
		{"Path":"example.com/direct","Version":"v1.0.0"},
		{"Path":"example.com/indirect","Version":"v1.0.0","Indirect":true},
		{"Path":"example.com/tools","Version":"v1.0.0","Indirect":true},
		{"Path":"example.com/tools/cmd/gen","Version":"v0.1.0","Indirect":true}],
		"Tool":[{"Path":"example.com/tools/cmd/gen"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, m := range mods {
		got = append(got, m.path)
	}
	if strings.Join(got, ",") != "example.com/direct,example.com/tools/cmd/gen" {
		t.Errorf("got %v", got)
	}
}

// TestRun runs the gate against fake registries: a Go module with a newer
// major path, a deprecated one, a current one, a crate a 0.x minor behind and
// a current crate, then the same with ignore entries, one of them expired.
func TestRun(t *testing.T) {
	proxy := map[string]string{
		"/example.com/old/@v/list":             "v1.4.0\nv1.5.0\nv2.0.0+incompatible\n",
		"/example.com/old/v2/@v/list":          "v2.0.0\nv2.1.0\n",
		"/example.com/old/v3/@v/list":          "v3.0.0-rc.1\n",
		"/example.com/old/@v/v1.5.0.mod":       "module example.com/old\n",
		"/example.com/inc/@v/list":             "v1.0.0\nv3.0.0+incompatible\n",
		"/example.com/inc/@v/v1.0.0.mod":       "module example.com/inc\n",
		"/example.com/renamed/@v/list":         "v0.9.0\n",
		"/example.com/renamed/@v/v0.9.0.mod":   "// Deprecated: use example.com/new.\nmodule example.com/renamed\n",
		"/example.com/!fresh/v5/@v/list":       "v5.0.0\nv5.2.0\n",
		"/example.com/!fresh/v5/@v/v5.2.0.mod": "module example.com/Fresh/v5\n",
	}
	index := map[string]string{
		"/rc/ge/rcgen": `{"name":"rcgen","vers":"0.13.2","yanked":false}` + "\n" +
			`{"name":"rcgen","vers":"0.14.0","yanked":false}` + "\n" +
			`{"name":"rcgen","vers":"0.15.0","yanked":true}` + "\n" +
			`{"name":"rcgen","vers":"0.16.0-alpha","yanked":false}` + "\n",
		"/to/ki/tokio": `{"name":"tokio","vers":"1.54.1","yanked":false}` + "\n",
	}
	serve := func(m map[string]string) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, ok := m[r.URL.Path]
			if !ok {
				http.NotFound(w, r)
				return
			}
			_, _ = w.Write([]byte(body))
		}))
	}
	ps, is := serve(proxy), serve(index)
	defer ps.Close()
	defer is.Close()

	dir := t.TempDir()
	write := func(name, s string) {
		t.Helper()
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("go.mod", "module example.com/me\n\ngo 1.24\n\nrequire (\n\texample.com/old v1.4.0\n\texample.com/renamed v0.9.0\n\texample.com/Fresh/v5 v5.2.0\n\texample.com/inc v1.0.0\n\texample.com/ind v1.0.0 // indirect\n)\n")
	write("dp/Cargo.toml", "[workspace.dependencies]\ntokio = \"1.54.1\"\n")
	write("dp/crates/a/Cargo.toml", "[dependencies]\ntokio.workspace = true\n[dev-dependencies]\nrcgen = \"0.13\"\n")
	write("dp/target/debug/Cargo.toml", "[dependencies]\nignored = \"0.1\"\n")

	now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	opts := options{
		goMod: filepath.Join(dir, "go.mod"), cargoRoot: filepath.Join(dir, "dp"), ignore: filepath.Join(dir, "none"),
		goProxy: ps.URL, cratesIndex: is.URL, jobs: 4, now: func() time.Time { return now },
	}
	var out bytes.Buffer
	code, err := run(context.Background(), opts, &out)
	if err != nil {
		t.Fatal(err)
	}
	report := out.String()
	if code != 1 {
		t.Fatalf("exit %d, want 1:\n%s", code, report)
	}
	for _, want := range [][]string{
		{"BEHIND", "go", "example.com/old", "v1.4.0", "example.com/old/v2@v2.1.0"},
		{"DEPRECATED", "go", "example.com/renamed", "v0.9.0", "v0.9.0"},
		{"ok", "go", "example.com/Fresh/v5", "v5.2.0", "v5.2.0"},
		{"ok", "go", "example.com/inc", "v1.0.0", "v1.0.0"},
		{"BEHIND", "cargo", "rcgen", "0.13", "0.14.0"},
		{"ok", "cargo", "tokio", "1.54.1", "1.54.1"},
	} {
		if !hasRow(report, want...) {
			t.Errorf("report lacks row %v:\n%s", want, report)
		}
	}
	if !strings.Contains(report, "3 of 6 checked dependencies fail") {
		t.Errorf("summary missing:\n%s", report)
	}
	for _, unwanted := range []string{"example.com/ind", "ignored", "v3.0.0", "0.15.0"} {
		if strings.Contains(report, unwanted) {
			t.Errorf("report has %q:\n%s", unwanted, report)
		}
	}

	// Ignore entries make the gate pass, until one expires.
	write("ignore", "go example.com/old 2026-12-31 v2 drops X\ngo example.com/renamed 2026-12-31 move later\ncargo rcgen 2026-11-21 needs Y\ncargo tokio 2027-01-01 stale entry\n")
	opts.ignore = filepath.Join(dir, "ignore")
	out.Reset()
	if code, err = run(context.Background(), opts, &out); err != nil || code != 0 {
		t.Fatalf("with ignores: exit %d, %v:\n%s", code, err, out.String())
	}
	if !hasRow(out.String(), "ignored", "cargo", "rcgen") || !strings.Contains(out.String(), "warning: ") || !strings.Contains(out.String(), "cargo tokio matches no dependency") {
		t.Errorf("ignored rows or stale warning missing:\n%s", out.String())
	}
	now = now.Add(24 * time.Hour)
	out.Reset()
	if code, _ = run(context.Background(), opts, &out); code != 1 || !strings.Contains(out.String(), "expired on 2026-11-21") {
		t.Fatalf("expired entry: exit %d:\n%s", code, out.String())
	}

	// A registry that fails is a failure, never a pass.
	retryBase = time.Millisecond
	t.Cleanup(func() { retryBase = time.Second })
	is.Close()
	opts.goMod, opts.ignore = "", filepath.Join(dir, "none")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out.Reset()
	if code, _ = run(ctx, opts, &out); code != 1 || !strings.Contains(out.String(), "ERROR") {
		t.Fatalf("registry down: exit %d:\n%s", code, out.String())
	}
}

// hasRow reports whether a report line starts with the given fields.
func hasRow(report string, fields ...string) bool {
	for _, line := range strings.Split(report, "\n") {
		f := strings.Fields(line)
		if len(f) >= len(fields) && slices.Equal(f[:len(fields)], fields) {
			return true
		}
	}
	return false
}
