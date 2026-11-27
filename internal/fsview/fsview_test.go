// SPDX-License-Identifier: AGPL-3.0-only

//go:build unix

// The views mirror a Unix home or use user and mount namespaces; Windows has
// neither, and fsview_windows_test.go covers what it does there.

package fsview

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

func TestMain(m *testing.M) {
	Main()
	if os.Getenv(envNetChild) != "" {
		os.Exit(netChild())
	}
	os.Exit(m.Run())
}

func write(t *testing.T, path, data string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
}

var (
	yes = func() Availability { return Availability{Namespace: true} }
	no  = func() Availability { return Availability{Reason: "none here"} }
)

func TestResolve(t *testing.T) {
	for _, c := range []struct {
		req      string
		ns       bool
		mode     string
		fallback bool
		err      bool
	}{
		{"", false, ModeOff, false, false},
		{ModeOff, true, ModeOff, false, false},
		{ModeHome, true, ModeHome, false, false},
		{ModeAuto, true, ModeNamespace, false, false},
		{ModeAuto, false, ModeHome, true, false},
		{ModeNamespace, true, ModeNamespace, false, false},
		{ModeNamespace, false, "", false, true},
		{"bogus", true, "", false, true},
	} {
		mode, fb, err := Resolve(c.req, Availability{Namespace: c.ns, Reason: "r"})
		if mode != c.mode || (fb != "") != c.fallback || (err != nil) != c.err {
			t.Errorf("Resolve(%q, %v) = %q, %q, %v", c.req, c.ns, mode, fb, err)
		}
	}
}

// home builds a home directory and a session directory with a generated
// file.
func home(t *testing.T) (dir, sess, gen string) {
	dir, sess = t.TempDir(), t.TempDir()
	write(t, filepath.Join(dir, ".aws/credentials"), "real")
	write(t, filepath.Join(dir, ".aws/config"), "real config")
	write(t, filepath.Join(dir, ".ssh/id_ed25519"), "key")
	write(t, filepath.Join(dir, ".ssh/id_ed25519.pub"), "pub")
	write(t, filepath.Join(dir, ".ssh/known_hosts"), "hosts")
	write(t, filepath.Join(dir, ".netrc"), "real netrc")
	write(t, filepath.Join(dir, "work/main.go"), "package main")
	if err := os.MkdirAll(filepath.Join(dir, ".config/gcloud"), 0o700); err != nil {
		t.Fatal(err)
	}
	gen = filepath.Join(sess, "profiles/aws/credentials")
	write(t, gen, "placeholder")
	return dir, sess, gen
}

func byHome(es []Entry) map[string]Entry {
	m := map[string]Entry{}
	for _, e := range es {
		m[e.Home] = e
	}
	return m
}

func TestBuildNamespaceEntries(t *testing.T) {
	dir, sess, gen := home(t)
	p, err := Build(Input{Mode: ModeAuto, Available: yes, Home: dir, PasswdHome: dir, SessionDir: sess, Hide: DefaultHide,
		Paths: []Path{
			{Home: ".netrc", Origin: "pip"},                               // hidden
			{Home: ".aws/credentials", Origin: "aws-hide"},                // hidden first ...
			{Home: ".aws/credentials", Source: gen, Origin: "aws"},        // ... a replacement wins
			{Home: ".kube/config", Source: gen, Origin: "kubectl"},        // no real file: nothing to mount
			{Home: ".config/gcloud", Origin: "gcloud"},                    // a directory
			{Home: ".aws/config", Source: filepath.Dir(gen), Origin: "x"}, // a directory over a file: hidden
			{Home: ".docker/config.json", Origin: "docker"},               // absent
		}})
	if err != nil {
		t.Fatal(err)
	}
	if p.Mode != ModeNamespace || !p.Active() || len(p.Homes) != 1 {
		t.Fatalf("plan = %+v", p)
	}
	m := byHome(p.Entries)
	want := map[string]struct {
		src string
		dir bool
	}{
		".netrc": {"", false}, ".aws/credentials": {gen, false}, ".config/gcloud": {"", true},
		".aws/config": {"", false}, ".ssh/id_ed25519": {"", false},
	}
	if len(m) != len(want) {
		t.Errorf("entries %v, want %v", m, want)
	}
	for h, w := range want {
		e, ok := m[h]
		if !ok || e.Source != w.src || e.Dir != w.dir || e.Target != filepath.Join(dir, h) {
			t.Errorf("%s = %+v (present %v), want source %q dir %v", h, e, ok, w.src, w.dir)
		}
	}
}

func TestBuildPasswdHomeCovered(t *testing.T) {
	dir, sess, gen := home(t)
	other := t.TempDir()
	p, err := Build(Input{Mode: ModeNamespace, Available: yes, Home: other, PasswdHome: dir, SessionDir: sess,
		Paths: []Path{{Home: ".aws/credentials", Source: gen, Origin: "aws"}}})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(p.Homes, []string{other, dir}) || len(p.Entries) != 1 || p.Entries[0].Target != filepath.Join(dir, ".aws/credentials") {
		t.Fatalf("plan = %+v", p)
	}
}

func TestBuildProbesOnlyWhenNeeded(t *testing.T) {
	sess := t.TempDir()
	called := false
	p, err := Build(Input{Mode: ModeAuto, Home: t.TempDir(), PasswdHome: t.TempDir(), SessionDir: sess, Hide: DefaultHide,
		Available: func() Availability { called = true; return Availability{} }})
	if err != nil {
		t.Fatal(err)
	}
	if called || p.Active() {
		t.Errorf("an empty home was probed (%v) or got a view: %+v", called, p)
	}
	// run.fs-view namespace always checks, and refuses without one.
	if _, err := Build(Input{Mode: ModeNamespace, Home: t.TempDir(), SessionDir: sess, Available: no}); err == nil || !strings.Contains(err.Error(), "none here") {
		t.Errorf("namespace without namespaces: %v", err)
	}
}

func TestBuildRejectsPaths(t *testing.T) {
	for _, bad := range []string{"../etc/passwd", "/etc/passwd", ".ssh/../../x", "", "*", "["} {
		if _, err := Build(Input{Mode: ModeHome, Home: t.TempDir(), SessionDir: t.TempDir(), Hide: []string{bad}}); err == nil {
			t.Errorf("hide pattern %q accepted", bad)
		}
		if _, err := Build(Input{Mode: ModeHome, Home: t.TempDir(), SessionDir: t.TempDir(), Paths: []Path{{Home: bad}}}); err == nil {
			t.Errorf("profile path %q accepted", bad)
		}
	}
	if _, err := Build(Input{Mode: ModeHome, Home: "relative", SessionDir: t.TempDir()}); err == nil {
		t.Error("relative HOME accepted")
	}
}

func TestHomeMirror(t *testing.T) {
	dir, sess, gen := home(t)
	p, err := Build(Input{Mode: ModeAuto, Available: no, Home: dir, SessionDir: sess, Hide: DefaultHide,
		Paths: []Path{
			{Home: ".aws/credentials", Source: gen, Origin: "aws"},
			{Home: ".kube/config", Source: gen, Origin: "kubectl"}, // shown although the real one is absent
			{Home: ".netrc", Origin: "pip"},
		}})
	if err != nil {
		t.Fatal(err)
	}
	if p.Mode != ModeHome || p.Fallback != "none here" || p.SessionHome == "" {
		t.Fatalf("plan = %+v", p)
	}
	if err := p.Prepare(); err != nil {
		t.Fatal(err)
	}
	sh := p.SessionHome
	read := func(rel string) string {
		b, err := os.ReadFile(filepath.Join(sh, rel))
		if err != nil {
			return "ERR"
		}
		return string(b)
	}
	for rel, want := range map[string]string{
		".aws/credentials": "placeholder", ".kube/config": "placeholder", ".aws/config": "real config",
		".ssh/id_ed25519": "ERR", ".ssh/id_ed25519.pub": "pub", ".ssh/known_hosts": "hosts", ".netrc": "ERR",
		"work/main.go": "package main",
	} {
		if got := read(rel); got != want {
			t.Errorf("session home %s = %q, want %q", rel, got, want)
		}
	}
	// Uncovered entries are links into the real home, so writes land there.
	if l, err := os.Readlink(filepath.Join(sh, "work")); err != nil || l != filepath.Join(dir, "work") {
		t.Errorf("work is %q, %v; want a link to the real directory", l, err)
	}
	if st, err := os.Lstat(filepath.Join(sh, ".ssh")); err != nil || !st.IsDir() {
		t.Errorf(".ssh should be a real directory in the mirror: %v", err)
	}

	vars := p.Vars([]string{"XDG_CONFIG_HOME=" + filepath.Join(dir, ".config"), "XDG_CACHE_HOME=/var/cache/u", "HOME=" + dir})
	got := map[string]string{}
	for _, v := range vars {
		got[v.Name] = v.Value
	}
	if got["HOME"] != sh || got["XDG_CONFIG_HOME"] != filepath.Join(sh, ".config") {
		t.Errorf("vars = %v", got)
	}
	if _, ok := got["XDG_CACHE_HOME"]; ok {
		t.Error("XDG_CACHE_HOME outside the home was moved")
	}
}

func TestPrepareNamespaceHidden(t *testing.T) {
	dir, sess, _ := home(t)
	p, err := Build(Input{Mode: ModeNamespace, Available: yes, Home: dir, PasswdHome: dir, SessionDir: sess, Hide: DefaultHide})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Prepare(); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{hiddenFile, hiddenDir} {
		st, err := os.Stat(filepath.Join(sess, "fsview", n))
		if err != nil || st.Mode().Perm() != 0 {
			t.Errorf("%s: %v, mode %v; want mode 0", n, err, st.Mode())
		}
	}
	if err := os.RemoveAll(sess); err != nil {
		t.Errorf("the session directory cannot be removed: %v", err)
	}
}

func TestGapsAndProbe(t *testing.T) {
	if g := Gaps(ModeHome); len(g) == 0 || !strings.Contains(strings.Join(g, " "), "password database") {
		t.Errorf("home gaps = %v", g)
	}
	a := Probe(context.Background(), os.Args[0])
	switch runtime.GOOS {
	case "linux":
		t.Logf("namespace view here: %+v", a)
		if os.Getenv("SCRIM_TEST_REQUIRE_USERNS") == "1" && !a.Namespace {
			t.Fatalf("user namespaces required: %s", a.Reason)
		}
		n := ProbeNetwork(context.Background(), os.Args[0])
		t.Logf("network namespace here: %+v", n)
		if os.Getenv("SCRIM_TEST_REQUIRE_USERNS") == "1" && !n.Namespace {
			t.Fatalf("network namespaces required: %s", n.Reason)
		}
	default:
		if a.Namespace || !strings.Contains(a.Reason, runtime.GOOS) {
			t.Errorf("probe on %s = %+v", runtime.GOOS, a)
		}
		if n := ProbeNetwork(context.Background(), os.Args[0]); n.Namespace {
			t.Errorf("network probe on %s = %+v", runtime.GOOS, n)
		}
	}
}
