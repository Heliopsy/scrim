// SPDX-License-Identifier: AGPL-3.0-only

// Package testhome keeps tests away from the user's own scrim files. scrim's
// local profile keeps state, keys, the CA and sockets under HOME and the XDG
// directories; a test that builds an App or a daemon must never read or
// write the real ones.
//
// Use it from TestMain in every package whose tests build an App or daemon:
//
//	func TestMain(m *testing.M) { os.Exit(testhome.Run(m)) }
package testhome

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Vars are the variables pointed at a temporary directory. On Windows they
// include USERPROFILE (what os.UserHomeDir reads there) and LOCALAPPDATA
// (where scrim unpacks its data plane).
var Vars = vars()

func vars() []string {
	v := []string{"HOME", "XDG_CONFIG_HOME", "XDG_STATE_HOME", "XDG_DATA_HOME", "XDG_RUNTIME_DIR", "XDG_CACHE_HOME"}
	if runtime.GOOS == "windows" {
		v = append(v, "USERPROFILE", "LOCALAPPDATA", "APPDATA")
	}
	return v
}

// keepGo pins the Go caches to where they are now, before the variables
// they default from (LOCALAPPDATA, USERPROFILE on Windows) move, so tests
// that run the go command reuse them.
func keepGo() {
	if runtime.GOOS != "windows" {
		return
	}
	if os.Getenv("GOCACHE") == "" {
		if d, err := os.UserCacheDir(); err == nil {
			_ = os.Setenv("GOCACHE", filepath.Join(d, "go-build"))
		}
	}
	if os.Getenv("GOPATH") == "" {
		if h, err := os.UserHomeDir(); err == nil {
			_ = os.Setenv("GOPATH", filepath.Join(h, "go"))
		}
	}
}

// Run points every variable in Vars at a fresh temporary directory, checks
// none of them still reaches the real home, runs the tests and removes the
// directory. It returns the exit code for os.Exit.
func Run(m *testing.M) int {
	real, _ := os.UserHomeDir()
	keepGo()
	dir, err := os.MkdirTemp("", "scrim-test-home-")
	if err != nil {
		fmt.Fprintln(os.Stderr, "testhome:", err)
		return 2
	}
	defer func() { _ = os.RemoveAll(dir) }()
	for _, k := range Vars {
		if err := os.Setenv(k, dir); err != nil {
			fmt.Fprintln(os.Stderr, "testhome:", err)
			return 2
		}
	}
	if err := Check(real); err != nil {
		fmt.Fprintln(os.Stderr, "testhome:", err)
		return 2
	}
	return m.Run()
}

// Check fails when any variable in Vars is unset or points into realHome.
func Check(realHome string) error {
	for _, k := range Vars {
		v := os.Getenv(k)
		if v == "" {
			return fmt.Errorf("%s is not set; tests must not fall back to the real home", k)
		}
		if realHome != "" && within(v, realHome) {
			return fmt.Errorf("%s=%s is inside the real home %s", k, v, realHome)
		}
	}
	return nil
}

// within reports whether p is inside dir. The temporary directory never
// counts: on Windows it is itself inside the profile.
func within(p, dir string) bool {
	if tmp := os.TempDir(); tmp != "" && tmp != dir && inside(p, tmp) && !inside(tmp, p) {
		return false
	}
	return inside(p, dir)
}

func inside(p, dir string) bool {
	rel, err := filepath.Rel(dir, p)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// Environ returns a config environment for one test: every variable in
// Vars pointed at t.TempDir(), plus extra.
func Environ(t testing.TB, extra ...string) []string {
	t.Helper()
	dir := t.TempDir()
	out := make([]string, 0, len(Vars)+len(extra))
	for _, k := range Vars {
		out = append(out, k+"="+dir)
	}
	return append(out, extra...)
}
