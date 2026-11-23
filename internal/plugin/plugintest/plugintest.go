// SPDX-License-Identifier: AGPL-3.0-only

// Package plugintest builds plugin binaries for tests.
package plugintest

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

var (
	mu    sync.Mutex
	built = map[string]string{}
	dir   string
)

// Build compiles the main package at pkg (a module-relative import path
// such as "./examples/plugins/dirstore") once per test process and returns
// the binary's path. The directory it lands in is private to the user, so
// the binary passes the plugin ownership checks.
func Build(t testing.TB, pkg string) string {
	t.Helper()
	mu.Lock()
	defer mu.Unlock()
	if p, ok := built[pkg]; ok {
		return p
	}
	root := moduleRoot(t)
	if dir == "" {
		d, err := os.MkdirTemp("", "scrim-plugintest-")
		if err != nil {
			t.Fatal(err)
		}
		dir = d
	}
	out := filepath.Join(dir, filepath.Base(pkg))
	cmd := exec.Command("go", "build", "-o", out, pkg) //nolint:gosec // test helper, fixed package paths
	cmd.Dir = root
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("building %s: %v\n%s", pkg, err, b)
	}
	// Whatever the umask, the plugin must be writable by its owner only.
	if err := os.Chmod(out, 0o755); err != nil { //nolint:gosec // an executable
		t.Fatal(err)
	}
	built[pkg] = out
	return out
}

// Cleanup removes every binary built; call it from TestMain.
func Cleanup() {
	mu.Lock()
	defer mu.Unlock()
	if dir != "" {
		_ = os.RemoveAll(dir)
	}
}

func moduleRoot(t testing.TB) string {
	b, err := exec.Command("go", "env", "GOMOD").Output()
	if err != nil {
		t.Fatalf("go env GOMOD: %v", err)
	}
	mod := strings.TrimSpace(string(b))
	if mod == "" || mod == os.DevNull {
		t.Fatal("not inside the scrim module")
	}
	return filepath.Dir(mod)
}
