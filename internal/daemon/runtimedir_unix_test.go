// SPDX-License-Identifier: AGPL-3.0-only

//go:build !windows

package daemon

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/secret"
)

// Without $XDG_RUNTIME_DIR the daemon info file sits next to the admin
// socket in this user's directory under the temporary directory.
func TestInfoPathWithoutXDGRuntimeDir(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("XDG_RUNTIME_DIR", "")
	t.Setenv("TMPDIR", tmp)
	want := filepath.Join(tmp, fmt.Sprintf("scrim-%d", os.Getuid()), "daemon.json")
	for _, addr := range []string{"", "http://127.0.0.1:9000"} {
		if got := InfoPath(addr); got != want {
			t.Fatalf("InfoPath(%q) = %s, want %s", addr, got, want)
		}
	}
}

// Another user's pre-created runtime directory, with a socket listening in
// it, is refused: the client neither talks to it nor treats it as "no
// daemon" (which would start one there).
func TestConnectRefusesALooseRuntimeDir(t *testing.T) {
	xdg := t.TempDir()
	t.Setenv("XDG_RUNTIME_DIR", xdg)
	dir := filepath.Join(xdg, "scrim")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("unix", filepath.Join(dir, "admin.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Build(config.Options{Registry: config.Default, Environ: []string{"HOME=" + t.TempDir()},
		ConfigPaths: []string{writeEmptyConfig(t)}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = Connect(t.Context(), cfg)
	if err == nil || errors.Is(err, ErrNotRunning) || !strings.Contains(err.Error(), dir) {
		t.Fatalf("Connect = %v, want a refusal naming %s", err, dir)
	}
	// The daemon refuses to listen there as well.
	if _, err := listenAdmin("", secret.Value{}); err == nil || !strings.Contains(err.Error(), dir) {
		t.Fatalf("listenAdmin = %v, want a refusal naming %s", err, dir)
	}
}
