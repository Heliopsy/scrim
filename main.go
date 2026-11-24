// SPDX-License-Identifier: AGPL-3.0-only

// Command scrim keeps secret values away from LLM providers while AI agents
// keep working. See README.md.
package main

import (
	"context"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"github.com/heliopsy/scrim/internal/cli"
	"github.com/heliopsy/scrim/internal/credhelper"
	"github.com/heliopsy/scrim/internal/fsview"
)

func main() {
	windowsHome()
	// scrim run starts scrim again to set up the session filesystem view;
	// that start never reaches the command line.
	fsview.Main()
	// Linked into a session's bin directory as docker-credential-scrim, scrim
	// is the docker credential helper "scrim" (tasks 10a.9).
	if strings.TrimSuffix(strings.ToLower(filepath.Base(os.Args[0])), ".exe") == credhelper.DockerBinary {
		os.Exit(credhelper.Main(append([]string{"docker"}, os.Args[1:]...), os.Environ(), os.Stdin, os.Stdout, os.Stderr))
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := cli.Main(ctx, os.Args[1:])
	stop()
	os.Exit(code)
}

// windowsHome gives scrim a HOME on Windows, where it is usually unset:
// %USERPROFILE%, so the per-user paths documented as ~/.config/scrim and
// ~/.local/state/scrim resolve under the profile, which only the user,
// SYSTEM and Administrators can reach. A HOME that is already set is kept.
func windowsHome() {
	if runtime.GOOS != "windows" || os.Getenv("HOME") != "" {
		return
	}
	if p := os.Getenv("USERPROFILE"); p != "" {
		_ = os.Setenv("HOME", p)
	}
}
