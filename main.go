// SPDX-License-Identifier: AGPL-3.0-only

// Command scrim keeps secret values away from LLM providers while AI agents
// keep working. See README.md.
package main

import (
	"context"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/heliopsy/scrim/internal/cli"
	"github.com/heliopsy/scrim/internal/credhelper"
	"github.com/heliopsy/scrim/internal/fsview"
)

func main() {
	// scrim run starts scrim again to set up the session filesystem view;
	// that start never reaches the command line.
	fsview.Main()
	// Linked into a session's bin directory as docker-credential-scrim, scrim
	// is the docker credential helper "scrim" (tasks 10a.9).
	if filepath.Base(os.Args[0]) == credhelper.DockerBinary {
		os.Exit(credhelper.Main(append([]string{"docker"}, os.Args[1:]...), os.Environ(), os.Stdin, os.Stdout, os.Stderr))
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := cli.Main(ctx, os.Args[1:])
	stop()
	os.Exit(code)
}
