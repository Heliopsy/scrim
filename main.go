// SPDX-License-Identifier: AGPL-3.0-only

// Command scrim keeps secret values away from LLM providers while AI agents
// keep working. See README.md.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/heliopsy/scrim/internal/cli"
	"github.com/heliopsy/scrim/internal/fsview"
)

func main() {
	// scrim run starts scrim again to set up the session filesystem view;
	// that start never reaches the command line.
	fsview.Main()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := cli.Main(ctx, os.Args[1:])
	stop()
	os.Exit(code)
}
