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
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := cli.Main(ctx, os.Args[1:])
	stop()
	os.Exit(code)
}
