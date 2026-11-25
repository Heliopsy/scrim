// SPDX-License-Identifier: AGPL-3.0-only

// Package testpodman runs podman for tests so their containers cannot
// outlive them unseen.
//
// testhome points HOME and the XDG directories at a temporary directory that
// it deletes when the tests end. A podman started with that environment keeps
// its container store there, so a later `podman rm` finds nothing and the
// containers keep running, invisible to the user's `podman ps`. Command runs
// podman with the environment the test binary started with, captured before
// TestMain changes it, so containers live in the user's own store. Every
// container a test starts is labelled [Label] and killed after [MaxLifetime]
// even when the test binary dies before its cleanup runs.
package testpodman

import (
	"context"
	"os"
	"os/exec"
	"strconv"
	"time"
)

// Label marks every container a test starts:
// `podman ps -a --filter label=io.heliopsy.scrim-test` lists them.
const Label = "io.heliopsy.scrim-test"

// MaxLifetime is how long a test container may run before podman kills it.
const MaxLifetime = 2 * time.Hour

// env is the environment the test binary started with. Package variables are
// initialised before TestMain runs, so testhome has not changed it yet.
var env = os.Environ()

// Command is exec.Command("podman", args...) with the original environment.
// A `run` gets the label and the maximum lifetime.
func Command(args ...string) *exec.Cmd {
	return CommandContext(context.Background(), args...)
}

// CommandContext is Command with a context.
func CommandContext(ctx context.Context, args ...string) *exec.Cmd {
	c := exec.CommandContext(ctx, "podman", withRunFlags(args)...) // #nosec G204 -- test helper, fixed binary
	c.Env = env
	return c
}

func withRunFlags(args []string) []string {
	if len(args) == 0 || args[0] != "run" {
		return args
	}
	out := []string{"run", "--label", Label + "=1", "--timeout", strconv.Itoa(int(MaxLifetime / time.Second))}
	return append(out, args[1:]...)
}
