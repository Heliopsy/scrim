// SPDX-License-Identifier: AGPL-3.0-only

//go:build !unix

package run

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
)

// supervise starts cmd and waits for it. Signals are not forwarded on this
// platform.
func supervise(cmd *exec.Cmd, _ <-chan os.Signal, _ io.Writer, started func() error) error {
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("%w: starting %s failed: %w", ErrRefused, cmd.Args[0], err)
	}
	if err := started(); err != nil {
		_ = cmd.Wait()
		return err
	}
	err := cmd.Wait()
	var xe *exec.ExitError
	if errors.As(err, &xe) {
		return &ExitError{Code: xe.ExitCode()}
	}
	return err
}
