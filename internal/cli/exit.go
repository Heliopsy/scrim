// SPDX-License-Identifier: AGPL-3.0-only

package cli

import (
	"errors"
	"fmt"
)

// Exit codes beyond 0 (success) and 1 (error). The agent-facing commands use
// them so a script can tell outcomes apart without parsing output.
const (
	ExitError    = 1
	ExitDenied   = 3 // denied by policy, or the caller is not allowed
	ExitPending  = 4 // waiting for a human: approval or ask still open
	ExitDeclined = 5 // the human declined, or the approval or ask expired
)

// ExitCodeError ends a command with a specific exit code. With a nil Err
// nothing is printed: the command already wrote its result.
type ExitCodeError struct {
	Code int
	Err  error
}

func (e *ExitCodeError) Error() string {
	if e.Err == nil {
		return fmt.Sprintf("exit status %d", e.Code)
	}
	return e.Err.Error()
}

func (e *ExitCodeError) Unwrap() error { return e.Err }

// exitCode returns the exit code for err and the error to print, nil when
// nothing should be printed.
func exitCode(err error) (int, error) {
	var xe *ExitCodeError
	if errors.As(err, &xe) {
		return xe.Code, xe.Err
	}
	return ExitError, err
}
