// SPDX-License-Identifier: AGPL-3.0-only

package execbroker

import (
	"context"
	"errors"
)

// ErrUnsupported is returned on Windows, where the broker cannot start a
// command in its own process group as another account with nothing
// inherited. The daemon refuses to start with exec commands configured
// there (internal/platform), so this is a backstop.
var ErrUnsupported = errors.New("execbroker: brokered commands (secret_exec) are not supported on Windows")

func start(context.Context, spec) (outcome, error) { return outcome{}, ErrUnsupported }
