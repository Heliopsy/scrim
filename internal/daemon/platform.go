// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"errors"
	"fmt"
	"runtime"
	"strings"

	"github.com/heliopsy/scrim/internal/config"
)

// errUnsupportedPlatform wraps every setting the platform cannot honour.
var errUnsupportedPlatform = errors.New("not supported on " + runtime.GOOS)

// checkPlatform refuses a configuration that asks for something this
// platform cannot do, naming every such setting, so scrim never starts
// believing a protection is in place that is not. Windows is the platform
// with refusals (docs/limitations.md, Platforms).
func checkPlatform(cfg *config.Config) error {
	refusals := platformRefusals(cfg)
	if len(refusals) == 0 {
		return nil
	}
	return fmt.Errorf("%w:\n  %s", errUnsupportedPlatform, strings.Join(refusals, "\n  "))
}
