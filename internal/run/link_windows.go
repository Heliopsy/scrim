// SPDX-License-Identifier: AGPL-3.0-only

package run

import (
	"errors"
	"os"
	"strings"
)

// linkBin links name in the session's bin directory to the scrim binary,
// with the .exe suffix Windows needs to find it on PATH. A symbolic link
// needs Developer Mode or an administrator, so a hard link is tried next
// (same volume only); scrim recognises itself by the link's name either way.
func linkBin(target, name string) error {
	if !strings.HasSuffix(strings.ToLower(name), ".exe") {
		name += ".exe"
	}
	serr := os.Symlink(target, name)
	if serr == nil {
		return nil
	}
	lerr := os.Link(target, name)
	if lerr == nil {
		return nil
	}
	return errors.Join(serr, lerr)
}
