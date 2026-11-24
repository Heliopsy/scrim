// SPDX-License-Identifier: AGPL-3.0-only

//go:build !windows

package run

import "os"

// linkBin links name in the session's bin directory to the scrim binary.
func linkBin(target, name string) error { return os.Symlink(target, name) }
