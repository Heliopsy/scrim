// SPDX-License-Identifier: AGPL-3.0-only

//go:build !windows

package fsview

import "golang.org/x/sys/unix"

// readable reports whether this process's user can read path: open a file,
// or list or traverse a directory.
func readable(path string, dir bool) bool {
	if unix.Access(path, unix.R_OK) == nil {
		return true
	}
	return dir && unix.Access(path, unix.X_OK) == nil
}
