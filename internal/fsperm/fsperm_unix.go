// SPDX-License-Identifier: AGPL-3.0-only

//go:build !windows

package fsperm

import (
	"fmt"
	"io/fs"
	"os"
	"syscall"
)

func loose0(_ string, fi fs.FileInfo) (bool, string, error) {
	perm := fi.Mode().Perm()
	return perm&0o077 != 0, fmt.Sprintf("mode %04o", perm), nil
}

// Restrict makes path private. On Unix the caller already created it with a
// private mode, so there is nothing to do.
func Restrict(string) error { return nil }

// Owned returns an error unless the current user owns path.
func Owned(path string, fi fs.FileInfo) error {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || int(st.Uid) != os.Getuid() {
		return fmt.Errorf("%s is not owned by this user", path)
	}
	return nil
}

// FixHint says how to make path private.
func FixHint(path string, dir bool) string {
	if dir {
		return "run `chmod 700 " + path + "`"
	}
	return "run `chmod 600 " + path + "`"
}
