// SPDX-License-Identifier: AGPL-3.0-only

//go:build unix

package plugin

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// checkOwnership checks the file and every directory above it.
func checkOwnership(path string) error {
	st, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() {
		return errors.New("is not a regular file")
	}
	if st.Mode().Perm()&0o111 == 0 {
		return errors.New("is not executable")
	}
	if err := trusted(path, st, false); err != nil {
		return err
	}
	for dir := filepath.Dir(path); ; dir = filepath.Dir(dir) {
		dst, err := os.Stat(dir)
		if err != nil {
			return err
		}
		if err := trusted(dir, dst, true); err != nil {
			return err
		}
		if dir == filepath.Dir(dir) {
			return nil
		}
	}
}

// trusted refuses an entry another user could change.
func trusted(path string, st os.FileInfo, dir bool) error {
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("%s: cannot read its owner", path)
	}
	if uid := uint32(os.Getuid()); sys.Uid != 0 && sys.Uid != uid { //nolint:gosec // uids are non-negative
		return fmt.Errorf("%s is owned by uid %d, not root or scrim's user", path, sys.Uid)
	}
	// In a sticky directory (/tmp) nobody can rename or remove another
	// user's entry, so the path to the plugin stays put.
	if dir && st.Mode()&os.ModeSticky != 0 {
		return nil
	}
	perm := st.Mode().Perm()
	if perm&0o002 != 0 {
		return fmt.Errorf("%s is writable by every user", path)
	}
	if perm&0o020 != 0 && sys.Gid != 0 {
		return fmt.Errorf("%s is writable by its group", path)
	}
	return nil
}
