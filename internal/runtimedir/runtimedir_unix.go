// SPDX-License-Identifier: AGPL-3.0-only

//go:build !windows

package runtimedir

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
)

// UserTemp is this user's directory under the temporary directory. The
// temporary directory is shared, so the name carries the user ID.
func UserTemp() string {
	return filepath.Join(os.TempDir(), "scrim-"+strconv.Itoa(os.Getuid()))
}

// getuid is the user the directories must belong to. A variable so tests
// can check the ownership rule without chown.
var getuid = os.Getuid

// checkDir refuses dir unless it is a directory (not a symbolic link) owned
// by this user and not writable by group or others.
func checkDir(dir string) error {
	fi, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return errUnsafe(dir, "it is a symbolic link")
	}
	if !fi.IsDir() {
		return errUnsafe(dir, "it is not a directory")
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return errUnsafe(dir, "its owner cannot be read")
	}
	if me := getuid(); int(st.Uid) != me {
		return errUnsafe(dir, fmt.Sprintf("it is owned by uid %d, not this user (uid %d)", st.Uid, me))
	}
	if perm := fi.Mode().Perm(); perm&0o022 != 0 {
		return errUnsafe(dir, fmt.Sprintf("it is writable by group or others (mode %04o)", perm))
	}
	return nil
}

// errUnsafe builds the error for a directory scrim refuses.
func errUnsafe(dir, why string) error {
	return fmt.Errorf("refusing the scrim runtime directory %s: %s; another local user may have created it. "+
		"Remove it, or set XDG_RUNTIME_DIR to a directory only this user can write", dir, why)
}
