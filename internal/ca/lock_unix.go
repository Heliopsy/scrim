// SPDX-License-Identifier: AGPL-3.0-only

//go:build unix

package ca

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

// lockDir takes the CA directory's advisory lock, shared for readers and
// exclusive for writers, so `scrim ca rotate` and a running daemon never
// write at the same time and a reader never sees a generation being removed.
func lockDir(dir string, exclusive bool) (unlock func(), err error) {
	p := filepath.Join(dir, lockFile)
	f, err := os.OpenFile(p, os.O_RDWR|os.O_CREATE, 0o600) // #nosec G304 -- path inside the CA directory
	if err != nil {
		return nil, fmt.Errorf("ca: lock %s: %w", p, err)
	}
	how := unix.LOCK_SH
	if exclusive {
		how = unix.LOCK_EX
	}
	for {
		err = unix.Flock(int(f.Fd()), how) // #nosec G115 -- file descriptors fit in int
		if err != unix.EINTR {
			break
		}
	}
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("ca: lock %s: %w", p, err)
	}
	return func() {
		_ = unix.Flock(int(f.Fd()), unix.LOCK_UN) // #nosec G115 -- file descriptors fit in int
		_ = f.Close()
	}, nil
}

// checkOwner refuses a file or directory owned by another user.
func checkOwner(path string, fi fs.FileInfo) error {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	if uid := os.Getuid(); int(st.Uid) != uid {
		return fmt.Errorf("ca: %s is owned by uid %d, not by this user (uid %d)", path, st.Uid, uid)
	}
	return nil
}
