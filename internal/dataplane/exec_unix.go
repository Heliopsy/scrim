// SPDX-License-Identifier: AGPL-3.0-only

//go:build unix

package dataplane

import (
	"fmt"
	"os"
)

const exeSuffix = ""

func mkdirPrivate(dir string) error { return os.MkdirAll(dir, 0o700) }

// checkPrivateDir refuses a directory other users can write to or that we
// do not own, since anyone who can replace the file controls the data plane.
func checkPrivateDir(dir string) error {
	fi, err := os.Stat(dir)
	if err != nil {
		return err
	}
	if perm := fi.Mode().Perm(); perm&0o022 != 0 {
		return &looseDirError{dir: dir, detail: fmt.Sprintf("mode %04o", perm)}
	}
	return checkOwner(fi, dir)
}
