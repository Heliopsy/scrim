// SPDX-License-Identifier: AGPL-3.0-only

package dataplane

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// prepare writes b to the user cache directory and checks its hash. macOS
// has no memfd, and exec takes a path, so the file is re-checked just
// before exec in a directory only this user can write.
func prepare(b Binary, _ bool) (*executable, error) {
	d, err := os.UserCacheDir()
	if err != nil {
		return nil, err
	}
	dir := filepath.Join(d, "scrim")
	f, err := writeVerified(dir, b)
	if err != nil {
		return nil, err
	}
	return &executable{path: f.Name(), keep: f, how: "file"}, nil
}

func execRefused(error) bool { return false }

func checkOwner(fi os.FileInfo, dir string) error {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || int(st.Uid) != os.Getuid() {
		return fmt.Errorf("%s is not owned by this user", dir)
	}
	return nil
}
