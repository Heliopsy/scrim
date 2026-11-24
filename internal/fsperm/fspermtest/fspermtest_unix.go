// SPDX-License-Identifier: AGPL-3.0-only

//go:build unix

package fspermtest

import "os"

func open(path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	mode := os.FileMode(0o644)
	if fi.IsDir() {
		mode = 0o755
	}
	return os.Chmod(path, mode) // #nosec G302 -- the test needs a readable path
}
