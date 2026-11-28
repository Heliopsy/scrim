// SPDX-License-Identifier: AGPL-3.0-only

//go:build !windows

package localapi

import (
	"io/fs"
	"os"
)

func setMode(path string, mode fs.FileMode) error { return os.Chmod(path, mode) }
