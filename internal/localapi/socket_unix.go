// SPDX-License-Identifier: AGPL-3.0-only

//go:build !windows

package localapi

import (
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
)

// UserTempDir is this user's directory under the temporary directory, for
// sockets and session files when $XDG_RUNTIME_DIR is unset: the temporary
// directory is shared, so the name carries the user ID.
func UserTempDir() string {
	return filepath.Join(os.TempDir(), "scrim-"+strconv.Itoa(os.Getuid()))
}

func setMode(path string, mode fs.FileMode) error { return os.Chmod(path, mode) }
