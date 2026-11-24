// SPDX-License-Identifier: AGPL-3.0-only

package localapi

import (
	"io/fs"
	"os"
	"path/filepath"
)

// UserTempDir is %TEMP%\scrim. The temporary directory is inside the user's
// profile on Windows and private to the account already.
func UserTempDir() string { return filepath.Join(os.TempDir(), "scrim") }

// setMode does nothing on Windows: an AF_UNIX socket file has no mode bits,
// and who may connect is decided by the directory's DACL, which
// fsperm.MkdirPrivate restricted to this account, SYSTEM and Administrators.
// A wider socket mode (api.permissions) is refused at start-up there.
func setMode(string, fs.FileMode) error { return nil }
