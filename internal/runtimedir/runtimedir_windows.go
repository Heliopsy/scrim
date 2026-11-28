// SPDX-License-Identifier: AGPL-3.0-only

package runtimedir

import (
	"os"
	"path/filepath"
)

// UserTemp is %TEMP%\scrim. The temporary directory is inside the user's
// profile on Windows and private to the account already.
func UserTemp() string { return filepath.Join(os.TempDir(), "scrim") }

// checkDir only checks that dir exists: %TEMP% is per-user on Windows, and
// fsperm.MkdirPrivate gives a directory it creates a DACL for this account,
// SYSTEM and Administrators.
func checkDir(dir string) error {
	_, err := os.Lstat(dir)
	return err
}
