// SPDX-License-Identifier: AGPL-3.0-only

package dataplane

import (
	"os"
	"path/filepath"

	"github.com/heliopsy/scrim/internal/fsperm"
)

// prepare writes b to %LOCALAPPDATA%\scrim and checks its hash, as on
// macOS. The directory gets a protected DACL (this user, SYSTEM and
// Administrators) when scrim creates it, and is refused when anyone else
// can reach it. The returned descriptor stays open until the child has
// started; Windows does not let the file be replaced while it is open
// without FILE_SHARE_DELETE, which Go does not grant.
func prepare(b Binary, _ bool) (*executable, error) {
	d, err := os.UserCacheDir()
	if err != nil {
		return nil, err
	}
	f, err := writeVerified(filepath.Join(d, "scrim"), b)
	if err != nil {
		return nil, err
	}
	return &executable{path: f.Name(), keep: f, how: "file"}, nil
}

func execRefused(error) bool { return false }

// exeSuffix is appended to the cached file's name: CreateProcess runs
// only files it can name with their extension.
const exeSuffix = ".exe"

func mkdirPrivate(dir string) error { return fsperm.MkdirPrivate(dir) }

func checkPrivateDir(dir string) error {
	fi, err := os.Stat(dir)
	if err != nil {
		return err
	}
	if loose, detail, err := fsperm.Loose(dir, fi); err != nil {
		return err
	} else if loose {
		return &looseDirError{dir: dir, detail: detail}
	}
	return fsperm.Owned(dir, fi)
}
