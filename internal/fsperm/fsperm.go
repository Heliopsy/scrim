// SPDX-License-Identifier: AGPL-3.0-only

// Package fsperm answers one question the same way on every platform: can
// anyone but the account scrim runs as reach a file or directory? On Unix it
// reads the permission bits; on Windows, where the bits Go reports say
// nothing about access, it reads the owner and the DACL.
//
// "Private" means accessible only to the owner, plus the accounts that can
// read anything on the machine anyway: root on Unix; SYSTEM and the
// Administrators group on Windows.
package fsperm

import (
	"fmt"
	"io/fs"
	"os"
)

// Loose reports whether path (whose FileInfo is fi) is accessible to
// accounts other than its owner. detail describes what makes it loose, for
// an error message: "mode 0644" on Unix, the accounts the DACL grants on
// Windows.
func Loose(path string, fi fs.FileInfo) (loose bool, detail string, err error) {
	return loose0(path, fi)
}

// Check returns an error naming path when it is loose, or when its access
// cannot be read. what prefixes the message ("ca", "placeholder").
func Check(what, path string, fi fs.FileInfo) error {
	loose, detail, err := Loose(path, fi)
	if err != nil {
		return fmt.Errorf("%s: reading the access of %s: %w", what, path, err)
	}
	if loose {
		return fmt.Errorf("%s: %s is accessible to group or others (%s); %s", what, path, detail, FixHint(path, fi.IsDir()))
	}
	return nil
}

// MkdirPrivate creates dir and any missing parents. The directory itself is
// made private when this call creates it (mode 0700 on Unix; on Windows a
// protected DACL that grants the current user, SYSTEM and Administrators
// only, inherited by everything created inside). An existing directory is
// left as it is: callers check it with [Loose] and refuse it when loose.
func MkdirPrivate(dir string) error {
	if _, err := os.Stat(dir); err == nil {
		return nil
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return Restrict(dir)
}
