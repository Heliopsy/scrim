// SPDX-License-Identifier: AGPL-3.0-only

//go:build !unix

package ca

import (
	"io/fs"

	"github.com/heliopsy/scrim/internal/fsperm"
)

// lockDir is a no-op where flock is not available.
func lockDir(string, bool) (func(), error) { return func() {}, nil }

// checkOwner refuses a file or directory owned by another account (on
// Windows, by the owner SID).
func checkOwner(path string, fi fs.FileInfo) error { return fsperm.Owned(path, fi) }
