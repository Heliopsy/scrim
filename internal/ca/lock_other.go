// SPDX-License-Identifier: AGPL-3.0-only

//go:build !unix

package ca

import "io/fs"

// lockDir is a no-op where flock is not available.
func lockDir(string, bool) (func(), error) { return func() {}, nil }

// checkOwner is not checked where ownership is not a uid.
func checkOwner(string, fs.FileInfo) error { return nil }
