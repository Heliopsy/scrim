// SPDX-License-Identifier: AGPL-3.0-only

// Package runtimedir places scrim's sockets and runtime files for the user
// it runs as: $XDG_RUNTIME_DIR/scrim, or a directory under the temporary
// directory whose name carries the user ID when $XDG_RUNTIME_DIR is unset.
//
// The temporary directory is shared on Unix, so another local user can
// create the directory first. Every path under [Dir] is checked before it is
// used: the directory must be owned by this user and must not be writable
// by group or others, or scrim refuses to listen in it or dial a socket in
// it.
package runtimedir

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/heliopsy/scrim/internal/fsperm"
)

// Dir is this user's runtime directory: $XDG_RUNTIME_DIR/scrim, or
// [UserTemp] when $XDG_RUNTIME_DIR is unset.
func Dir() string {
	if dir := os.Getenv("XDG_RUNTIME_DIR"); dir != "" {
		return filepath.Join(dir, "scrim")
	}
	return UserTemp()
}

// within reports whether dir is top or inside it.
func within(top, dir string) bool {
	rel, err := filepath.Rel(top, dir)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}

// Mkdir creates dir with [fsperm.MkdirPrivate]. When dir is [Dir] or inside
// it, Dir and every directory down to dir must then be owned by this user
// and not writable by group or others; one that is not is an error naming
// it, and nothing is created below it.
func Mkdir(dir string) error { return MkdirUnder(Dir(), dir) }

// MkdirUnder is [Mkdir] with top in place of [Dir], for a runtime directory
// taken from another environment than this process's.
func MkdirUnder(top, dir string) error {
	top, dir = filepath.Clean(top), filepath.Clean(dir)
	if !within(top, dir) {
		return fsperm.MkdirPrivate(dir)
	}
	if err := fsperm.MkdirPrivate(top); err != nil {
		return err
	}
	if err := checkDir(top); err != nil {
		return err
	}
	if err := fsperm.MkdirPrivate(dir); err != nil {
		return err
	}
	return checkChain(top, dir, false)
}

// CheckSocket is the client's side of [Mkdir]: when the directory of the
// socket at path is [Dir] or inside it, every existing directory from Dir
// down to it must be owned by this user and not writable by group or
// others. A missing directory is not an error (nothing listens there).
func CheckSocket(path string) error {
	top, dir := filepath.Clean(Dir()), filepath.Dir(filepath.Clean(path))
	if !within(top, dir) {
		return nil
	}
	return checkChain(top, dir, true)
}

// checkChain checks top and each directory below it down to dir.
func checkChain(top, dir string, missingOK bool) error {
	rel, err := filepath.Rel(top, dir)
	if err != nil {
		return err
	}
	cur := top
	parts := []string{}
	if rel != "." {
		parts = strings.Split(rel, string(filepath.Separator))
	}
	for i := -1; i < len(parts); i++ {
		if i >= 0 {
			cur = filepath.Join(cur, parts[i])
		}
		if err := checkDir(cur); err != nil {
			if missingOK && errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			return err
		}
	}
	return nil
}

// errUnsafe builds the error for a directory scrim refuses.
func errUnsafe(dir, why string) error {
	return fmt.Errorf("refusing the scrim runtime directory %s: %s; another local user may have created it. "+
		"Remove it, or set XDG_RUNTIME_DIR to a directory only this user can write", dir, why)
}
