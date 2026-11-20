// SPDX-License-Identifier: AGPL-3.0-only

//go:build darwin

package sqlite

import "golang.org/x/sys/unix"

// detectFS classifies the filesystem holding dir from statfs's type name.
func detectFS(dir string) FSKind {
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err != nil {
		return FSUnknown
	}
	return classifyFSType(unix.ByteSliceToString(st.Fstypename[:]))
}
