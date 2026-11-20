// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package sqlite

import (
	"os"

	"golang.org/x/sys/unix"
)

// detectFS classifies the filesystem holding dir. /proc/mounts names FUSE
// subtypes, which statfs cannot; statfs is the fallback.
func detectFS(dir string) FSKind {
	if f, err := os.Open("/proc/mounts"); err == nil {
		mounts, err := parseMounts(f)
		_ = f.Close()
		if err == nil {
			if t, ok := mountFor(mounts, dir); ok {
				return classifyFSType(t)
			}
		}
	}
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err != nil {
		return FSUnknown
	}
	switch uint32(st.Type) { // #nosec G115 -- magic numbers are uint32
	case unix.NFS_SUPER_MAGIC:
		return FSNFS
	case unix.CIFS_SUPER_MAGIC, unix.SMB_SUPER_MAGIC, unix.SMB2_SUPER_MAGIC:
		return FSSMB
	}
	return FSLocal
}
