// SPDX-License-Identifier: AGPL-3.0-only

package sqlite

import (
	"bufio"
	"io"
	"path/filepath"
	"strings"
)

// FSKind classifies the filesystem a database file sits on, as far as it
// matters to SQLite's locking and durability.
type FSKind string

// Filesystem kinds. Only the network kinds are refused.
const (
	FSLocal   FSKind = "local"
	FSNFS     FSKind = "nfs"
	FSSMB     FSKind = "smb"
	FSFUSE    FSKind = "network-fuse"
	FSNetwork FSKind = "network"
	FSUnknown FSKind = "unknown"
)

// IsNetwork reports whether k is a network or shared filesystem, on which
// SQLite's file locks are unreliable and a database can be corrupted.
func (k FSKind) IsNetwork() bool {
	switch k {
	case FSNFS, FSSMB, FSFUSE, FSNetwork:
		return true
	}
	return false
}

// networkFUSE lists FUSE subtypes that mount a remote endpoint.
var networkFUSE = []string{"sshfs", "rclone", "s3fs", "gcsfuse", "curlftpfs", "davfs", "webdav", "smbnetfs"}

// classifyFSType maps a filesystem type name as /proc/mounts reports it to a
// kind. Unrecognised names are local: every network filesystem SQLite is
// known to break on is listed.
func classifyFSType(name string) FSKind {
	name = strings.ToLower(strings.TrimSpace(name))
	if sub, ok := strings.CutPrefix(name, "fuse."); ok {
		for _, n := range networkFUSE {
			if strings.HasPrefix(sub, n) {
				return FSFUSE
			}
		}
		return FSUnknown
	}
	switch name {
	case "":
		return FSUnknown
	case "nfs", "nfs3", "nfs4":
		return FSNFS
	case "cifs", "smb", "smbfs", "smb2", "smb3":
		return FSSMB
	case "9p", "afpfs", "ncpfs", "glusterfs", "ceph", "cephfs", "lustre", "gpfs", "davfs", "davfs2", "webdav":
		return FSNetwork
	}
	return FSLocal
}

type mount struct{ point, fstype string }

// parseMounts reads a file in /proc/mounts format.
func parseMounts(r io.Reader) ([]mount, error) {
	var out []mount
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 3 {
			continue
		}
		out = append(out, mount{point: unescapeMount(f[1]), fstype: f[2]})
	}
	return out, sc.Err()
}

// unescapeMount reverses the octal escapes /proc/mounts uses for spaces,
// tabs, newlines and backslashes.
func unescapeMount(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			v, ok := 0, true
			for _, c := range s[i+1 : i+4] {
				if c < '0' || c > '7' {
					ok = false
					break
				}
				v = v*8 + int(c-'0')
			}
			if ok && v <= 0xff {
				b.WriteByte(byte(v))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// mountFor returns the filesystem type of the mount holding dir: the longest
// matching mount point, the last one listed on a tie, as the kernel resolves
// an overmount.
func mountFor(mounts []mount, dir string) (string, bool) {
	best, bestLen := "", -1
	for _, m := range mounts {
		if !under(dir, m.point) {
			continue
		}
		if len(m.point) >= bestLen {
			best, bestLen = m.fstype, len(m.point)
		}
	}
	return best, bestLen >= 0
}

func under(dir, point string) bool {
	if !filepath.IsAbs(dir) {
		return false
	}
	if point == "/" || dir == point {
		return true
	}
	return strings.HasPrefix(dir, strings.TrimSuffix(point, "/")+"/")
}
