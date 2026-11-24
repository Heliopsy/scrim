// SPDX-License-Identifier: AGPL-3.0-only

package sqlite

import (
	"runtime"
	"strings"
	"testing"
)

func TestClassifyFSType(t *testing.T) {
	cases := map[string]FSKind{
		"ext4": FSLocal, "btrfs": FSLocal, "tmpfs": FSLocal, "xfs": FSLocal,
		"nfs": FSNFS, "nfs4": FSNFS, "cifs": FSSMB, "smb3": FSSMB,
		"fuse.sshfs": FSFUSE, "fuse.rclone": FSFUSE, "fuse.gocryptfs": FSUnknown,
		"9p": FSNetwork, "cephfs": FSNetwork, "": FSUnknown,
	}
	for in, want := range cases {
		if got := classifyFSType(in); got != want {
			t.Errorf("classifyFSType(%q) = %s, want %s", in, got, want)
		}
	}
}

func TestMountFor(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("mount tables and their Unix paths are Linux and macOS only")
	}
	mounts, err := parseMounts(strings.NewReader(`/dev/sda1 / ext4 rw 0 0
server:/export /mnt/nfs nfs4 rw 0 0
/dev/sdb1 /mnt/nfs/local ext4 rw 0 0
host:/x /mnt/with\040space fuse.sshfs rw 0 0
short
`))
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"/home/u/.local/state/scrim": "ext4",
		"/mnt/nfs/scrim":             "nfs4",
		"/mnt/nfs":                   "nfs4",
		"/mnt/nfsx":                  "ext4",
		"/mnt/nfs/local/scrim":       "ext4",
		"/mnt/with space/state":      "fuse.sshfs",
	}
	for dir, want := range cases {
		if got, _ := mountFor(mounts, dir); got != want {
			t.Errorf("mountFor(%q) = %q, want %q", dir, got, want)
		}
	}
	if _, ok := mountFor(mounts, "relative/dir"); ok {
		t.Error("a relative path matched a mount")
	}
}
