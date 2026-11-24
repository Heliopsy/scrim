// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package identity

import "golang.org/x/sys/unix"

func peerOfFD(h uintptr) (Peer, error) {
	fd := int(h) // #nosec G115 -- a file descriptor fits in an int
	u, err := unix.GetsockoptUcred(fd, unix.SOL_SOCKET, unix.SO_PEERCRED)
	if err != nil {
		return Peer{}, err
	}
	return Peer{UID: u.Uid, GID: u.Gid, PID: u.Pid}, nil
}
