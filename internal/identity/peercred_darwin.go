// SPDX-License-Identifier: AGPL-3.0-only

//go:build darwin

package identity

import "golang.org/x/sys/unix"

func peerOfFD(fd int) (Peer, error) {
	x, err := unix.GetsockoptXucred(fd, unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	if err != nil {
		return Peer{}, err
	}
	p := Peer{UID: x.Uid}
	if x.Ngroups > 0 {
		p.GID = x.Groups[0]
	}
	// LOCAL_PEERPID exists since macOS 10.8. Without it the PID stays 0, and
	// session tokens bound to a process tree are refused.
	if pid, err := unix.GetsockoptInt(fd, unix.SOL_LOCAL, unix.LOCAL_PEERPID); err == nil {
		p.PID = int32(pid) // #nosec G115 -- pid_t is 32 bits
	}
	return p, nil
}
