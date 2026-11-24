// SPDX-License-Identifier: AGPL-3.0-only

package identity

import (
	"errors"
	"fmt"
	"net"
	"syscall"
)

// ErrNoPeerCredentials is returned where the platform or the connection
// cannot report peer credentials. A caller without them is unknown.
var ErrNoPeerCredentials = errors.New("identity: peer credentials are not available")

// PeerOf returns the operating system's credentials for the process at the
// other end of a Unix socket connection: SO_PEERCRED on Linux,
// LOCAL_PEERCRED and LOCAL_PEERPID on macOS, SIO_AF_UNIX_GETPEERPID and the
// peer process's token on Windows. The values are those the kernel recorded
// when the peer connected; the peer cannot forge them.
func PeerOf(c net.Conn) (Peer, error) {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return Peer{}, fmt.Errorf("%w: not a Unix socket connection", ErrNoPeerCredentials)
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return Peer{}, fmt.Errorf("%w: %w", ErrNoPeerCredentials, err)
	}
	return peerOfRaw(raw)
}

func peerOfRaw(raw syscall.RawConn) (Peer, error) {
	var (
		p    Peer
		perr error
	)
	if err := raw.Control(func(fd uintptr) { p, perr = peerOfFD(fd) }); err != nil {
		return Peer{}, fmt.Errorf("%w: %w", ErrNoPeerCredentials, err)
	}
	if perr != nil {
		return Peer{}, fmt.Errorf("%w: %w", ErrNoPeerCredentials, perr)
	}
	return p, nil
}
