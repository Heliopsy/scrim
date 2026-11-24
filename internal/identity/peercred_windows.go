// SPDX-License-Identifier: AGPL-3.0-only

package identity

import (
	"fmt"
	"math"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Windows has no user or group IDs. A peer is either the account scrim runs
// as, which gets the UID os.Getuid reports there ([SelfUID]), or another
// account, which gets [OtherUID]: never mapped, never root. identity.peers
// rules cannot name Windows accounts and are refused there.
const (
	// SelfUID is the UID of a peer running as scrim's own account. It is
	// the value os.Getuid returns on Windows (-1), so code comparing a peer
	// with os.Getuid works unchanged.
	SelfUID = math.MaxUint32
	// OtherUID is the UID of a peer running as any other account.
	OtherUID = math.MaxUint32 - 1
)

// sioAFUnixGetPeerPID is SIO_AF_UNIX_GETPEERPID, _WSAIOR(IOC_VENDOR, 256):
// the process ID the kernel recorded for the peer of an AF_UNIX socket
// (Windows 10 1809 and later).
const sioAFUnixGetPeerPID = 0x58000100

func peerOfFD(h uintptr) (Peer, error) {
	var pid, n uint32
	err := windows.WSAIoctl(windows.Handle(h), sioAFUnixGetPeerPID, nil, 0,
		(*byte)(unsafe.Pointer(&pid)), uint32(unsafe.Sizeof(pid)), &n, nil, 0) //nolint:gosec // WSAIoctl writes the 4-byte PID into pid
	if err != nil {
		return Peer{}, fmt.Errorf("SIO_AF_UNIX_GETPEERPID: %w", err)
	}
	if pid == 0 || pid > math.MaxInt32 {
		return Peer{}, fmt.Errorf("SIO_AF_UNIX_GETPEERPID returned pid %d", pid)
	}
	self, err := sameAccount(pid)
	if err != nil {
		return Peer{}, err
	}
	p := Peer{UID: OtherUID, GID: OtherUID, PID: int32(pid)} // #nosec G115 -- checked above
	if self {
		p.UID, p.GID = SelfUID, SelfUID
	}
	return p, nil
}

// sameAccount reports whether process pid runs as the account this process
// runs as, by the user SID of its primary token.
func sameAccount(pid uint32) (bool, error) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return false, fmt.Errorf("opening peer process %d: %w", pid, err)
	}
	defer func() { _ = windows.CloseHandle(h) }()
	var tok windows.Token
	if err := windows.OpenProcessToken(h, windows.TOKEN_QUERY, &tok); err != nil {
		return false, fmt.Errorf("reading the token of peer process %d: %w", pid, err)
	}
	defer func() { _ = tok.Close() }()
	theirs, err := tok.GetTokenUser()
	if err != nil {
		return false, err
	}
	ours, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return false, err
	}
	return theirs.User.Sid.Equals(ours.User.Sid), nil
}
