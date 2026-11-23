// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package identity

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// LoopbackPeerOf returns the owner of the client end of a loopback TCP
// connection c accepted: the user from the kernel's socket table
// (/proc/net/tcp, tcp6) and, when this process may read the other process's
// file descriptors (same user), the process holding the socket. It is the TCP
// counterpart of [PeerOf] for local listeners such as the database proxies.
// A connection from another host or another network namespace has no entry
// and returns [ErrNoPeerCredentials].
func LoopbackPeerOf(c net.Conn) (Peer, error) {
	ra, ok1 := c.RemoteAddr().(*net.TCPAddr)
	la, ok2 := c.LocalAddr().(*net.TCPAddr)
	if !ok1 || !ok2 || !ra.IP.IsLoopback() {
		return Peer{}, fmt.Errorf("%w: not a loopback TCP connection", ErrNoPeerCredentials)
	}
	for _, table := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		uid, inode, found, err := findSocket(table, ra, la)
		if err != nil {
			continue
		}
		if found {
			return Peer{UID: uid, PID: pidOfSocket(inode, uid)}, nil
		}
	}
	return Peer{}, fmt.Errorf("%w: the client socket is not in this network namespace's table", ErrNoPeerCredentials)
}

// findSocket looks for the socket whose local address is the client's
// (remote) address and whose remote address is our listener's.
func findSocket(table string, client, server *net.TCPAddr) (uid uint32, inode string, found bool, err error) {
	f, err := os.Open(table) // #nosec G304 -- fixed kernel paths
	if err != nil {
		return 0, "", false, err
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	sc.Scan() // header
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 10 {
			continue
		}
		if !addrIs(fields[1], client) || !addrIs(fields[2], server) {
			continue
		}
		u, err := strconv.ParseUint(fields[7], 10, 32)
		if err != nil {
			return 0, "", false, err
		}
		return uint32(u), fields[9], true, nil
	}
	return 0, "", false, sc.Err()
}

// addrIs compares a /proc/net/tcp address ("0100007F:1F90", each 32-bit word
// in host byte order, which is little endian on every platform scrim
// supports) with a.
func addrIs(field string, a *net.TCPAddr) bool {
	ipHex, portHex, ok := strings.Cut(field, ":")
	if !ok {
		return false
	}
	port, err := strconv.ParseUint(portHex, 16, 16)
	if err != nil || int(port) != a.Port {
		return false
	}
	raw, err := hex.DecodeString(ipHex)
	if err != nil || len(raw)%4 != 0 {
		return false
	}
	for i := 0; i < len(raw); i += 4 {
		raw[i], raw[i+1], raw[i+2], raw[i+3] = raw[i+3], raw[i+2], raw[i+1], raw[i]
	}
	return net.IP(raw).Equal(a.IP)
}

// pidOfSocket finds a process of uid holding socket inode, or 0.
func pidOfSocket(inode string, uid uint32) int32 {
	want := "socket:[" + inode + "]"
	procs, err := os.ReadDir("/proc")
	if err != nil {
		return 0
	}
	for _, p := range procs {
		pid, err := strconv.ParseInt(p.Name(), 10, 32)
		if err != nil {
			continue
		}
		if fi, err := os.Stat(filepath.Join("/proc", p.Name())); err != nil || !ownedBy(fi, uid) {
			continue
		}
		dir := filepath.Join("/proc", p.Name(), "fd")
		fds, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, fd := range fds {
			if l, err := os.Readlink(filepath.Join(dir, fd.Name())); err == nil && l == want {
				return int32(pid)
			}
		}
	}
	return 0
}

func ownedBy(fi os.FileInfo, uid uint32) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && st.Uid == uid
}
