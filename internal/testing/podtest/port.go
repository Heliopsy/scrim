// SPDX-License-Identifier: AGPL-3.0-only

package podtest

import (
	"net"
	"strconv"
)

// freePort asks the kernel for a free loopback port. Another process could
// take it before podman binds it; the caller then fails to start and skips.
func freePort() (string, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	defer func() { _ = l.Close() }()
	return strconv.Itoa(l.Addr().(*net.TCPAddr).Port), nil
}
