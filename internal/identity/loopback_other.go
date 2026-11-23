// SPDX-License-Identifier: AGPL-3.0-only

//go:build !linux

package identity

import "net"

// LoopbackPeerOf is only available on Linux.
func LoopbackPeerOf(net.Conn) (Peer, error) { return Peer{}, ErrNoPeerCredentials }
