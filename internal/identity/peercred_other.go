// SPDX-License-Identifier: AGPL-3.0-only

//go:build !linux && !darwin && !windows

package identity

func peerOfFD(uintptr) (Peer, error) { return Peer{}, ErrNoPeerCredentials }
