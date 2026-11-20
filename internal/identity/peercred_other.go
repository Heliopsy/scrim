// SPDX-License-Identifier: AGPL-3.0-only

//go:build !linux && !darwin

package identity

func peerOfFD(int) (Peer, error) { return Peer{}, ErrNoPeerCredentials }
