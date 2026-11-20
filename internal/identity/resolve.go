// SPDX-License-Identifier: AGPL-3.0-only

package identity

import (
	"context"
	"errors"
)

// Resolver turns a transport into an identity: peer credentials always, a
// session token when one is presented.
type Resolver struct {
	Peers    *PeerMap
	Sessions *Manager
}

// Resolve returns the caller's identity.
//
// With no token the caller is its peer identity, or unknown when no rule maps
// it. With a token the caller is that session or nothing: a token that fails
// verification is an error, never a fall-back to the peer identity, so a
// stolen or stale token cannot be retried as something else.
func (r Resolver) Resolve(ctx context.Context, peer Peer, token []byte) (Identity, error) {
	if len(token) == 0 {
		id, _ := r.Peers.Lookup(peer)
		return id, nil
	}
	if r.Sessions == nil {
		return Identity{}, &RefusedError{Reason: RefusedUnknown}
	}
	return r.Sessions.Verify(ctx, peer, token)
}

// IsRefused reports whether err is a refused credential, and why.
func IsRefused(err error) (*RefusedError, bool) {
	var re *RefusedError
	ok := errors.As(err, &re)
	return re, ok
}
