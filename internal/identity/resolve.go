// SPDX-License-Identifier: AGPL-3.0-only

package identity

import (
	"bytes"
	"context"
	"errors"
)

// Resolver turns a transport into an identity: peer credentials always, a
// session token when one is presented.
type Resolver struct {
	Peers    *PeerMap
	Sessions *Manager
	// Kubernetes verifies service account tokens; nil refuses them.
	Kubernetes *KubeResolver
	// Certificates verifies client certificates; nil refuses them.
	Certificates *CertResolver
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
	if LooksLikeKubernetesToken(token) {
		id, err := r.Kubernetes.Resolve(ctx, token)
		if err == nil && id.Known() {
			id.Peer = peer
		}
		return id, err
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

// LooksLikeKubernetesToken reports whether tok is shaped like a JWT, the
// form of a Kubernetes service account token, rather than a session token.
func LooksLikeKubernetesToken(tok []byte) bool {
	return bytes.HasPrefix(bytes.TrimSpace(tok), []byte("eyJ")) && bytes.Count(tok, []byte(".")) == 2
}
