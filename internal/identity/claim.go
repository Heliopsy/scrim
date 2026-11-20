// SPDX-License-Identifier: AGPL-3.0-only

package identity

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"maps"
	"slices"
)

// RefusedNoProof is a session named without proof that the caller holds its
// token: a bare session id is public (audit entries, status) and proves
// nothing.
const RefusedNoProof RefusalReason = "no proof of the session token"

// proofDomain separates session proofs from any other HMAC use.
const proofDomain = "scrim session proof v1\x00"

// SessionProof is the proof an ask carries that the request held the token of
// session id (design D14, `AskCaller.session_proof`): HMAC-SHA256 keyed with
// the token's stored hash over the session id, the ask id and the ask
// deadline. The data plane computes it from the token it saw and forgets the
// token; the control plane recomputes it from [Session.Hash]. It is bound to
// one ask and reveals neither the token nor the hash.
func SessionProof(hash []byte, sessionID string, askID uint64, deadlineUnixNano int64) []byte {
	m := hmac.New(sha256.New, hash)
	m.Write([]byte(proofDomain))
	m.Write([]byte(sessionID))
	m.Write([]byte{0})
	var b [16]byte
	binary.BigEndian.PutUint64(b[:8], askID)
	binary.BigEndian.PutUint64(b[8:], uint64(deadlineUnixNano)) // #nosec G115 -- bit pattern, as the data plane writes it
	m.Write(b[:])
	return m.Sum(nil)
}

// TransportClaim is what the data plane's transport said about the sender of
// a request it asks about (`AskCaller`). The data plane verifies none of it.
type TransportClaim struct {
	// SessionID is the session the request named, if any.
	SessionID string
	// Proof is [SessionProof] for the ask, when the request carried the
	// session's token.
	Proof []byte
	// AskID and Deadline are the ask the proof is bound to.
	AskID    uint64
	Deadline int64
	// UnixPeer is set when the request came over a Unix socket; Peer holds
	// the kernel's credentials then.
	UnixPeer bool
	Peer     Peer
	// KubernetesToken is the service account token the request carried
	// instead of a session (`AskCaller.kubernetes_token`). The caller owns
	// and wipes it.
	KubernetesToken []byte
}

// ResolveClaim turns a transport claim into an identity.
//
//   - A named session is that session or nothing: it needs a valid proof of
//     its token, must be active, and when the request came over a Unix socket
//     the peer must be the session's user and inside its process tree. A
//     refusal is an error, never a fall-back to the peer identity.
//   - A Unix peer without a session is the innermost active session of the
//     same user whose process tree it is in (the agent `scrim run` started),
//     else its identity.peers mapping, else unknown.
//   - A Kubernetes service account token, when no session is named, is the
//     service account the cluster verifies it as, or nothing: a refused
//     token never falls back to the peer identity either.
//   - Nothing at all is unknown.
func (r Resolver) ResolveClaim(ctx context.Context, c TransportClaim) (Identity, error) {
	peer := Peer{}
	if c.UnixPeer {
		peer = c.Peer
	}
	if c.SessionID != "" {
		return r.verifyClaim(ctx, c, peer)
	}
	if len(c.KubernetesToken) > 0 {
		id, err := r.Kubernetes.Resolve(ctx, c.KubernetesToken)
		if err != nil {
			return Unknown(peer), err
		}
		if c.UnixPeer && id.Known() {
			id.Peer = peer
		}
		return id, nil
	}
	if !c.UnixPeer {
		return Unknown(peer), nil
	}
	if r.Sessions != nil {
		id, ok, err := r.Sessions.sessionOfTree(ctx, peer)
		if err != nil {
			return Unknown(peer), err
		}
		if ok {
			return id, nil
		}
	}
	if r.Peers == nil {
		return Unknown(peer), nil
	}
	id, _ := r.Peers.Lookup(peer)
	return id, nil
}

func (r Resolver) verifyClaim(ctx context.Context, c TransportClaim, peer Peer) (Identity, error) {
	if r.Sessions == nil {
		return Unknown(peer), &RefusedError{Reason: RefusedUnknown}
	}
	m := r.Sessions
	s, err := m.store.GetSession(ctx, c.SessionID)
	if errors.Is(err, ErrSessionNotFound) {
		return Unknown(peer), &RefusedError{Reason: RefusedUnknown}
	}
	if err != nil {
		return Unknown(peer), fmt.Errorf("identity: reading the session: %w", err)
	}
	refuse := func(why RefusalReason) (Identity, error) {
		return Unknown(peer), &RefusedError{Reason: why, SessionID: s.ID}
	}
	if len(c.Proof) == 0 {
		return refuse(RefusedNoProof)
	}
	if !hmac.Equal(c.Proof, SessionProof(s.Hash, s.ID, c.AskID, c.Deadline)) {
		// Same answer as a wrong token on the agent API: nothing tells the
		// caller whether the session exists.
		return Unknown(peer), &RefusedError{Reason: RefusedUnknown}
	}
	switch {
	case s.Revoked():
		return refuse(RefusedRevoked)
	case !m.now().Before(s.ExpiresAt):
		return refuse(RefusedExpired)
	}
	if c.UnixPeer {
		if peer.UID != s.UID {
			return refuse(RefusedWrongUser)
		}
		in, err := descends(m.procs, peer.PID, s.Root)
		if err != nil {
			return Unknown(peer), fmt.Errorf("identity: checking the caller's process tree: %w", err)
		}
		if !in {
			return refuse(RefusedWrongTree)
		}
	}
	return sessionIdentity(s, peer), nil
}

func sessionIdentity(s Session, peer Peer) Identity {
	if peer == (Peer{}) {
		peer = Peer{UID: s.UID}
	}
	return Identity{
		Agent: s.Agent, Source: SourceSession, Peer: peer,
		SessionID: s.ID, SessionName: s.Name, ExpiresAt: s.ExpiresAt,
		Scopes: slices.Clone(s.Scopes), Labels: maps.Clone(s.Labels),
	}
}

// sessionOfTree finds the innermost active session of peer's user whose root
// process is peer's process or one of its ancestors.
func (m *Manager) sessionOfTree(ctx context.Context, peer Peer) (Identity, bool, error) {
	if peer.PID <= 0 {
		return Identity{}, false, nil
	}
	all, err := m.store.ListSessions(ctx)
	if err != nil {
		return Identity{}, false, fmt.Errorf("identity: listing sessions: %w", err)
	}
	now := m.now()
	roots := map[int32][]Session{}
	for _, s := range all {
		if s.Active(now) && s.UID == peer.UID {
			roots[s.Root.PID] = append(roots[s.Root.PID], s)
		}
	}
	if len(roots) == 0 {
		return Identity{}, false, nil
	}
	cur := peer.PID
	for range maxDepth {
		p, err := m.procs.Lookup(cur)
		if err != nil {
			if errors.Is(err, errNoProcess) {
				return Identity{}, false, nil
			}
			return Identity{}, false, err
		}
		for _, s := range roots[p.PID] {
			if s.Root.Start == p.Start {
				return sessionIdentity(s, peer), true, nil
			}
		}
		if p.PPID <= 0 || p.PPID == p.PID {
			return Identity{}, false, nil
		}
		cur = p.PPID
	}
	return Identity{}, false, nil
}
