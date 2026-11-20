// SPDX-License-Identifier: AGPL-3.0-only

package identity

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"maps"
	"slices"
	"time"

	"github.com/heliopsy/scrim/internal/secret"
)

// Session lifetimes. A session normally ends when `scrim run` exits; the
// expiry is the backstop for a wrapper that never got to revoke it.
const (
	DefaultSessionTTL = 12 * time.Hour
	MaxSessionTTL     = 7 * 24 * time.Hour
)

// Reasons a session is revoked, as recorded and audited.
const (
	RevokeEnded      = "ended"
	RevokeOperator   = "operator"
	RevokeRootExited = "root exited"
)

// RefusalReason says why a presented session token was refused. It is safe
// to log and audit; the caller is only ever told the token was refused.
type RefusalReason string

// The reasons a token can be refused.
const (
	RefusedMalformed RefusalReason = "malformed"
	RefusedUnknown   RefusalReason = "unknown"
	RefusedRevoked   RefusalReason = "revoked"
	RefusedExpired   RefusalReason = "expired"
	RefusedWrongUser RefusalReason = "wrong user"
	RefusedWrongTree RefusalReason = "outside the session's process tree"
)

// RefusedError is returned for a session token that cannot be used.
type RefusedError struct {
	Reason RefusalReason
	// SessionID is set when the token named a known session.
	SessionID string
}

func (e *RefusedError) Error() string { return "identity: session token refused: " + string(e.Reason) }

// ErrMintRefused is returned when a caller may not mint a session.
var ErrMintRefused = errors.New("identity: caller may not mint a session")

// ManagerOptions configure a Manager. Zero values take the defaults.
type ManagerOptions struct {
	DefaultTTL time.Duration
	MaxTTL     time.Duration
	Procs      ProcInfo
	Now        func() time.Time
	Rand       io.Reader
	// OnMint, if set, receives a copy of every minted token, which it owns
	// and must wipe. The daemon adds it to the redaction set, so a token
	// an agent echoes never reaches a model provider.
	OnMint func(s Session, token secret.Value)
}

// Manager mints, verifies and revokes session tokens.
type Manager struct {
	onMint     func(Session, secret.Value)
	store      SessionStore
	procs      ProcInfo
	now        func() time.Time
	rand       io.Reader
	defaultTTL time.Duration
	maxTTL     time.Duration
}

// NewManager returns a Manager over store.
func NewManager(store SessionStore, o ManagerOptions) *Manager {
	m := &Manager{store: store, procs: o.Procs, now: o.Now, rand: o.Rand,
		defaultTTL: o.DefaultTTL, maxTTL: o.MaxTTL, onMint: o.OnMint}
	if m.procs == nil {
		m.procs = OSProcs{}
	}
	if m.now == nil {
		m.now = time.Now
	}
	if m.rand == nil {
		m.rand = defaultRand
	}
	if m.maxTTL <= 0 {
		m.maxTTL = MaxSessionTTL
	}
	if m.defaultTTL <= 0 {
		m.defaultTTL = min(DefaultSessionTTL, m.maxTTL)
	}
	return m
}

// MintRequest is what `scrim run` asks for.
type MintRequest struct {
	// Name labels the session, for example the agent command.
	Name string
	// TTL is the requested lifetime, capped at the maximum. Zero takes the
	// default.
	TTL time.Duration
	// Scopes narrow the session below the minter's. Empty takes the minter's
	// agent scopes.
	Scopes []Scope
}

// Minted is a new session and its token. The token is shown to the minter
// once and never stored.
type Minted struct {
	Token   secret.Value
	Session Session
}

// Mint creates a session for the calling process. The session belongs to the
// minter's agent and user, and is bound to the minter's own process and its
// descendants: `scrim run` mints it, then starts the agent as its child.
func (m *Manager) Mint(ctx context.Context, minter Identity, req MintRequest) (Minted, error) {
	if minter.Source != SourcePeer || !minter.Has(ScopeSessionsMint) {
		return Minted{}, fmt.Errorf("%w: only a mapped local user with %s can", ErrMintRefused, ScopeSessionsMint)
	}
	if minter.Peer.PID <= 0 {
		return Minted{}, fmt.Errorf("%w: the platform does not report the caller's process", ErrMintRefused)
	}
	root, err := m.procs.Lookup(minter.Peer.PID)
	if err != nil {
		return Minted{}, fmt.Errorf("%w: reading the caller's process: %w", ErrMintRefused, err)
	}
	if len(req.Name) > 64 {
		return Minted{}, fmt.Errorf("%w: session name longer than 64 bytes", ErrMintRefused)
	}
	scopes, err := narrow(minter.Scopes, req.Scopes)
	if err != nil {
		return Minted{}, err
	}
	ttl := req.TTL
	if ttl <= 0 {
		ttl = m.defaultTTL
	}
	ttl = min(ttl, m.maxTTL)

	id, tok, hash, err := mintToken(m.rand)
	if err != nil {
		return Minted{}, err
	}
	now := m.now().UTC()
	s := Session{
		ID: id, Agent: minter.Agent, Name: req.Name, Hash: hash,
		UID: minter.Peer.UID, Root: root, Scopes: scopes,
		Labels: maps.Clone(minter.Labels), CreatedAt: now, ExpiresAt: now.Add(ttl),
	}
	if err := m.store.CreateSession(ctx, s); err != nil {
		tok.Wipe()
		return Minted{}, fmt.Errorf("identity: storing the session: %w", err)
	}
	if m.onMint != nil {
		var cp secret.Value
		_ = tok.Expose(func(b []byte) error { cp = secret.New(b); return nil })
		m.onMint(s, cp)
	}
	return Minted{Token: tok, Session: s}, nil
}

// narrow returns the requested scopes, refusing any the minter lacks and the
// mint scope itself. A session never mints further sessions.
func narrow(have, want []Scope) ([]Scope, error) {
	if len(want) == 0 {
		var out []Scope
		for _, s := range AgentScopes {
			if slices.Contains(have, s) {
				out = append(out, s)
			}
		}
		return out, nil
	}
	out := make([]Scope, 0, len(want))
	for _, s := range want {
		switch {
		case !ValidScope(s):
			return nil, fmt.Errorf("%w: unknown scope %q", ErrMintRefused, s)
		case s == ScopeSessionsMint:
			return nil, fmt.Errorf("%w: a session cannot hold %s", ErrMintRefused, s)
		case !slices.Contains(have, s):
			return nil, fmt.Errorf("%w: the caller lacks scope %s", ErrMintRefused, s)
		case !slices.Contains(out, s):
			out = append(out, s)
		}
	}
	return out, nil
}

// Verify checks a token presented by peer and returns the session identity.
// The token must name an active session whose secret matches, the peer must
// be the session's user, and the peer process must be the session's root or
// one of its descendants.
func (m *Manager) Verify(ctx context.Context, peer Peer, token []byte) (Identity, error) {
	id, hash, ok := parseToken(token)
	if !ok {
		return Identity{}, &RefusedError{Reason: RefusedMalformed}
	}
	s, err := m.store.GetSession(ctx, id)
	if errors.Is(err, ErrSessionNotFound) {
		return Identity{}, &RefusedError{Reason: RefusedUnknown}
	}
	if err != nil {
		return Identity{}, fmt.Errorf("identity: reading the session: %w", err)
	}
	if subtle.ConstantTimeCompare(hash, s.Hash) != 1 {
		return Identity{}, &RefusedError{Reason: RefusedUnknown}
	}
	refuse := func(r RefusalReason) (Identity, error) {
		return Identity{}, &RefusedError{Reason: r, SessionID: s.ID}
	}
	switch {
	case s.Revoked():
		return refuse(RefusedRevoked)
	case !m.now().Before(s.ExpiresAt):
		return refuse(RefusedExpired)
	case peer.UID != s.UID:
		return refuse(RefusedWrongUser)
	}
	in, err := descends(m.procs, peer.PID, s.Root)
	if err != nil {
		return Identity{}, fmt.Errorf("identity: checking the caller's process tree: %w", err)
	}
	if !in {
		return refuse(RefusedWrongTree)
	}
	return Identity{
		Agent: s.Agent, Source: SourceSession, Peer: peer,
		SessionID: s.ID, SessionName: s.Name, ExpiresAt: s.ExpiresAt,
		Scopes: slices.Clone(s.Scopes), Labels: maps.Clone(s.Labels),
	}, nil
}

// Revoke ends one session.
func (m *Manager) Revoke(ctx context.Context, id, reason string) error {
	return m.store.RevokeSession(ctx, id, m.now().UTC(), reason)
}

// RevokeAgent ends every session of an agent.
func (m *Manager) RevokeAgent(ctx context.Context, agent string) (int, error) {
	return m.store.RevokeAgentSessions(ctx, agent, m.now().UTC(), RevokeOperator)
}

// Get returns one session.
func (m *Manager) Get(ctx context.Context, id string) (Session, error) {
	return m.store.GetSession(ctx, id)
}

// Sweep revokes active sessions whose root process has exited, the backstop
// for a `scrim run` that was killed before it could revoke its own. It
// returns the sessions it revoked.
func (m *Manager) Sweep(ctx context.Context) ([]Session, error) {
	all, err := m.store.ListSessions(ctx)
	if err != nil {
		return nil, err
	}
	now := m.now()
	var revoked []Session
	var errs []error
	for _, s := range all {
		if !s.Active(now) {
			continue
		}
		p, err := m.procs.Lookup(s.Root.PID)
		alive := err == nil && p.Start == s.Root.Start
		if err != nil && !errors.Is(err, errNoProcess) {
			errs = append(errs, err)
			continue
		}
		if alive {
			continue
		}
		if err := m.store.RevokeSession(ctx, s.ID, now.UTC(), RevokeRootExited); err != nil {
			errs = append(errs, err)
			continue
		}
		s.RevokedAt, s.RevokeReason = now.UTC(), RevokeRootExited
		revoked = append(revoked, s)
	}
	return revoked, errors.Join(errs...)
}
