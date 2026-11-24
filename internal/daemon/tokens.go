// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"

	"github.com/heliopsy/scrim/internal/identity"
	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/state"
	"github.com/heliopsy/scrim/internal/stores/refresh"
)

// sessionTokens holds the session tokens this daemon minted, until they
// expire, so they are in the redaction set: an agent that prints its own
// SCRIM_SESSION_TOKEN never sends it to a provider. Only the hash is ever
// stored; these copies live in memory and are wiped on expiry and Close.
// The same type holds the Kubernetes service account tokens scrim verified
// (store "scrim-kubernetes") and the identity tokens its issuer signed
// (store "scrim-issuer"), keyed by their SHA-256.
//
// With shared state (sharedTokens) the set also holds the tokens other
// replicas minted or verified, and hands every token it gets here to share,
// so every replica redacts every token.
type sessionTokens struct {
	store string
	// kind is the token kind in the shared state (state.Token*).
	kind     string
	mu       sync.Mutex
	tokens   map[string]sessionToken
	now      func() time.Time
	onChange func()
	// share, when set, receives a copy of every token added here (not one
	// that came from another replica), and of one whose expiry moved by
	// more than reshareAfter. It owns the copy.
	share func(kind, id string, v secret.Value, expires time.Time)
}

// Store names for the token sets.
const (
	sessionTokenStore = "scrim-sessions"
	kubeTokenStore    = "scrim-kubernetes"
	// issuedTokenStore holds the identity tokens scrim's issuer signed.
	issuedTokenStore = "scrim-issuer"
)

// kubeTokenTTL is how long a service account token without an expiry stays
// in the redaction set after it was last verified.
const kubeTokenTTL = 24 * time.Hour

// reshareAfter is how far a token's expiry must move past the expiry last
// shared before it is shared again: a token without an expiry has it moved
// on every verification.
const reshareAfter = time.Hour

type sessionToken struct {
	v       secret.Value
	expires time.Time
	// agent is the session's agent; empty for a Kubernetes token.
	agent string
	// ended is set when the session was revoked: its token stays in the
	// redaction set until it expires, but the session leaves the narrowed
	// redaction scopes.
	ended bool
	// shared is the expiry last handed to share.
	shared time.Time
}

func newSessionTokens(store string, onChange func()) *sessionTokens {
	kind := map[string]string{sessionTokenStore: state.TokenSession, kubeTokenStore: state.TokenKubernetes,
		issuedTokenStore: state.TokenIssuer}[store]
	return &sessionTokens{store: store, kind: kind, tokens: map[string]sessionToken{}, now: time.Now, onChange: onChange}
}

// Store implements ValueSource.
func (t *sessionTokens) Store() string { return t.store }

func tokenKey(tok []byte) string {
	sum := sha256.Sum256(tok)
	return hex.EncodeToString(sum[:])
}

// offer hands a copy of tok to share, outside the lock.
func (t *sessionTokens) offer(id string, tok []byte, expires time.Time) {
	if t.share != nil {
		t.share(t.kind, id, secret.New(tok), expires)
	}
}

// addKube adds a copy of a verified service account token until it
// expires (kubeTokenTTL after this verification when it has no expiry).
// A token already held only has its expiry moved, and no snapshot is
// pushed for it.
func (t *sessionTokens) addKube(tok []byte, expires time.Time) {
	if len(tok) == 0 {
		return
	}
	id := tokenKey(tok)
	if expires.IsZero() {
		expires = t.now().Add(kubeTokenTTL)
	}
	t.mu.Lock()
	if old, ok := t.tokens[id]; ok {
		if expires.After(old.expires) {
			old.expires = expires
		}
		reshare := t.share != nil && old.expires.After(old.shared.Add(reshareAfter))
		if reshare {
			old.shared = old.expires
		}
		t.tokens[id] = old
		t.mu.Unlock()
		if reshare {
			t.offer(id, tok, old.expires)
		}
		return
	}
	t.tokens[id] = sessionToken{v: secret.New(tok), expires: expires, shared: expires}
	t.mu.Unlock()
	t.offer(id, tok, expires)
	if t.onChange != nil {
		t.onChange()
	}
}

// addValue takes ownership of v, an identity token scrim signed, and holds
// it until it expires.
func (t *sessionTokens) addValue(v secret.Value, expires time.Time) {
	defer v.Wipe()
	_ = v.Expose(func(b []byte) error { t.addKube(b, expires); return nil })
}

// add takes ownership of v.
func (t *sessionTokens) add(s identity.Session, v secret.Value) {
	t.mu.Lock()
	if old, ok := t.tokens[s.ID]; ok {
		old.v.Wipe()
	}
	t.tokens[s.ID] = sessionToken{v: v, expires: s.ExpiresAt, agent: s.Agent, ended: !s.RevokedAt.IsZero(), shared: s.ExpiresAt}
	t.mu.Unlock()
	if t.share != nil {
		_ = v.Expose(func(b []byte) error { t.offer(s.ID, b, s.ExpiresAt); return nil })
	}
	if t.onChange != nil {
		t.onChange()
	}
}

// addShared takes ownership of v, a token another replica (or this one
// before a restart) shared, and holds it until expires. A session token is
// keyed by its session ID, any other by its SHA-256. A token already held
// keeps its value and gets the later expiry; ended is only ever set.
func (t *sessionTokens) addShared(sessionID, agent string, ended bool, v secret.Value, expires time.Time) {
	id := sessionID
	if id == "" {
		_ = v.Expose(func(b []byte) error { id = tokenKey(b); return nil })
	}
	if !t.now().Before(expires) {
		v.Wipe()
		return
	}
	t.mu.Lock()
	old, ok := t.tokens[id]
	if ok {
		v.Wipe()
		changed := ended && !old.ended
		if expires.After(old.expires) {
			old.expires = expires
		}
		old.ended = old.ended || ended
		if old.agent == "" {
			old.agent = agent
		}
		t.tokens[id] = old
		t.mu.Unlock()
		if changed && t.onChange != nil {
			t.onChange()
		}
		return
	}
	// shared is set so this replica does not share the token back.
	t.tokens[id] = sessionToken{v: v, expires: expires, agent: agent, ended: ended, shared: expires}
	t.mu.Unlock()
	if t.onChange != nil {
		t.onChange()
	}
}

// end marks a session revoked: it leaves the redaction scopes, its token
// stays until it expires.
func (t *sessionTokens) end(id string) {
	t.mu.Lock()
	old, ok := t.tokens[id]
	changed := ok && !old.ended
	if changed {
		old.ended = true
		t.tokens[id] = old
	}
	t.mu.Unlock()
	if changed && t.onChange != nil {
		t.onChange()
	}
}

// prune wipes expired tokens and reports whether any went.
func (t *sessionTokens) prune() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	gone := false
	for id, tok := range t.tokens {
		if !now.Before(tok.expires) {
			tok.v.Wipe()
			delete(t.tokens, id)
			gone = true
		}
	}
	return gone
}

// sessionsByAgent lists the ids of the unexpired sessions held that were
// not revoked, by agent.
func (t *sessionTokens) sessionsByAgent() map[string][]string {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	out := map[string][]string{}
	for id, tok := range t.tokens {
		if tok.agent != "" && !tok.ended && now.Before(tok.expires) {
			out[tok.agent] = append(out[tok.agent], id)
		}
	}
	return out
}

// EachValue implements ValueSource. Tokens carry no reference: they are
// redacted and never injected.
func (t *sessionTokens) EachValue(fn func(refresh.Source, secret.Value)) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, tok := range t.tokens {
		fn(refresh.Source{}, tok.v)
	}
}

func (t *sessionTokens) close() {
	t.mu.Lock()
	defer t.mu.Unlock()
	for id, tok := range t.tokens {
		tok.v.Wipe()
		delete(t.tokens, id)
	}
}
