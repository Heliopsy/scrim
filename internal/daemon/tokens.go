// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"sync"
	"time"

	"github.com/heliopsy/scrim/internal/identity"
	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores/refresh"
)

// sessionTokens holds the session tokens this daemon minted, until they
// expire, so they are in the redaction set: an agent that prints its own
// SCRIM_SESSION_TOKEN never sends it to a provider. Only the hash is ever
// stored; these copies live in memory and are wiped on expiry and Close.
type sessionTokens struct {
	mu       sync.Mutex
	tokens   map[string]sessionToken
	now      func() time.Time
	onChange func()
}

type sessionToken struct {
	v       secret.Value
	expires time.Time
}

func newSessionTokens(onChange func()) *sessionTokens {
	return &sessionTokens{tokens: map[string]sessionToken{}, now: time.Now, onChange: onChange}
}

// Store implements ValueSource.
func (t *sessionTokens) Store() string { return "scrim-sessions" }

// add takes ownership of v.
func (t *sessionTokens) add(s identity.Session, v secret.Value) {
	t.mu.Lock()
	if old, ok := t.tokens[s.ID]; ok {
		old.v.Wipe()
	}
	t.tokens[s.ID] = sessionToken{v: v, expires: s.ExpiresAt}
	t.mu.Unlock()
	if t.onChange != nil {
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
