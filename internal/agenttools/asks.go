// SPDX-License-Identifier: AGPL-3.0-only

package agenttools

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/heliopsy/scrim/internal/identity"
	"github.com/heliopsy/scrim/internal/secret"
)

// Ask limits.
const (
	DefaultAskTimeout = 15 * time.Minute
	MaxAskTimeout     = 24 * time.Hour
	MaxAskWait        = 10 * time.Minute
	// askRetention is how long a settled ask stays visible to approval_status.
	askRetention = time.Hour
	askIDPrefix  = "ask_"
	maxOpenAsks  = 64
)

func isAskID(id string) bool { return strings.HasPrefix(id, askIDPrefix) }

// ask is one request for a human to enter a value.
type ask struct {
	id        string
	tokenHash string
	who       identity.Identity
	ref       string
	store     string
	prompt    string
	overwrite bool
	created   time.Time
	expires   time.Time
	status    string
	claimed   bool
	settled   time.Time
	written   Written
	done      chan struct{}
}

func (a *ask) output() AskOutput {
	return AskOutput{ID: a.id, Status: a.status, Ref: a.ref, Placeholder: a.written.Placeholder, ExpiresAt: a.expires.UTC()}
}

// asks holds open and recently settled asks in memory. A restart drops them;
// the agent then sees not found, and nothing was stored.
type asks struct {
	mu      sync.Mutex
	byID    map[string]*ask
	byToken map[string]*ask
	now     func() time.Time
	rand    io.Reader
}

func newAsks(now func() time.Time, r io.Reader) *asks {
	if r == nil {
		r = rand.Reader
	}
	return &asks{byID: map[string]*ask{}, byToken: map[string]*ask{}, now: now, rand: r}
}

func tokenKey(tok string) string {
	h := sha256.Sum256([]byte("scrim entry token v1\x00" + tok))
	return hex.EncodeToString(h[:])
}

// expire settles every open ask past its expiry and forgets settled ones
// past retention. Callers hold mu.
func (r *asks) expire() {
	now := r.now()
	for id, a := range r.byID {
		if a.status == AskPending && !a.claimed && !now.Before(a.expires) {
			r.settle(a, AskTimedOut)
		}
		if a.status != AskPending && now.Sub(a.settled) > askRetention {
			delete(r.byID, id)
		}
	}
}

// settle moves a to a final status and burns its token. Callers hold mu.
func (r *asks) settle(a *ask, status string) {
	a.status, a.settled = status, r.now()
	delete(r.byToken, a.tokenHash)
	close(a.done)
}

func (r *asks) open(who identity.Identity, in AskInput, timeout time.Duration) (*ask, string, error) {
	raw := make([]byte, 32+12)
	if _, err := io.ReadFull(r.rand, raw); err != nil {
		return nil, "", Errorf(CodeInternal, "reading randomness failed")
	}
	tok := base64.RawURLEncoding.EncodeToString(raw[:32])
	id := askIDPrefix + hex.EncodeToString(raw[32:])
	secret.WipeBytes(raw)

	r.mu.Lock()
	defer r.mu.Unlock()
	r.expire()
	open := 0
	for _, a := range r.byID {
		if a.status == AskPending && a.who.Principal() == who.Principal() {
			open++
		}
	}
	if open >= maxOpenAsks {
		return nil, "", Errorf(CodeConflict, "too many open asks; wait for one to be answered")
	}
	now := r.now()
	a := &ask{id: id, tokenHash: tokenKey(tok), who: who, ref: in.Ref, store: in.Store, prompt: in.Prompt,
		overwrite: in.Overwrite, created: now, expires: now.Add(timeout), status: AskPending, done: make(chan struct{})}
	r.byID[id], r.byToken[a.tokenHash] = a, a
	return a, tok, nil
}

func (r *asks) cancel(a *ask) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.byID, a.id)
	if a.status == AskPending {
		delete(r.byToken, a.tokenHash)
	}
}

func (r *asks) status(principal, id string) (AskOutput, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.expire()
	a, ok := r.byID[id]
	if !ok || a.who.Principal() != principal {
		return AskOutput{}, Errorf(CodeNotFound, "no ask %s", id)
	}
	return a.output(), nil
}

// byTok returns the open ask for an entry token.
func (r *asks) byTok(tok string) (*ask, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.expire()
	a, ok := r.byToken[tokenKey(tok)]
	return a, ok && a.status == AskPending
}

// Ask implements secret_ask_human: it opens an ask, sends the one-time entry
// link to the configured notifiers, and waits up to in.WaitSeconds for the
// answer. The agent never receives the link, only the ask's status.
func (s *Service) Ask(ctx context.Context, id identity.Identity, in AskInput) (AskOutput, error) {
	c := s.begin(id, ToolSecretAskHuman, in.Ref, in.Store)
	out, err := s.askHuman(ctx, c, in)
	return out, c.finish(ctx, err)
}

func (s *Service) askHuman(ctx context.Context, c *call, in AskInput) (AskOutput, error) {
	if err := c.authorize(); err != nil {
		return AskOutput{}, err
	}
	if err := checkRef(in.Ref); err != nil {
		return AskOutput{}, err
	}
	if err := checkStore(in.Store); err != nil {
		return AskOutput{}, err
	}
	in.Prompt = strings.TrimSpace(in.Prompt)
	if in.Prompt == "" || len(in.Prompt) > 1024 {
		return AskOutput{}, Errorf(CodeInvalid, "prompt is required and at most 1024 bytes")
	}
	timeout := DefaultAskTimeout
	if in.TimeoutSeconds != 0 {
		timeout = time.Duration(in.TimeoutSeconds) * time.Second
	}
	if timeout <= 0 || timeout > MaxAskTimeout {
		return AskOutput{}, Errorf(CodeInvalid, "timeout_seconds must be between 1 and %d", int(MaxAskTimeout/time.Second))
	}
	wait := time.Duration(in.WaitSeconds) * time.Second
	if wait < 0 || wait > MaxAskWait {
		return AskOutput{}, Errorf(CodeInvalid, "wait_seconds must be between 0 and %d", int(MaxAskWait/time.Second))
	}
	if s.d.Notifier == nil || s.d.Links == nil {
		return AskOutput{}, Errorf(CodeUnavailable, "no notifier or entry page is configured, so no human can be asked")
	}
	if err := c.decide(ctx); err != nil {
		return AskOutput{}, err
	}
	a, tok, err := s.asks.open(c.id, in, timeout)
	if err != nil {
		return AskOutput{}, err
	}
	c.entry.ApprovalID = a.id
	url, err := s.d.Links.EntryURL(tok)
	if err != nil {
		s.asks.cancel(a)
		s.d.Logger.Error("building the entry link failed", "ask", a.id, "error", err)
		return AskOutput{}, Errorf(CodeUnavailable, "the entry page is unavailable")
	}
	n := Notice{AskID: a.id, Agent: c.id.Agent, Ref: a.ref, Prompt: a.prompt, URL: url, ExpiresAt: a.expires.UTC()}
	if err := s.d.Notifier.NotifyAsk(ctx, n); err != nil {
		s.asks.cancel(a)
		s.d.Logger.Warn("no notifier delivered the ask", "ask", a.id, "error", err)
		return AskOutput{}, Errorf(CodeUnavailable, "no notifier could reach a human; nothing was asked")
	}
	if wait > 0 {
		t := time.NewTimer(min(wait, a.expires.Sub(s.d.Now())+time.Second))
		defer t.Stop()
		select {
		case <-a.done:
		case <-t.C:
		case <-ctx.Done():
		}
	}
	out, err := s.asks.status(c.id.Principal(), a.id)
	if err != nil {
		return AskOutput{}, err
	}
	c.entry.Outcome = askOutcome(out.Status)
	return out, nil
}

func askOutcome(status string) string {
	switch status {
	case AskStored:
		return OutcomeOK
	case AskDeclined:
		return OutcomeDeclined
	case AskTimedOut:
		return OutcomeTimedOut
	default:
		return OutcomePending
	}
}

// EntryView is what the entry page shows a human. It holds no value.
type EntryView struct {
	Agent     string
	Ref       string
	Store     string
	Prompt    string
	ExpiresAt time.Time
}

// Entry returns the open ask for a one-time entry token.
func (s *Service) Entry(tok string) (EntryView, bool) {
	a, ok := s.asks.byTok(tok)
	if !ok {
		return EntryView{}, false
	}
	return EntryView{Agent: a.who.Agent, Ref: a.ref, Store: a.store, Prompt: a.prompt, ExpiresAt: a.expires.UTC()}, true
}

// SubmitAsk stores the value a human entered for an open ask. The token is
// single use: it is burned whether the write succeeds or not, so a failed
// entry needs a new ask. The value is wiped before SubmitAsk returns.
func (s *Service) SubmitAsk(ctx context.Context, tok string, v secret.Value) error {
	defer v.Wipe()
	a, err := s.claimAsk(tok)
	if err != nil {
		return err
	}
	c := s.begin(a.who, ToolSecretAskHuman, a.ref, a.store)
	c.entry.ApprovalID, c.entry.Detail = a.id, "entered"
	status := AskStored
	werr := func() error {
		if v.IsZero() {
			return Errorf(CodeInvalid, "the value is empty")
		}
		if v.Len() > MaxValueSize {
			return Errorf(CodeInvalid, "the value is larger than %d bytes", MaxValueSize)
		}
		// Policy is evaluated again at entry, so a deny-all engaged while the
		// human was typing still applies.
		if err := c.decide(ctx); err != nil {
			return err
		}
		got, err := s.write(ctx, c, Write{Ref: a.ref, Store: a.store, Value: v, Overwrite: a.overwrite})
		if err == nil {
			s.asks.mu.Lock()
			a.written = Written{Ref: got.Ref, Store: got.Store, Placeholder: got.Placeholder}
			s.asks.mu.Unlock()
		}
		return err
	}()
	if werr != nil {
		status = AskDeclined
		c.entry.Detail = "entered, not stored"
	}
	s.finishAsk(a, status)
	return c.finish(ctx, werr)
}

// DeclineAsk settles an open ask as declined.
func (s *Service) DeclineAsk(ctx context.Context, tok string) error {
	a, err := s.claimAsk(tok)
	if err != nil {
		return err
	}
	c := s.begin(a.who, ToolSecretAskHuman, a.ref, a.store)
	c.entry.ApprovalID, c.entry.Outcome, c.entry.Detail = a.id, OutcomeDeclined, "declined by the human"
	s.finishAsk(a, AskDeclined)
	return c.finish(ctx, nil)
}

// claimAsk takes an open ask off the token index so a second submission
// with the same token finds nothing.
func (s *Service) claimAsk(tok string) (*ask, error) {
	s.asks.mu.Lock()
	defer s.asks.mu.Unlock()
	s.asks.expire()
	key := tokenKey(tok)
	a, ok := s.asks.byToken[key]
	if !ok || a.status != AskPending {
		return nil, Errorf(CodeNotFound, "this entry link has been used or has expired")
	}
	delete(s.asks.byToken, key)
	a.claimed = true
	return a, nil
}

func (s *Service) finishAsk(a *ask, status string) {
	s.asks.mu.Lock()
	defer s.asks.mu.Unlock()
	if a.status == AskPending {
		a.status, a.settled = status, s.asks.now()
		close(a.done)
	}
}
