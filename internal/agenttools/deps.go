// SPDX-License-Identifier: AGPL-3.0-only

package agenttools

import (
	"context"
	"errors"
	"time"

	"github.com/heliopsy/scrim/internal/identity"
	"github.com/heliopsy/scrim/internal/secret"
)

// The interfaces below are what the service needs from the rest of the
// control plane. They are deliberately small so the policy engine, the
// approval service, the store adapters and the audit log can each satisfy
// one with a thin adapter.

// Operation is one thing a caller wants to do with a secret.
type Operation struct {
	Tool  string
	Ref   string
	Store string
}

// Effect is a policy decision.
type Effect string

// The decisions policy can reach.
const (
	EffectAllow Effect = "allow"
	EffectDeny  Effect = "deny"
	// EffectAsk means a human must approve first. For tools other than
	// secret_request the caller is told to request a grant, and policy is
	// expected to answer allow once one exists.
	EffectAsk Effect = "ask"
)

// Decision is the outcome of evaluating policy for one operation.
type Decision struct {
	Effect Effect
	// Reason is a short, value-free explanation, shown to the caller on deny.
	Reason string
	// Rule names the rule that decided, for audit.
	Rule string
}

// Policy decides operations other than secret_request, which the approval
// service decides.
type Policy interface {
	Decide(ctx context.Context, id identity.Identity, op Operation) (Decision, error)
}

// GrantRequest is a request for a just-in-time grant.
type GrantRequest struct {
	Ref string
	// Duration is the requested duration, zero for the policy default.
	Duration time.Duration
	Reason   string
}

// GrantResult is what the approval service decided about a GrantRequest.
type GrantResult struct {
	Status     string // StatusGranted, StatusDenied or StatusPending
	ApprovalID string
	GrantID    string
	ExpiresAt  time.Time
	Duration   time.Duration
	Capped     bool
	Reason     string
}

// ApprovalState is the state of one approval.
type ApprovalState struct {
	Status    string // Approval* constants
	Ref       string
	GrantID   string
	ExpiresAt time.Time
}

// Approvals is the approval and grant service. It evaluates policy for
// requests, holds pending approvals and owns grants. Every method is scoped
// to the identity's principal: an approval or grant of another principal is
// reported as ErrNotFound, never as forbidden, so its existence is not
// revealed.
type Approvals interface {
	Request(ctx context.Context, id identity.Identity, req GrantRequest) (GrantResult, error)
	Approval(ctx context.Context, id identity.Identity, approvalID string) (ApprovalState, error)
	Grants(ctx context.Context, id identity.Identity) ([]Grant, error)
}

// Catalog lists secret metadata. It returns candidates; the service filters
// them through policy before the caller sees any.
type Catalog interface {
	List(ctx context.Context, id identity.Identity, filter ListInput) ([]SecretInfo, error)
}

// Write is one value to store.
type Write struct {
	Ref       string
	Store     string
	Value     secret.Value
	Overwrite bool
}

// Written is where a value went.
type Written struct {
	Ref         string
	Store       string
	Placeholder string
}

// Store writes values. The implementation resolves the store, writes with the
// agent's store identity where one is configured, adds the value to the
// redaction set and returns the placeholder. It never reads a value back for
// the caller. Errors must not contain the value; the service withholds any
// error text that does.
type Store interface {
	Write(ctx context.Context, id identity.Identity, w Write) (Written, error)
}

// WriteAccess checks, after scrim's rules allowed a write, that the
// caller's own store identity may make it (specs/agent-identity "Agent
// writes are checked as the agent"). A nil WriteAccess writes with scrim's
// own store identity once the rules allow it.
type WriteAccess interface {
	// CheckWrite returns how the write was checked, a *WriteRefusedError
	// when the store or scrim's identity settings refuse it, and any other
	// error when the check itself failed.
	CheckWrite(ctx context.Context, id identity.Identity, op Operation) (WriteCheck, error)
}

// WriteCheck records how a write was checked, for audit: which store
// identity (agentstore source: static, federated, kubernetes, shared, none)
// and how (checked, unchecked, skipped, shared).
type WriteCheck struct {
	Identity string
	Check    string
}

// WriteRefusedError is a write the agent's own store identity may not make.
// Reason names the store, reference and cause, never a value; it is shown to
// the caller.
type WriteRefusedError struct{ Reason string }

func (e *WriteRefusedError) Error() string {
	return "refused by the agent's store identity: " + e.Reason
}

// ErrExists is returned by a Store when the reference already holds a value
// and Overwrite is false.
var ErrExists = errors.New("agenttools: a secret already exists at the reference")

// ErrNotFound is returned for an approval, grant or ask the caller does not
// own or that does not exist.
var ErrNotFound = errors.New("agenttools: not found")

// AuditEntry records one tool call. It has no field for a value.
type AuditEntry struct {
	Time       time.Time `json:"time"`
	Agent      string    `json:"agent,omitempty"`
	Principal  string    `json:"principal,omitempty"`
	Source     string    `json:"source"`
	SessionID  string    `json:"session_id,omitempty"`
	UID        uint32    `json:"uid"`
	PID        int32     `json:"pid,omitempty"`
	Tool       string    `json:"tool"`
	Ref        string    `json:"ref,omitempty"`
	Store      string    `json:"store,omitempty"`
	Decision   string    `json:"decision,omitempty"`
	Rule       string    `json:"rule,omitempty"`
	Outcome    string    `json:"outcome"`
	ApprovalID string    `json:"approval_id,omitempty"`
	GrantID    string    `json:"grant_id,omitempty"`
	// Detail is a short, value-free note such as a refusal reason.
	Detail string `json:"detail,omitempty"`
	// StoreIdentity and WriteCheck say how a write was checked against the
	// agent's own store identity ([WriteCheck]).
	StoreIdentity string `json:"store_identity,omitempty"`
	WriteCheck    string `json:"store_write_check,omitempty"`
}

// Audit outcomes.
const (
	OutcomeOK       = "ok"
	OutcomeDenied   = "denied"
	OutcomePending  = "pending"
	OutcomeError    = "error"
	OutcomeDeclined = "declined"
	OutcomeTimedOut = "timed_out"
	OutcomeRefused  = "refused"
)

// Auditor records audit entries.
type Auditor interface {
	Record(ctx context.Context, e AuditEntry) error
}

// Notice asks a human to enter a value. URL is the one-time entry link; it is
// a credential for that one entry and goes only to the configured notifiers,
// never to the agent.
type Notice struct {
	AskID     string
	Agent     string
	Ref       string
	Prompt    string
	URL       string
	ExpiresAt time.Time
}

// Notifier delivers a Notice to a human.
type Notifier interface {
	NotifyAsk(ctx context.Context, n Notice) error
}

// EntryLinks builds the entry page URL for a one-time token.
type EntryLinks interface {
	EntryURL(token string) (string, error)
}
