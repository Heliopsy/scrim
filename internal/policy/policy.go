// SPDX-License-Identifier: AGPL-3.0-only

// Package policy holds the decision types and the [Engine] contract
// (specs/policy-approvals, design D7).
//
// An engine answers one question: may this [Request] proceed? The answer is a
// [Decision] with an [Effect] of allow, deny or ask. The zero Effect is
// [Deny], so a decision nobody filled in fails closed. When several rules
// match, deny wins over ask and ask over allow ([Combine]). The rule
// language (CEL) compiles to an Engine; this package ships [Static] and
// [Rules] for wiring and tests.
package policy

import (
	"context"
	"fmt"
	"time"

	"github.com/heliopsy/scrim/internal/stores"
)

// Effect is what a decision does.
type Effect uint8

// Effects. Deny is the zero value on purpose.
const (
	Deny Effect = iota
	Ask
	Allow
)

func (e Effect) String() string {
	switch e {
	case Deny:
		return "deny"
	case Ask:
		return "ask"
	case Allow:
		return "allow"
	}
	return fmt.Sprintf("effect(%d)", e)
}

// ParseEffect parses "allow", "deny" or "ask".
func ParseEffect(s string) (Effect, error) {
	switch s {
	case "deny":
		return Deny, nil
	case "ask":
		return Ask, nil
	case "allow":
		return Allow, nil
	}
	return Deny, fmt.Errorf("policy: unknown effect %q (want allow, deny or ask)", s)
}

// MarshalText implements encoding.TextMarshaler.
func (e Effect) MarshalText() ([]byte, error) { return []byte(e.String()), nil }

// UnmarshalText implements encoding.TextUnmarshaler.
func (e *Effect) UnmarshalText(b []byte) error {
	v, err := ParseEffect(string(b))
	*e = v
	return err
}

// strength orders effects for combination: deny > ask > allow.
func (e Effect) strength() int {
	switch e {
	case Allow:
		return 0
	case Ask:
		return 1
	}
	return 2
}

// IdentityKind says how an agent was identified (specs/agent-identity).
type IdentityKind string

// Identity kinds.
const (
	IdentityUnknown IdentityKind = ""
	IdentityPeer    IdentityKind = "peer"    // Unix socket peer credentials
	IdentitySession IdentityKind = "session" // session token from `scrim run`
	IdentityK8s     IdentityKind = "k8s"     // Kubernetes service account token
	IdentityMTLS    IdentityKind = "mtls"    // client certificate
)

// Agent identifies the caller. It is metadata and safe to log.
type Agent struct {
	// ID is the stable identity rules match on, such as
	// "uid:1000/claude-code" or "k8s:agents/reviewer".
	ID string
	// Kind says how ID was established.
	Kind IdentityKind
	// Session is the scrim session the call belongs to, if any.
	Session string
	// Labels are extra attributes (profile, namespace, pod).
	Labels map[string]string
}

// Action is the kind of operation being decided.
type Action string

// Actions.
const (
	ActionForward  Action = "llm.forward"   // send a request to a model provider
	ActionInject   Action = "inject"        // put a credential on an outbound connection
	ActionRestore  Action = "restore"       // resolve a placeholder into a tool argument
	ActionRead     Action = "store.read"    // read a value from a store
	ActionWrite    Action = "store.write"   // write or capture a value into a store
	ActionGenerate Action = "secret.gen"    // generate a new value
	ActionGrant    Action = "grant"         // create a just-in-time grant
	ActionExec     Action = "exec"          // run a command through the exec broker
	ActionTool     Action = "mcp.tool"      // call an agent tool
	ActionAskHuman Action = "secret.ask"    // ask a human to enter a value
	ActionSign     Action = "ssh.sign"      // sign with an ssh-agent key
	ActionDatabase Action = "database.auth" // authenticate a database connection
)

// Request is everything a rule may look at. Fields that do not apply are
// left empty. It never holds a value.
type Request struct {
	Agent  Agent
	Action Action
	// Ref is the secret involved, if any.
	Ref stores.Ref
	// Name is the catalog name of the secret, if it has one.
	Name string
	// Store is the store instance name.
	Store string
	// SecretClass is the catalog class of the secret (credential, display),
	// if the catalog declares one.
	SecretClass string
	// SecretLabels are catalog or store metadata labels of the secret. They
	// are metadata and safe to log; a store adapter must never copy a value
	// into them.
	SecretLabels map[string]string
	// Provider is the model provider ("anthropic", "openai").
	Provider string
	// Host, Method and Path describe the destination.
	Host   string
	Method string
	Path   string
	// Tool is the agent tool or command name; Command its argv[0].
	Tool    string
	Command string
	// Time is when the request was made; zero means now.
	Time time.Time
}

// Decision is an engine's answer.
type Decision struct {
	Effect Effect
	// Rule names the rule that decided, or "default".
	Rule string
	// Reason is a human-readable explanation, shown in approvals and audit.
	// It must not contain a value.
	Reason string
	// GrantTTL, for an allow or an approved ask, is how long a grant may
	// last; zero means no grant is created.
	GrantTTL time.Duration
}

// Allowed reports whether the decision lets the request proceed now.
func (d Decision) Allowed() bool { return d.Effect == Allow }

// Engine decides requests. Implementations must be safe for concurrent use
// and must not block on I/O for allow and deny. An error means the request
// is denied; callers must treat it exactly like a [Deny] decision.
type Engine interface {
	Decide(ctx context.Context, req Request) (Decision, error)
}

// Combine returns the strongest decision: deny over ask over allow. An empty
// list yields a zero (deny) decision.
func Combine(ds ...Decision) Decision {
	var out Decision
	for i, d := range ds {
		if i == 0 || d.Effect.strength() > out.Effect.strength() {
			out = d
		}
	}
	return out
}

// Static is an engine that gives every request the same decision. The
// shipped default is Static{Effect: Deny}.
type Static struct {
	Effect Effect
	Reason string
}

// Decide implements [Engine].
func (s Static) Decide(context.Context, Request) (Decision, error) {
	reason := s.Reason
	if reason == "" {
		reason = "no rule matched; default is " + s.Effect.String()
	}
	return Decision{Effect: s.Effect, Rule: "default", Reason: reason}, nil
}

// Rule is one compiled rule.
type Rule struct {
	Name     string
	Match    func(Request) bool
	Effect   Effect
	Reason   string
	GrantTTL time.Duration
}

// Rules evaluates every rule, combines the matches with [Combine] and falls
// back to Default when none match.
type Rules struct {
	List    []Rule
	Default Static
}

// Decide implements [Engine].
func (r Rules) Decide(ctx context.Context, req Request) (Decision, error) {
	var matched []Decision
	for _, rule := range r.List {
		if rule.Match != nil && rule.Match(req) {
			matched = append(matched, Decision{Effect: rule.Effect, Rule: rule.Name, Reason: rule.Reason, GrantTTL: rule.GrantTTL})
		}
	}
	if len(matched) == 0 {
		return r.Default.Decide(ctx, req)
	}
	return Combine(matched...), nil
}

// BreakGlass wraps an engine with the deny-all switch: while Active returns
// true every request is denied, whatever the rules say.
type BreakGlass struct {
	Engine Engine
	Active func() bool
}

// Decide implements [Engine].
func (b BreakGlass) Decide(ctx context.Context, req Request) (Decision, error) {
	if b.Active != nil && b.Active() {
		return Decision{Effect: Deny, Rule: "break-glass", Reason: "break-glass deny-all is active"}, nil
	}
	return b.Engine.Decide(ctx, req)
}
