// SPDX-License-Identifier: AGPL-3.0-only

package policy

import (
	"errors"
	"fmt"
	"regexp"
	"time"
)

// Config is the `policy` section of the configuration: an ordered list of
// rules and the decision applied when none matches.
type Config struct {
	// Default applies when no rule matches: allow, ask or deny. Empty
	// means the policy.default setting, whose shipped value is deny.
	Default string `json:"default,omitempty" yaml:"default"`
	// Rules are evaluated in order; see [Engine.Evaluate] for how matches
	// combine.
	Rules []RuleSpec `json:"rules" yaml:"rules"`
}

// RuleSpec is one policy rule as configured.
type RuleSpec struct {
	// Name identifies the rule in audit entries, approvals and metrics. It is
	// required and unique.
	Name string `json:"name" yaml:"name"`
	// Description is free text for operators.
	Description string `json:"description,omitempty" yaml:"description"`
	// When is a CEL expression over the request that must evaluate to a
	// bool. Empty means the rule matches every request.
	When string `json:"when,omitempty" yaml:"when"`
	// Decision is what the rule yields when it matches: allow, ask or deny.
	// It is required.
	Decision string `json:"decision" yaml:"decision"`
	// Reason is shown to the approver and recorded in audit. It must not
	// contain a secret value; it is static text from configuration.
	Reason string `json:"reason,omitempty" yaml:"reason"`
	// Approval tunes the approval raised by an ask rule.
	Approval ApprovalSettings `json:"approval,omitzero" yaml:"approval"`
	// Grant controls the just-in-time grant created when an ask rule is
	// approved, or when an allow rule should leave a grant behind.
	Grant GrantSettings `json:"grant,omitzero" yaml:"grant"`
}

// ApprovalSettings are per-rule approval options.
type ApprovalSettings struct {
	// Timeout overrides approvals.timeout for this rule.
	Timeout Duration `json:"timeout,omitzero" yaml:"timeout"`
	// Notifiers names the notifiers to use; empty means all configured.
	Notifiers []string `json:"notifiers,omitempty" yaml:"notifiers"`
}

// GrantSettings are per-rule grant options.
type GrantSettings struct {
	// TTL is the grant duration when the approver does not choose one. For
	// an allow rule a non-zero TTL means "allow with a duration": the first
	// matching request leaves a grant behind.
	TTL Duration `json:"ttl,omitzero" yaml:"ttl"`
	// MaxTTL caps any duration an approver asks for. Zero means
	// grants.max-ttl.
	MaxTTL Duration `json:"max_ttl,omitzero" yaml:"max_ttl"`
	// Uses limits how many operations the grant lets through; zero means
	// unlimited within its TTL.
	Uses int `json:"uses,omitempty" yaml:"uses"`
	// Scope selects which later requests the grant covers.
	Scope GrantScope `json:"scope,omitempty" yaml:"scope"`
}

// GrantScope selects what a grant created by a rule covers. Every scope is
// bound to one agent identity and one secret reference.
type GrantScope string

// Grant scopes.
const (
	// ScopeRequest covers the destination host and tool of the approved
	// request. This is the default.
	ScopeRequest GrantScope = "request"
	// ScopeHost covers the destination host from any tool.
	ScopeHost GrantScope = "host"
	// ScopeSecret covers every operation on the reference that policy would
	// otherwise send to ask.
	ScopeSecret GrantScope = "secret"
)

// Valid reports whether s is a known scope or empty.
func (s GrantScope) Valid() bool {
	switch s {
	case "", ScopeRequest, ScopeHost, ScopeSecret:
		return true
	}
	return false
}

// Duration is a time.Duration that reads and writes Go duration strings
// ("30m", "1h30m") in configuration files.
type Duration time.Duration

// D returns the value as a time.Duration.
func (d Duration) D() time.Duration { return time.Duration(d) }

// MarshalText implements encoding.TextMarshaler.
func (d Duration) MarshalText() ([]byte, error) { return []byte(time.Duration(d).String()), nil }

// UnmarshalText implements encoding.TextUnmarshaler.
func (d *Duration) UnmarshalText(b []byte) error {
	v, err := time.ParseDuration(string(b))
	if err != nil {
		return fmt.Errorf("policy: invalid duration %q: %w", b, err)
	}
	if v < 0 {
		return fmt.Errorf("policy: negative duration %q", b)
	}
	*d = Duration(v)
	return nil
}

var ruleNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)

// RuleError describes why one rule is invalid.
type RuleError struct {
	Index int
	Name  string
	Err   error
}

func (e *RuleError) Error() string {
	if e.Name != "" {
		return fmt.Sprintf("policy rule %d (%s): %v", e.Index, e.Name, e.Err)
	}
	return fmt.Sprintf("policy rule %d: %v", e.Index, e.Err)
}

func (e *RuleError) Unwrap() error { return e.Err }

// validateShape checks everything about the config except the expressions.
func (c *Config) validateShape() ([]Effect, error) {
	var errs []error
	if c.Default != "" {
		if _, err := ParseEffect(c.Default); err != nil {
			errs = append(errs, fmt.Errorf("policy default: %w", err))
		}
	}
	effects := make([]Effect, len(c.Rules))
	seen := map[string]int{}
	for i, r := range c.Rules {
		add := func(err error) { errs = append(errs, &RuleError{Index: i, Name: r.Name, Err: err}) }
		switch {
		case r.Name == "":
			add(errors.New("name is required"))
		case !ruleNamePattern.MatchString(r.Name):
			add(fmt.Errorf("name %q must be lower-case letters, digits, '.', '_' or '-'", r.Name))
		default:
			if j, dup := seen[r.Name]; dup {
				add(fmt.Errorf("name %q already used by rule %d", r.Name, j))
			}
			seen[r.Name] = i
		}
		eff, err := ParseEffect(r.Decision)
		if err != nil {
			add(errors.New("decision is required (allow, ask or deny)"))
		}
		effects[i] = eff
		if !r.Grant.Scope.Valid() {
			add(fmt.Errorf("grant.scope %q is not request, host or secret", r.Grant.Scope))
		}
		if r.Grant.Uses < 0 {
			add(errors.New("grant.uses must not be negative"))
		}
		if r.Grant.MaxTTL != 0 && r.Grant.TTL > r.Grant.MaxTTL {
			add(fmt.Errorf("grant.ttl %s exceeds grant.max_ttl %s", r.Grant.TTL.D(), r.Grant.MaxTTL.D()))
		}
		if err == nil && eff == Deny && (r.Grant != GrantSettings{} || r.Approval.Timeout != 0 || len(r.Approval.Notifiers) > 0) {
			add(errors.New("a deny rule takes no grant or approval settings"))
		}
		if err == nil && eff == Allow && (r.Approval.Timeout != 0 || len(r.Approval.Notifiers) > 0) {
			add(errors.New("an allow rule takes no approval settings"))
		}
	}
	return effects, errors.Join(errs...)
}
