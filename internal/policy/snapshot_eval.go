// SPDX-License-Identifier: AGPL-3.0-only

package policy

import (
	"fmt"
	"strconv"
	"strings"
)

// Outcome is what the data plane does with a request after evaluating the
// snapshot.
type Outcome uint8

// Data-plane outcomes.
const (
	// OutcomeDeny refuses the request locally.
	OutcomeDeny Outcome = iota + 1
	// OutcomeAllow lets the request through locally.
	OutcomeAllow
	// OutcomeControlPlane sends the request to the control plane over the
	// "ask" call. The control plane evaluates the full rule set, checks
	// grants and raises an approval if needed.
	OutcomeControlPlane
)

func (o Outcome) String() string {
	switch o {
	case OutcomeDeny:
		return "deny"
	case OutcomeAllow:
		return "allow"
	case OutcomeControlPlane:
		return "control_plane"
	}
	return "invalid"
}

// MarshalText implements encoding.TextMarshaler.
func (o Outcome) MarshalText() ([]byte, error) { return []byte(o.String()), nil }

// UnmarshalText implements encoding.TextUnmarshaler.
func (o *Outcome) UnmarshalText(b []byte) error {
	for _, v := range []Outcome{OutcomeDeny, OutcomeAllow, OutcomeControlPlane} {
		if v.String() == string(b) {
			*o = v
			return nil
		}
	}
	return fmt.Errorf("policy: unknown outcome %q", b)
}

// AskReason says why the data plane sends a request to the control plane.
type AskReason string

// Reasons for [OutcomeControlPlane].
const (
	// AskRule: a rule (or the default) decided ask.
	AskRule AskReason = "ask"
	// AskResidual: a rule the data plane cannot fully evaluate could
	// decide the outcome.
	AskResidual AskReason = "residual"
	// AskSideEffect: an allow rule with a grant TTL decided; the control
	// plane records the grant.
	AskSideEffect AskReason = "side_effect"
)

// LocalResult is the data plane's decision for a request.
type LocalResult struct {
	Outcome Outcome `json:"outcome"`
	// Rule names the deciding rule, or the rule that forced the control
	// plane call; [DefaultRule] when no rule matched.
	Rule string `json:"rule,omitempty"`
	// Default is set when no rule matched.
	Default bool `json:"default,omitempty"`
	// Ask is set when Outcome is OutcomeControlPlane.
	Ask AskReason `json:"ask,omitempty"`
	// DenyAll is set when the break-glass switch decided.
	DenyAll bool `json:"deny_all,omitempty"`
}

// tri is a three-valued truth value, mirroring CEL's treatment of errors in
// && and ||, extended with unknown for residual parts.
type tri uint8

const (
	triFalse tri = iota
	triTrue
	triError
	triUnknown
)

// Evaluate is the reference data-plane evaluator. The data plane decides
// locally only when the result is certain to equal the control plane's full
// CEL evaluation: same decision and same deciding rule.
//
// Algorithm:
//
//  1. If DenyAll is set, deny.
//  2. Evaluate each rule to match, no-match or unknown. A condition on a
//     missing map key is an error; errors combine as in CEL (false && error
//     is false, true || error is true). A rule that errors counts as a match
//     if it denies or asks and as no match if it allows.
//  3. For each decision level in precedence order (deny, ask, allow), take
//     the first rule in order at that level that is not a no-match. If it is
//     unknown, send to the control plane (residual). Otherwise it decides:
//     deny locally; ask goes to the control plane; allow is local unless the
//     rule has side effects.
//  4. No rule matched: apply the default (ask goes to the control plane).
func (s *Snapshot) Evaluate(req Request) LocalResult {
	v := newView(&req)
	if s.DenyAll {
		return LocalResult{Outcome: OutcomeDeny, DenyAll: true}
	}
	status := make([]tri, len(s.Rules))
	for i := range s.Rules {
		r := &s.Rules[i]
		st := r.eval(&v)
		if st == triError {
			if r.Decision == Allow {
				st = triFalse
			} else {
				st = triTrue
			}
		}
		status[i] = st
	}
	for _, level := range []Effect{Deny, Ask, Allow} {
		for i := range s.Rules {
			r := &s.Rules[i]
			if r.Decision != level || status[i] == triFalse {
				continue
			}
			if status[i] == triUnknown {
				return LocalResult{Outcome: OutcomeControlPlane, Rule: r.Name, Ask: AskResidual}
			}
			switch {
			case level == Deny:
				return LocalResult{Outcome: OutcomeDeny, Rule: r.Name}
			case level == Ask:
				return LocalResult{Outcome: OutcomeControlPlane, Rule: r.Name, Ask: AskRule}
			case r.ControlPlane:
				return LocalResult{Outcome: OutcomeControlPlane, Rule: r.Name, Ask: AskSideEffect}
			default:
				return LocalResult{Outcome: OutcomeAllow, Rule: r.Name}
			}
		}
	}
	switch s.Default {
	case Allow:
		return LocalResult{Outcome: OutcomeAllow, Rule: DefaultRule, Default: true}
	case Ask:
		return LocalResult{Outcome: OutcomeControlPlane, Rule: DefaultRule, Default: true, Ask: AskRule}
	default:
		return LocalResult{Outcome: OutcomeDeny, Rule: DefaultRule, Default: true}
	}
}

func (r *SnapshotRule) eval(req *view) tri {
	out := triFalse
	for i := range r.Clauses {
		switch r.Clauses[i].eval(req) {
		case triTrue:
			return triTrue
		case triUnknown:
			out = triUnknown
		case triError:
			if out != triUnknown {
				out = triError
			}
		}
	}
	return out
}

func (c *Clause) eval(req *view) tri {
	out := triTrue
	for i := range c.Conditions {
		switch c.Conditions[i].eval(req) {
		case triFalse:
			return triFalse
		case triError:
			out = triError
		}
	}
	if c.Residual {
		return triUnknown
	}
	return out
}

func (c *Condition) eval(req *view) tri {
	var v string
	if kind, known := SnapshotFields[c.Field]; !known {
		return triError
	} else if kind == kindMap {
		m := mapField(req, c.Field)
		val, has := m[c.Key]
		if c.Op == OpHasKey {
			return boolTri(has != c.Negate)
		}
		if !has {
			return triError
		}
		v = val
	} else {
		v = scalarField(req, c.Field)
	}
	var b bool
	switch c.Op {
	case OpIn:
		for _, x := range c.Values {
			if x == v {
				b = true
				break
			}
		}
	case OpPrefix, OpSuffix, OpContains, OpGlob:
		if len(c.Values) != 1 {
			return triError
		}
		switch c.Op {
		case OpPrefix:
			b = strings.HasPrefix(v, c.Values[0])
		case OpSuffix:
			b = strings.HasSuffix(v, c.Values[0])
		case OpContains:
			b = strings.Contains(v, c.Values[0])
		default:
			toks, err := compileGlob(c.Values[0])
			if err != nil {
				return triError
			}
			b = globMatch(toks, []rune(v))
		}
	default:
		return triError
	}
	return boolTri(b != c.Negate)
}

func boolTri(b bool) tri {
	if b {
		return triTrue
	}
	return triFalse
}

func mapField(v *view, f string) map[string]string {
	switch f {
	case "agent.labels":
		return v.agent.Labels
	case "secret.labels":
		return v.secret.Labels
	}
	return nil
}

func scalarField(v *view, f string) string {
	switch f {
	case "op":
		return v.op
	case "provider":
		return v.provider
	case "agent.id":
		return v.agent.ID
	case "agent.kind":
		return v.agent.Kind
	case "agent.known":
		return strconv.FormatBool(v.agent.Known)
	case "agent.session":
		return v.agent.Session
	case "secret.ref":
		return v.secret.Ref
	case "secret.name":
		return v.secret.Name
	case "secret.store":
		return v.secret.Store
	case "secret.class":
		return v.secret.Class
	case "dest.host":
		return v.dest.Host
	case "dest.method":
		return v.dest.Method
	case "dest.path":
		return v.dest.Path
	case "tool.name":
		return v.tool.Name
	case "tool.command":
		return v.tool.Command
	}
	return ""
}
