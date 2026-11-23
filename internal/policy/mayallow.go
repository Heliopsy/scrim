// SPDX-License-Identifier: AGPL-3.0-only

package policy

import (
	"strings"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/common/types"
)

// MayAllow reports whether req could end in allow or ask once the attributes
// named in unknown are known. An attribute is a variable and one field,
// "ssh.user". It decides what to offer (which ssh-agent keys to list), never
// whether an operation proceeds: that is [RuleSet.Evaluate] on the complete
// request.
//
// A rule whose outcome depends on an unknown attribute counts as matching
// when it allows or asks and as not matching when it denies, so a key is
// listed when some later request could use it. A rule that fails counts as in
// Evaluate (matching when it denies or asks).
func (rs *RuleSet) MayAllow(req Request, unknown ...string) bool {
	env, err := Env()
	if err != nil {
		return false
	}
	patterns := make([]*cel.AttributePatternType, 0, len(unknown))
	for _, u := range unknown {
		v, f, ok := strings.Cut(u, ".")
		if !ok || v == "" || f == "" {
			return false
		}
		patterns = append(patterns, cel.AttributePattern(v).QualString(f))
	}
	view := newView(&req)
	vars, err := cel.PartialVars(view.activation(), patterns...)
	if err != nil {
		return false
	}
	var best *compiledRule
	for i := range rs.rules {
		cr := &rs.rules[i]
		matched := true
		if cr.ast != nil {
			matched = cr.mayMatch(env, vars)
		}
		if matched && (best == nil || cr.effect.strength() > best.effect.strength()) {
			best = cr
		}
	}
	if best == nil {
		return rs.def != Deny
	}
	return best.effect != Deny
}

// mayMatch evaluates the rule with some attributes unknown.
func (cr *compiledRule) mayMatch(env *cel.Env, vars any) bool {
	prg, err := env.Program(cr.ast, cel.CostLimit(costLimit), cel.EvalOptions(cel.OptPartialEval),
		cel.InterruptCheckFrequency(100))
	if err != nil {
		return cr.effect != Allow
	}
	out, _, err := prg.Eval(vars)
	switch {
	case err != nil:
		return cr.effect != Allow
	case types.IsUnknown(out):
		return cr.effect != Deny
	}
	b, ok := out.Value().(bool)
	if !ok {
		return cr.effect != Allow
	}
	return b
}

// MayAllow is [RuleSet.MayAllow] with the rule set in force.
func (l *Live) MayAllow(req Request, unknown ...string) bool {
	return l.cur.Load().MayAllow(req, unknown...)
}
