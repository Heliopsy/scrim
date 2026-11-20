// SPDX-License-Identifier: AGPL-3.0-only

package policy

import (
	"fmt"
	"strings"

	"github.com/heliopsy/scrim/internal/config"
)

// BuiltinPrefix starts the names of the rules scrim adds itself. Rules files
// may not use it.
const BuiltinPrefix = "builtin."

// BuiltinInjectRule is the name of the built-in injection rule.
const BuiltinInjectRule = BuiltinPrefix + "inject-bound"

// BuiltinInject is the built-in rule for credential injection. The data
// plane asks about an injection only after the credential's destination
// binding matched (design D5: the binding is the primary control), so a
// rule on `op == "inject"` covers exactly "toward a bound host". Without it
// the shipped default (deny) would inject nothing at all.
var BuiltinInject = config.Register(config.Spec[string]{
	Key:     "policy.builtin.inject",
	Default: "allow",
	Enum:    []string{"allow", "ask", "off"},
	Description: "Built-in rule `builtin.inject-bound` for injecting a credential toward a host it is bound to, " +
		"for an identified agent: allow, ask, or off (injection is then decided by your rules and policy.default). " +
		"Deny rules in the rules file still win.",
})

// injectWhen is the built-in rule's condition: an injection (only ever asked
// after the binding matched) for an identified caller. Unknown callers get
// no injection (specs/agent-identity "Process without a session").
const injectWhen = `op == "inject" && agent.known`

// WithBuiltins appends the built-in rules cfg turns on to c, after the rules
// from the file, and refuses file rules that use the reserved prefix.
func WithBuiltins(cfg *config.Config, c Config) (Config, error) {
	for i, r := range c.Rules {
		if strings.HasPrefix(r.Name, BuiltinPrefix) {
			return Config{}, &RuleError{Index: i, Name: r.Name, Err: fmt.Errorf("names starting with %q are reserved for built-in rules", BuiltinPrefix)}
		}
	}
	rules := append([]RuleSpec(nil), c.Rules...)
	if d := BuiltinInject.Get(cfg); d != "off" {
		rules = append(rules, RuleSpec{
			Name: BuiltinInjectRule, When: injectWhen, Decision: d,
			Description: "built-in (policy.builtin.inject): a credential may be injected toward a host its binding names",
			Reason:      "credential bound to this destination",
		})
	}
	c.Rules = rules
	return c, nil
}
