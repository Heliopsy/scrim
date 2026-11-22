// SPDX-License-Identifier: AGPL-3.0-only

package policy

import (
	"testing"

	"github.com/heliopsy/scrim/internal/stores"
)

// TestUnknownSecretLabels: with secret.labels unknown, a rule whose outcome
// depends on them errors (deny and ask match, allow does not), and a rule
// decided without them is evaluated as usual.
func TestUnknownSecretLabels(t *testing.T) {
	cases := []struct {
		when, decision string
		want           Effect
		errs           bool
	}{
		{`"vaultwarden.org" in secret.labels`, "deny", Deny, true},
		{`has(secret.labels.team)`, "ask", Ask, true},
		{`secret.labels["store.kind"] == "openbao"`, "deny", Deny, true},
		{`secret.labels.team == "x"`, "allow", Allow + 100, true}, // allow: not matching
		{`op == "inject" && "x" in secret.labels`, "deny", Allow + 100, false},
		{`op == "store.write" || "x" in secret.labels`, "deny", Deny, false},
		{`secret.ref.startsWith("vw://")`, "deny", Deny, false},
	}
	for _, c := range cases {
		rs, err := Compile(Config{Default: "allow", Rules: []RuleSpec{{Name: "r", Decision: c.decision, When: c.when}}})
		if err != nil {
			t.Fatal(err)
		}
		req := Request{Action: ActionWrite, Ref: stores.MustParseRef("vw://a/b"), SecretLabelsUnknown: true,
			SecretLabels: map[string]string{"vaultwarden.org": "Acme", "team": "x", "x": "1", "store.kind": "openbao"}}
		res := rs.Evaluate(req)
		want := c.want
		if want == Allow+100 {
			if res.Rule != DefaultRule {
				t.Errorf("%s: decided by %s, want the default", c.when, res.Rule)
			}
		} else if res.Effect != want || res.Rule != "r" {
			t.Errorf("%s: %+v, want %v by r", c.when, res, want)
		}
		if (len(res.Errors) > 0) != c.errs {
			t.Errorf("%s: errors %v, want %v", c.when, res.Errors, c.errs)
		}
		req.SecretLabelsUnknown = false
		if res := rs.Evaluate(req); len(res.Errors) > 0 {
			t.Errorf("%s with known labels: %v", c.when, res.Errors)
		}
	}
}
