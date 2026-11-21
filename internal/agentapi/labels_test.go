// SPDX-License-Identifier: AGPL-3.0-only

package agentapi

import (
	"testing"

	"github.com/heliopsy/scrim/internal/agenttools"
	"github.com/heliopsy/scrim/internal/agenttools/agenttoolstest"
	"github.com/heliopsy/scrim/internal/policy"
	"github.com/heliopsy/scrim/internal/stores"
	"github.com/heliopsy/scrim/internal/stores/memstore"
)

// TestPolicyAdapterLabels: a write or generate to a new item is decided on
// the labels the item would get, so "any write there must ask" holds for
// items that do not exist yet.
func TestPolicyAdapterLabels(t *testing.T) {
	set := stores.NewSet()
	if err := set.Add(memstore.New("mem")); err != nil {
		t.Fatal(err)
	}
	set.SetLabeling("mem", memstore.Kind, nil)
	eng, err := policy.Compile(policy.Config{Default: "allow", Rules: []policy.RuleSpec{
		{Name: "prod-writes", Decision: "ask", When: `op in ["store.write", "secret.gen"] && "memory.top" in secret.labels && secret.labels["memory.top"] == "prod"`},
	}})
	if err != nil {
		t.Fatal(err)
	}
	p := Policy{Engine: eng, Labels: set.WriteLabels}
	id := agenttoolstest.Session("dev", "s1", 1000)
	for ref, want := range map[string]agenttools.Effect{
		"mem://prod/new":   agenttools.EffectAsk,
		"mem://dev/new":    agenttools.EffectAllow,
		"mem://prod":       agenttools.EffectAllow,
		"mem://prod/a#key": agenttools.EffectAsk,
	} {
		for _, tool := range []string{agenttools.ToolSecretPut, agenttools.ToolSecretGen} {
			d, err := p.Decide(ctx, id, agenttools.Operation{Tool: tool, Ref: ref})
			if err != nil || d.Effect != want {
				t.Errorf("%s %s: %+v %v, want %v", tool, ref, d, err, want)
			}
		}
	}
}
