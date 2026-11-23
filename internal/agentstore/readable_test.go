// SPDX-License-Identifier: AGPL-3.0-only

package agentstore

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/heliopsy/scrim/internal/redactscope"
	"github.com/heliopsy/scrim/internal/stores/memstore"
)

var _ redactscope.AgentReader = (*Checker)(nil)

// TestReadAgentsAndAgentCanRead: the agents with a static credential are
// checked with it, never with Kubernetes passthrough; a store refusal is
// "cannot read", anything else is an error.
func TestReadAgentsAndAgentCanRead(t *testing.T) {
	f := &fakeStore{Adapter: memstore.New("bao"), allow: map[string]string{"tok-A": "kv/agents/a/", "agents-agent-a": "kv/"}}
	c := newChecker(t, map[string]string{"bao": "kubernetes role:{namespace}-{service_account}"},
		map[string]string{"bao/agent-a": "env:A", "bao/agent-b": "env:B"}, f)
	ctx := context.Background()
	if got := c.ReadAgents("bao"); !slices.Equal(got, []string{"agent-a", "agent-b"}) {
		t.Fatalf("ReadAgents(bao) = %v", got)
	}
	if got := c.ReadAgents("plain"); len(got) != 0 {
		t.Fatalf("ReadAgents(plain) = %v", got)
	}
	if ok, err := c.AgentCanRead(ctx, "agent-a", ref(t, "bao://kv/agents/a/x")); !ok || err != nil {
		t.Fatalf("agent-a own path: %v %v", ok, err)
	}
	if ok, err := c.AgentCanRead(ctx, "agent-a", ref(t, "bao://kv/prod/payments")); ok || err != nil {
		t.Fatalf("agent-a prod: %v %v", ok, err)
	}
	for _, g := range f.got {
		if g.Role != "" || g.Mount != "" || g.Agent != "agent-a" {
			t.Fatalf("checked with %+v, not the static credential", g)
		}
	}
	if ok, err := c.AgentCanRead(ctx, "nobody", ref(t, "bao://kv/agents/a/x")); ok || !errors.Is(err, ErrNoIdentity) {
		t.Fatalf("agent without a credential: %v %v", ok, err)
	}
	var nilChecker *Checker
	if nilChecker.ReadAgents("bao") != nil {
		t.Fatal("a nil checker lists agents")
	}
}
