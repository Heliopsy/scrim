// SPDX-License-Identifier: AGPL-3.0-only

package agentstore

import (
	"context"
	"errors"
	"maps"
	"slices"

	"github.com/heliopsy/scrim/internal/identity"
	"github.com/heliopsy/scrim/internal/stores"
)

// ReadAgents lists, sorted, the agents with a static credential for store
// (identity.store-credentials). It implements redactscope.AgentReader for
// the weakening setting redaction.limit-to-agent-identity. Kubernetes
// passthrough is left out: scrim holds a pod's token only while one of its
// requests is in flight, so it cannot check that identity in between.
func (c *Checker) ReadAgents(store string) []string {
	if c == nil {
		return nil
	}
	return slices.Sorted(maps.Keys(c.statics[store]))
}

// AgentCanRead reports whether agent's static credential for ref's store
// may read ref, asking the store as that agent ([stores.AgentAccess]). A
// refusal by the store is (false, nil); any other failure is an error, and
// the caller treats the value as readable (still redacted).
func (c *Checker) AgentCanRead(ctx context.Context, agent string, ref stores.Ref) (bool, error) {
	// Not a Kubernetes caller, so Source picks the static credential, never
	// passthrough; the principal is the agent's name.
	id := identity.Identity{Agent: agent, Source: identity.SourcePeer}
	_, err := c.Check(ctx, id, nil, stores.OpRead, ref)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, stores.ErrPermission):
		return false, nil
	default:
		return false, err
	}
}
