// SPDX-License-Identifier: AGPL-3.0-only

package vault

import (
	"context"
	"slices"

	"github.com/heliopsy/scrim/internal/stores"
	"github.com/heliopsy/scrim/internal/stores/internal/vaultapi"
)

var (
	_ stores.AgentAccess      = (*Adapter)(nil)
	_ stores.AgentFederation  = (*Adapter)(nil)
	_ stores.SessionForgetter = (*Adapter)(nil)
)

// AgentCan implements [stores.AgentAccess]: it asks Vault, with the agent's
// own token, for that token's capabilities on the API path ref reads
// (sys/capabilities-self): <mount>/data/<path> on KV v2, <mount>/<path> on
// KV v1 and on a dynamic secrets path. The agent's token is a static one, a
// Kubernetes auth login, or a JWT auth login with an identity token scrim
// signs for the agent; the value is never read with it.
func (a *Adapter) AgentCan(ctx context.Context, cred stores.AgentCredential, op stores.Op, ref stores.Ref) error {
	loc := a.locate(ctx, ref, ref.Path)
	if loc.rest == "" {
		return a.err(op, ref, stores.ErrInvalidRef, "reference names a mount, not a secret")
	}
	p := loc.mount + "/" + loc.rest
	if loc.engine == kv2 {
		p = loc.mount + "/data/" + loc.rest
	}
	return a.c.AgentCan(ctx, a.agents, cred, op, ref, p)
}

// FederationMethods implements [stores.AgentFederation].
func (a *Adapter) FederationMethods() []string { return slices.Clone(vaultapi.FederationMethods) }

// ForgetSession implements [stores.SessionForgetter].
func (a *Adapter) ForgetSession(id string) { a.agents.ForgetSession(id) }
