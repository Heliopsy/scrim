// SPDX-License-Identifier: AGPL-3.0-only

package openbao

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

// AgentCan implements [stores.AgentAccess]: it asks OpenBao, with the
// agent's own token, for that token's capabilities on ref's KV v2 data
// path (sys/capabilities-self). The value is never read with the agent's
// token. The agent's token is a static one, a Kubernetes auth login with
// the agent pod's service account token at the rendered role, or a JWT auth
// login with an identity token scrim signs for the agent, so the role
// OpenBao binds to that identity decides.
func (a *Adapter) AgentCan(ctx context.Context, cred stores.AgentCredential, op stores.Op, ref stores.Ref) error {
	mount, rest := a.split(ref.Path)
	if rest == "" {
		return a.err(op, ref, stores.ErrInvalidRef, "reference names a mount, not a secret")
	}
	return a.c.AgentCan(ctx, a.agents, cred, op, ref, mount+"/data/"+rest)
}

// FederationMethods implements [stores.AgentFederation].
func (a *Adapter) FederationMethods() []string { return slices.Clone(vaultapi.FederationMethods) }

// ForgetSession implements [stores.SessionForgetter].
func (a *Adapter) ForgetSession(id string) { a.agents.ForgetSession(id) }
