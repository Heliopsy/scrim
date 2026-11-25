// SPDX-License-Identifier: AGPL-3.0-only

package onepassword

import (
	"context"
	"errors"
	"slices"

	"github.com/heliopsy/scrim/internal/stores"
)

var _ stores.AgentAccess = (*Adapter)(nil)

// AgentCan implements [stores.AgentAccess]. The agent's credential
// (identity.store-credentials) is a Connect access token issued for the agent
// by the same Connect server (op connect token create), scoped to the
// agent's own vaults. It is the bearer as is: there is no login and nothing
// is cached.
//
// Connect grants read and write per vault, to every item in it, so an agent
// may read an item exactly when its token may read the vault's items. The
// check resolves the reference with scrim's own token to the vault ID and the
// item's ID and title, then lists the vault's items titled that way with the
// agent's token (GET /v1/vaults/{id}/items, summaries only, no field and no
// value) and requires the item's ID among them. A 401, 403 or 404 for the
// vault is [stores.ErrPermission].
//
// Connect has no call that reports whether a token may write without
// writing, so OpWrite is refused as unsupported.
func (a *Adapter) AgentCan(ctx context.Context, cred stores.AgentCredential, op stores.Op, ref stores.Ref) error {
	if op != stores.OpRead {
		return a.refuse(op, ref, stores.ErrUnsupported,
			"1Password Connect cannot report whether an access token may write to a vault without writing; only reads are checked per agent")
	}
	switch {
	case !cred.Token.IsZero():
	case !cred.KubernetesJWT.IsZero():
		return a.refuse(op, ref, stores.ErrUnsupported,
			"Kubernetes passthrough is not supported for 1Password; hold a Connect access token for the agent in identity.store-credentials")
	case cred.Federation != nil:
		return a.refuse(op, ref, stores.ErrUnsupported,
			"token exchange method "+cred.Federation.Method+" is not one this store takes; hold a Connect access token for the agent in identity.store-credentials")
	default:
		return a.refuse(op, ref, stores.ErrPermission, "no agent credential")
	}
	loc, err := a.checkRef(op, ref)
	if err != nil {
		return err
	}
	f, err := a.locate(ctx, loc, false)
	if err != nil {
		return a.fail(op, ref, err)
	}
	sums, err := a.c.itemsAs(ctx, f.vault.ID, f.sum.Title, cred.Token)
	if err != nil {
		var ae *apiError
		if errors.As(err, &ae) && (ae.kind == stores.ErrPermission || ae.kind == stores.ErrNotFound) {
			return a.refuse(op, ref, stores.ErrPermission,
				"the agent's Connect token may not read vault "+quote(loc.vault)+": "+ae.msg)
		}
		return a.fail(op, ref, err)
	}
	if !slices.ContainsFunc(sums, func(s apiSummary) bool { return s.ID == f.sum.ID }) {
		return a.refuse(op, ref, stores.ErrPermission,
			"the item is not among those the agent's Connect token lists in vault "+quote(loc.vault))
	}
	return nil
}
