// SPDX-License-Identifier: AGPL-3.0-only

package infisical

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores"
)

var (
	_ stores.AgentAccess      = (*Adapter)(nil)
	_ stores.AgentFederation  = (*Adapter)(nil)
	_ stores.SessionForgetter = (*Adapter)(nil)
)

// oidcLoginPath is Infisical's OIDC Auth login for machine identities.
const oidcLoginPath = "/api/v1/auth/oidc-auth/login"

// FederationMethods implements [stores.AgentFederation].
func (a *Adapter) FederationMethods() []string { return []string{stores.FederationInfisical} }

// ForgetSession implements [stores.SessionForgetter]: the access tokens
// agents of that scrim session logged in with are wiped.
func (a *Adapter) ForgetSession(id string) { a.agents.ForgetSession(id) }

// AgentCan implements [stores.AgentAccess]. Infisical has no call that
// reports an identity's permissions on a secret without using them, so the
// check is the read itself: the secret is read with the agent's own access
// token (the same GET /api/v4/secrets/{key} Read makes) and the value is
// wiped unread. A refusal, or a value Infisical hides from the identity, is
// [stores.ErrPermission]; a missing secret keeps Infisical's not-found.
//
// The agent's token is a static Infisical access token held for it
// (identity.store-credentials), or one obtained with OIDC Auth by presenting
// an identity token scrim's issuer signs for the agent at the machine
// identity identity-id names. Writes cannot be checked without writing, so
// OpWrite is refused as unsupported: the only endpoint that reports
// permissions (GET /api/v1/projects/{id}/permissions, undocumented)
// accepts user sessions only, not a machine identity's access token, and
// Infisical has no dry run for a secret write.
func (a *Adapter) AgentCan(ctx context.Context, cred stores.AgentCredential, op stores.Op, ref stores.Ref) error {
	if op != stores.OpRead {
		return &stores.Error{Store: a.name, Op: op, Ref: ref, Kind: stores.ErrUnsupported,
			Detail: "Infisical cannot report whether an identity may write without writing; only reads are checked per agent"}
	}
	path, q, _, _, err := a.secretQuery(ctx, ref, true)
	if err != nil {
		return err
	}
	tok := cred.Token
	if tok.IsZero() {
		if tok, err = a.agentToken(ctx, op, ref, cred); err != nil {
			return err
		}
		defer tok.Wipe()
	}
	b, err := a.c.doAs(ctx, http.MethodGet, path, q, tok)
	if err != nil {
		return a.fail(op, ref, err)
	}
	defer secret.WipeBytes(b)
	var resp struct {
		Secret apiSecret `json:"secret"`
	}
	err = json.Unmarshal(b, &resp)
	resp.Secret.SecretValue.Wipe()
	switch {
	case err != nil:
		return &stores.Error{Store: a.name, Op: op, Ref: ref, Kind: stores.ErrUnavailable, Detail: "malformed secret response"}
	case resp.Secret.SecretValueHidden:
		return &stores.Error{Store: a.name, Op: op, Ref: ref, Kind: stores.ErrPermission,
			Detail: "the agent's own Infisical identity may describe this secret but not read its value"}
	}
	return nil
}

// agentToken returns a copy of the agent's access token, logging in with
// OIDC Auth when none is cached. The caller wipes it.
func (a *Adapter) agentToken(ctx context.Context, op stores.Op, ref stores.Ref, cred stores.AgentCredential) (secret.Value, error) {
	f := cred.Federation
	switch {
	case f == nil && !cred.KubernetesJWT.IsZero():
		return secret.Value{}, &stores.Error{Store: a.name, Op: op, Ref: ref, Kind: stores.ErrUnsupported,
			Detail: "Kubernetes passthrough is not supported for Infisical; use infisical-oidc"}
	case f == nil:
		return secret.Value{}, &stores.Error{Store: a.name, Op: op, Ref: ref, Kind: stores.ErrPermission, Detail: "no agent credential"}
	case f.Method != stores.FederationInfisical:
		return secret.Value{}, &stores.Error{Store: a.name, Op: op, Ref: ref, Kind: stores.ErrUnsupported,
			Detail: "token exchange method " + f.Method + " is not one this store takes (" + stores.FederationInfisical + ")"}
	case f.Params["identity-id"] == "" || f.Token == nil:
		return secret.Value{}, &stores.Error{Store: a.name, Op: op, Ref: ref, Kind: stores.ErrPermission, Detail: "no agent credential"}
	}
	if t, ok := a.agents.Get(f.Key); ok {
		return t, nil
	}
	jwt, err := f.Token()
	if err != nil {
		return secret.Value{}, stores.NewError(a.name, op, ref, stores.ErrPermission, err)
	}
	defer jwt.Wipe()
	body, err := kubernetesLoginBody(f.Params["identity-id"], jwt)
	if err != nil {
		return secret.Value{}, a.fail(op, ref, err)
	}
	defer body.Wipe()
	tok, ttl, err := a.c.postLogin(ctx, oidcLoginPath, "OIDC Auth", body, []secret.Value{jwt})
	if err != nil {
		return secret.Value{}, a.fail(op, ref, err)
	}
	a.agents.Put(f.Key, f.Session, tok, ttl)
	return copyValue(tok), nil
}
