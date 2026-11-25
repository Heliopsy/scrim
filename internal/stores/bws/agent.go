// SPDX-License-Identifier: AGPL-3.0-only

package bws

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores"
	"github.com/heliopsy/scrim/internal/stores/internal/wire"
)

var (
	_ stores.AgentAccess      = (*Adapter)(nil)
	_ stores.SessionForgetter = (*Adapter)(nil)
)

// ForgetSession implements [stores.SessionForgetter]. Agents log in with
// static access tokens, which are not tied to a scrim session, so this
// drops nothing today; it is here so a session's logins would go with it.
func (a *Adapter) ForgetSession(id string) { a.agents.ForgetSession(id) }

// accessFlags is the part of SecretResponseModel and ProjectResponseModel
// the check reads: the caller's own access, as the server computed it.
// Everything else in the answer, the encrypted value and note among it, is
// skipped by the decoder and wiped with the body.
type accessFlags struct {
	ID    string `json:"id"`
	Read  *bool  `json:"read"`
	Write *bool  `json:"write"`
}

// AgentCan implements [stores.AgentAccess]. The agent's credential
// (identity.store-credentials) is an access token of a machine account of
// scrim's organisation. AgentCan logs in with it (the same client
// credentials login scrim makes, cached per agent until two thirds of the
// bearer's lifetime), refuses a machine account of another organisation,
// resolves the reference with scrim's own index, and then asks Bitwarden as
// the agent:
//
//   - a read, or a write to an existing secret, fetches GET /secrets/{id}:
//     the server answers 404 when the machine account may not read it, and
//     otherwise reports the caller's own read and write access, of which a
//     write needs write. The answer holds the encrypted value and note; they
//     are never decrypted (the organisation key the agent's login carries is
//     not even unwrapped) and the body is wiped.
//   - a write that would create a secret fetches GET /projects/{id} of the
//     project Write would create it in, which needs write.
//
// Kubernetes passthrough and token exchange are unsupported: Bitwarden
// has neither.
func (a *Adapter) AgentCan(ctx context.Context, cred stores.AgentCredential, op stores.Op, ref stores.Ref) error {
	if op != stores.OpRead && op != stores.OpWrite {
		return a.errorf(op, ref, stores.ErrUnsupported, "only reads and writes are checked per agent")
	}
	switch {
	case !cred.Token.IsZero():
	case !cred.KubernetesJWT.IsZero():
		return a.errorf(op, ref, stores.ErrUnsupported, "Kubernetes passthrough is not supported for Bitwarden Secrets Manager; give the agent a machine account access token")
	case cred.Federation != nil:
		return a.errorf(op, ref, stores.ErrUnsupported, "token exchange method %s is not one this store takes: Bitwarden Secrets Manager has no token exchange; give the agent a machine account access token", cred.Federation.Method)
	default:
		return a.errorf(op, ref, stores.ErrPermission, "no agent credential")
	}
	if !noSelectors(ref) {
		return a.errorf(op, ref, stores.ErrInvalidRef, "Secrets Manager references take no selectors")
	}
	switch ref.Field {
	case "", FieldValue, FieldNote:
	default:
		return a.errorf(op, ref, stores.ErrNotFound, "a Secrets Manager secret has the fields %s and %s", FieldValue, FieldNote)
	}
	loc, ok := parseLocation(ref.Path)
	if !ok {
		return a.errorf(op, ref, stores.ErrInvalidRef, refForms)
	}
	ix, err := a.loadIndex(ctx)
	if err != nil {
		return a.fail(op, ref, err)
	}
	var id, what string
	e, err := a.resolve(op, ref, ix)
	switch {
	case err == nil:
		id, what = e.id, "secret"
	case op == stores.OpWrite && errors.Is(err, stores.ErrNotFound) && loc.id == "":
		// Write creates the secret in the project the reference names.
		p, perr := a.project(op, ref, ix, loc.projectSel)
		if perr != nil {
			return perr
		}
		id, what = p.id, "project"
	default:
		return err
	}
	flags, err := a.agentGet(ctx, cred, ix.org, op, ref, "/"+what+"s/"+id)
	if err != nil {
		return err
	}
	if !strings.EqualFold(flags.ID, id) {
		return a.errorf(op, ref, stores.ErrUnavailable, "the server answered with another %s", what)
	}
	if op == stores.OpRead {
		return nil
	}
	switch {
	case flags.Write == nil:
		return a.errorf(op, ref, stores.ErrUnsupported, "this Bitwarden server does not report the machine account's write access to a %s", what)
	case !*flags.Write:
		return a.errorf(op, ref, stores.ErrPermission, "the agent's machine account may read this %s but not write it", what)
	}
	return nil
}

// agentGet fetches path with the agent's bearer token and returns the
// access flags of the answer. A 401 on a cached bearer logs in once more;
// a 404 (the server's answer when the machine account may not read an
// object scrim's own account sees) is a permission refusal.
func (a *Adapter) agentGet(ctx context.Context, cred stores.AgentCredential, org string, op stores.Op, ref stores.Ref, path string) (accessFlags, error) {
	key := agentKey(cred)
	for attempt := 0; ; attempt++ {
		bearer, cached, err := a.agentBearer(ctx, cred, key, org, op, ref, attempt > 0)
		if err != nil {
			return accessFlags{}, err
		}
		status, b, err := a.c.send(ctx, http.MethodGet, endpoint(a.s.api, path, nil), nil, bearer)
		if err != nil {
			bearer.Wipe()
			return accessFlags{}, a.fail(op, ref, err)
		}
		if status == http.StatusUnauthorized && cached && attempt == 0 {
			secret.WipeBytes(b)
			bearer.Wipe()
			a.agents.Forget(key)
			continue
		}
		if status >= 200 && status <= 299 {
			var flags accessFlags
			jerr := json.Unmarshal(b, &flags)
			secret.WipeBytes(b)
			bearer.Wipe()
			if jerr != nil {
				return accessFlags{}, a.errorf(op, ref, stores.ErrUnavailable, "the answer to the agent's check is not the expected JSON")
			}
			return flags, nil
		}
		e := classify(status, b)
		e.msg = wire.SafeDetail(e.msg, bearer, cred.Token)
		secret.WipeBytes(b)
		bearer.Wipe()
		if status == http.StatusNotFound || e.kind == stores.ErrPermission {
			return accessFlags{}, a.errorf(op, ref, stores.ErrPermission, "the agent's machine account may not %s this (Bitwarden answered %d)", op, status)
		}
		return accessFlags{}, a.fail(op, ref, e)
	}
}

// agentBearer returns a copy of the agent's bearer token, logging in with
// its access token when none is cached or force is set. cached reports
// whether it came from the cache.
func (a *Adapter) agentBearer(ctx context.Context, cred stores.AgentCredential, key, org string, op stores.Op, ref stores.Ref, force bool) (bearer secret.Value, cached bool, err error) {
	if !force {
		if v, ok := a.agents.Get(key); ok {
			return v, true, nil
		}
	}
	tok, err := parseAccessToken(cred.Token)
	if err != nil {
		return secret.Value{}, false, a.errorf(op, ref, stores.ErrPermission, "the agent's credential is not a machine account access token: %v", err)
	}
	defer tok.wipe()
	bearer, agentOrg, ttl, _, err := a.c.loginWith(ctx, tok, cred.Token)
	if err != nil {
		var ae *apiError
		if errors.As(err, &ae) {
			ae.msg = "the agent's machine account: " + ae.msg
		}
		return secret.Value{}, false, a.fail(op, ref, err)
	}
	if agentOrg != org {
		bearer.Wipe()
		return secret.Value{}, false, a.errorf(op, ref, stores.ErrPermission, "the agent's machine account belongs to another organization")
	}
	a.agents.Put(key, "", bearer, ttl)
	return copyValue(bearer), false, nil
}

// agentKey is the cache key of an agent's login: its principal and the
// SHA-256 of its access token, so a rotated token logs in again and the
// token itself is never kept.
func agentKey(cred stores.AgentCredential) string {
	h := sha256.New()
	_ = cred.Token.Expose(func(b []byte) error { h.Write(b); return nil })
	return "static\x00" + cred.Agent + "\x00" + string(h.Sum(nil))
}

func copyValue(v secret.Value) secret.Value {
	var out secret.Value
	_ = v.Expose(func(b []byte) error { out = secret.New(b); return nil })
	return out
}
