// SPDX-License-Identifier: AGPL-3.0-only

package vaultwarden

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores"
	"github.com/heliopsy/scrim/internal/stores/internal/wire"
)

var (
	_ stores.AgentAccess      = (*Adapter)(nil)
	_ stores.SessionForgetter = (*Adapter)(nil)
)

// agentKeyFormat names the only agent credential this store takes, for
// errors that refuse another shape (never quoting it).
const agentKeyFormat = `a personal API key as {"client_id": "user.<uuid>", "client_secret": "..."}`

// memberConfirmed is a confirmed organisation membership (Bitwarden's
// OrganizationUserStatusType).
const memberConfirmed = 2

// ForgetSession implements [stores.SessionForgetter]. Agents log in with
// static API keys, which are not tied to a scrim session, so their logins
// stay cached until they expire, the store is locked or it is closed.
func (a *Adapter) ForgetSession(id string) { a.agents.ForgetSession(id) }

// agentTarget is what an agent's check is about: an existing item, or the
// collections a new item would go into.
type agentTarget struct {
	cipherID    string
	orgID       string
	collections []string
}

// AgentCan implements [stores.AgentAccess]. The agent has its own
// Bitwarden or Vaultwarden account, a member of the organisations holding
// the shared items, and identity.store-credentials holds that account's
// personal API key. The item is found with scrim's own vault; the agent
// logs in with its API key and asks the server for the item as itself
// (GET /api/ciphers/{id}). A refusal, a collection that hides passwords
// from it, or for OpWrite a collection it may not edit, is
// [stores.ErrPermission]. A new item (OpWrite) must go into a collection
// the agent may add to, as its own sync reports. An item in scrim's
// personal vault is never an agent's. Nothing is decrypted with the
// agent's account, so its master password is never needed; the cipher
// returned is wiped unread.
func (a *Adapter) AgentCan(ctx context.Context, cred stores.AgentCredential, op stores.Op, ref stores.Ref) error {
	switch {
	case op != stores.OpRead && op != stores.OpWrite:
		return a.fail(op, ref, stores.ErrUnsupported, "only reads and writes are checked per agent", nil)
	case !cred.KubernetesJWT.IsZero():
		return a.fail(op, ref, stores.ErrUnsupported, "Kubernetes passthrough is not supported for Vaultwarden; give the agent "+agentKeyFormat, nil)
	case cred.Token.IsZero() && cred.Federation != nil:
		return a.fail(op, ref, stores.ErrUnsupported, "token exchange method "+cred.Federation.Method+" is not one this store takes; give the agent "+agentKeyFormat, nil)
	case cred.Token.IsZero():
		return a.fail(op, ref, stores.ErrPermission, "no agent credential", nil)
	}
	clientID, cs, cacheKey, err := a.agentAPIKey(op, ref, cred)
	if err != nil {
		return err
	}
	defer cs.Wipe()
	t, err := a.agentTarget(ctx, op, ref)
	if err != nil {
		return err
	}
	cl := *a.cl
	cl.deviceID = a.opts.agentDeviceID(a.name, cred.Agent)
	tok, cached, err := a.agentLogin(ctx, &cl, op, ref, cacheKey, clientID, cs)
	if err != nil {
		return err
	}
	err = a.agentCheck(ctx, &cl, op, ref, t, tok, cs)
	if cached && httpStatus(err) == http.StatusUnauthorized {
		// The server no longer takes the cached token: drop it and log in
		// once more.
		tok.Wipe()
		a.agents.Forget(cacheKey)
		if tok, _, err = a.agentLogin(ctx, &cl, op, ref, cacheKey, clientID, cs); err != nil {
			return err
		}
		err = a.agentCheck(ctx, &cl, op, ref, t, tok, cs)
	}
	tok.Wipe()
	return err
}

// agentAPIKey decodes the agent's personal API key. The cache key holds
// the agent principal and the key's client_id, which is not secret; nothing
// derived from the client secret is kept. A key rotated under the same
// client_id reuses the cached login, which the server keeps accepting until
// it expires, as it would for any client of that account. The caller wipes
// cs.
func (a *Adapter) agentAPIKey(op stores.Op, ref stores.Ref, cred stores.AgentCredential) (clientID string, cs secret.Value, cacheKey string, err error) {
	bad := func() error {
		return a.fail(op, ref, stores.ErrPermission, "the agent credential is not "+agentKeyFormat, nil)
	}
	var m map[string]wire.Raw
	perr := cred.Token.Expose(func(b []byte) error { return json.Unmarshal(b, &m) })
	defer func() {
		for _, v := range m {
			v.Wipe()
		}
	}()
	id, rs := m["client_id"], m["client_secret"]
	if perr != nil || len(m) != 2 || len(id) == 0 || len(rs) < 3 || rs[0] != '"' {
		return "", secret.Value{}, "", bad()
	}
	idb, uerr := wire.Unquote(id)
	rest, ok := strings.CutPrefix(string(idb), "user.")
	if uerr != nil || !ok || !isUUID(rest) {
		return "", secret.Value{}, "", bad()
	}
	cs, verr := rs.Value()
	if verr != nil || cs.IsZero() {
		cs.Wipe()
		return "", secret.Value{}, "", bad()
	}
	return string(idb), cs, "api-key\x00" + cred.Agent + "\x00" + string(idb), nil
}

// agentTarget resolves ref with scrim's own vault the way Read (OpRead) or
// Write (OpWrite) would.
func (a *Adapter) agentTarget(ctx context.Context, op stores.Op, ref stores.Ref) (agentTarget, error) {
	ref = ref.Secret()
	if err := a.checkRef(op, ref); err != nil {
		return agentTarget{}, err
	}
	if !a.inScope(ref.Path) {
		kind := stores.ErrNotFound
		if op == stores.OpWrite {
			kind = stores.ErrPermission
		}
		return agentTarget{}, a.fail(op, ref, kind, "outside the configured scope", nil)
	}
	v, err := a.current(ctx, op)
	if err != nil {
		return agentTarget{}, err
	}
	org := ref.Selector("org")
	it, detail, err := v.lookup(ref.Path, org)
	switch {
	case err != nil:
		return agentTarget{}, a.fail(op, ref, stores.ErrInvalidRef, detail, err)
	case it != nil && it.personal:
		return agentTarget{}, a.fail(op, ref, stores.ErrPermission, "the item is in scrim's personal vault, which is never an agent's", nil)
	case it != nil:
		return agentTarget{cipherID: it.raw.ID, orgID: it.orgID}, nil
	case op == stores.OpRead:
		return agentTarget{}, a.fail(op, ref, stores.ErrNotFound, "", nil)
	case org == "":
		return agentTarget{}, a.fail(op, ref, stores.ErrPermission, "a new item without ?org= goes into scrim's personal vault, which is never an agent's", nil)
	}
	// A new organisation item, placed as create places it.
	container := ""
	if i := strings.LastIndexByte(ref.Path, '/'); i >= 0 {
		container = ref.Path[:i]
	}
	if container == "" {
		return agentTarget{}, a.fail(op, ref, stores.ErrInvalidRef, "an organisation item needs a collection: <collection>/<item>", nil)
	}
	t := agentTarget{}
	for id, n := range v.orgNames {
		if id == org || n == org {
			t.orgID = id
		}
	}
	if t.orgID == "" {
		return agentTarget{}, a.fail(op, ref, stores.ErrNotFound, "organisation "+strconv.Quote(org)+" not found", nil)
	}
	for id, cn := range v.collNames {
		if cn == container && v.collections[id].OrganizationID == t.orgID {
			t.collections = append(t.collections, id)
		}
	}
	if len(t.collections) == 0 {
		return agentTarget{}, a.fail(op, ref, stores.ErrNotFound, "collection "+strconv.Quote(container)+" not found in the organisation", nil)
	}
	return t, nil
}

// agentLogin returns a copy of the agent's access token, logging in with
// its API key when none is cached. cached reports a token from the cache.
// The caller wipes the token.
func (a *Adapter) agentLogin(ctx context.Context, cl *client, op stores.Op, ref stores.Ref, key, clientID string, cs secret.Value) (tok secret.Value, cached bool, err error) {
	if t, ok := a.agents.Get(key); ok {
		if !t.IsZero() {
			return t, true, nil
		}
		t.Wipe()
	}
	s, err := cl.loginAPIKey(ctx, clientID, cs)
	if err != nil {
		return secret.Value{}, false, a.agentFail(op, ref, "the server refused the agent's API key", err, cs)
	}
	tok = copyValue(s.token)
	a.agents.Put(key, "", s.token, time.Until(s.expires))
	return tok, false, nil
}

// agentCheck asks the server, with the agent's token, whether the agent may
// perform op on t.
func (a *Adapter) agentCheck(ctx context.Context, cl *client, op stores.Op, ref stores.Ref, t agentTarget, tok, cs secret.Value) error {
	s := session{token: tok}
	if t.cipherID == "" {
		return a.agentCanCreate(ctx, cl, op, ref, t, s, cs)
	}
	body, err := cl.authedRaw(ctx, s, http.MethodGet, "/api/ciphers/"+url.PathEscape(t.cipherID), nil)
	defer secret.WipeBytes(body)
	if err != nil {
		switch httpStatus(err) {
		case http.StatusBadRequest, http.StatusForbidden, http.StatusNotFound:
			return a.agentFail(op, ref, "the agent's own account cannot see this item", err, cs, tok)
		}
		return a.agentFail(op, ref, "the agent's item request failed", err, cs, tok)
	}
	// Only the two permission flags are decoded; the rest of the cipher,
	// ciphertext included, is skipped and wiped.
	var c struct {
		Edit         *bool `json:"edit"`
		ViewPassword *bool `json:"viewPassword"`
	}
	if json.Unmarshal(body, &c) != nil || c.Edit == nil || c.ViewPassword == nil {
		return a.fail(op, ref, stores.ErrUnavailable, "the server did not report the agent's permissions on the item", nil)
	}
	switch {
	case op == stores.OpRead && !*c.ViewPassword:
		return a.fail(op, ref, stores.ErrPermission, "the agent's own account may see this item but not its passwords (its collection hides passwords)", nil)
	case op == stores.OpWrite && !*c.Edit:
		return a.fail(op, ref, stores.ErrPermission, "the agent's own account may not edit this item (its collection is read-only)", nil)
	}
	return nil
}

// agentCanCreate checks that the agent is a confirmed member of t's
// organisation and may add items to one of t's collections, from its own
// sync.
func (a *Adapter) agentCanCreate(ctx context.Context, cl *client, op stores.Op, ref stores.Ref, t agentTarget, s session, cs secret.Value) error {
	body, err := cl.authedRaw(ctx, s, http.MethodGet, "/api/sync", url.Values{"excludeDomains": {"true"}})
	defer secret.WipeBytes(body)
	if err != nil {
		return a.agentFail(op, ref, "the agent's sync failed", err, cs, s.token)
	}
	// Only memberships and collection flags are decoded; the ciphers are
	// skipped and wiped.
	var sr struct {
		Profile struct {
			Organizations []struct {
				ID     string `json:"id"`
				Status *int   `json:"status"`
			} `json:"organizations"`
		} `json:"profile"`
		Collections []struct {
			ID             string `json:"id"`
			OrganizationID string `json:"organizationId"`
			ReadOnly       bool   `json:"readOnly"`
		} `json:"collections"`
	}
	if json.Unmarshal(body, &sr) != nil {
		return a.fail(op, ref, stores.ErrUnavailable, "malformed sync response for the agent", nil)
	}
	member := slices.ContainsFunc(sr.Profile.Organizations, func(o struct {
		ID     string `json:"id"`
		Status *int   `json:"status"`
	}) bool {
		return strings.EqualFold(o.ID, t.orgID) && (o.Status == nil || *o.Status == memberConfirmed)
	})
	if !member {
		return a.fail(op, ref, stores.ErrPermission, "the agent's own account is not a confirmed member of the item's organisation", nil)
	}
	for _, c := range sr.Collections {
		if strings.EqualFold(c.OrganizationID, t.orgID) && !c.ReadOnly && slices.ContainsFunc(t.collections, func(id string) bool { return strings.EqualFold(id, c.ID) }) {
			return nil
		}
	}
	return a.fail(op, ref, stores.ErrPermission, "the agent's own account may not add items to this collection", nil)
}

// agentFail maps a failed request made as the agent to a store error. The
// server's message is kept only if it holds none of the involved
// credentials.
func (a *Adapter) agentFail(op stores.Op, ref stores.Ref, what string, err error, involved ...secret.Value) error {
	var se *stores.Error
	if errors.As(err, &se) {
		return err
	}
	detail := what
	var ae *apiError
	if errors.As(err, &ae) {
		detail += ": HTTP " + strconv.Itoa(ae.Status)
		if ae.Message != "" {
			detail += ": " + wire.SafeDetail(ae.Message, involved...)
		}
	} else {
		detail += ": " + wire.SafeDetail(err.Error(), involved...)
	}
	kind := stores.ErrUnavailable
	st := httpStatus(err)
	if !isTransport(err) {
		switch st {
		case http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
			// A login answers 400 invalid_client for a wrong or revoked
			// API key; an item request 400 (Vaultwarden) or 404 (Bitwarden)
			// for an item the account cannot see.
			kind = stores.ErrPermission
		}
	}
	// The cause keeps only the status, for the 401 retry; the server's
	// message is in the sanitised detail.
	var cause error
	if st != 0 {
		cause = &apiError{Status: st}
	}
	return a.fail(op, ref, kind, detail, cause)
}

func copyValue(v secret.Value) secret.Value {
	var out secret.Value
	_ = v.Expose(func(b []byte) error { out = secret.New(b); return nil })
	return out
}
