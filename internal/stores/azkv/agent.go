// SPDX-License-Identifier: AGPL-3.0-only

package azkv

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores"
	"github.com/heliopsy/scrim/internal/stores/internal/wire"
)

var (
	_ stores.AgentAccess      = (*Adapter)(nil)
	_ stores.AgentFederation  = (*Adapter)(nil)
	_ stores.SessionForgetter = (*Adapter)(nil)
)

// tenantPattern is a tenant ID or domain, the only thing interpolated into
// the token endpoint's path.
var tenantPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$`)

// FederationMethods implements [stores.AgentFederation].
func (a *Adapter) FederationMethods() []string { return []string{stores.FederationAzure} }

// ForgetSession implements [stores.SessionForgetter].
func (a *Adapter) ForgetSession(id string) { a.agents.ForgetSession(id) }

// AgentCan implements [stores.AgentAccess] for reads. It presents an
// identity token scrim signs for the agent as the client assertion of an
// Entra ID application with a federated credential (client credentials
// grant), and reads the secret with the access token it gets: Key Vault has
// no API that answers whether a caller may read a secret, so the read is
// the check, and its body is wiped unread. A static agent token
// (identity.store-credentials) is used as an access token as is. Writes
// cannot be checked without writing and are refused as unsupported.
func (a *Adapter) AgentCan(ctx context.Context, cred stores.AgentCredential, op stores.Op, ref stores.Ref) error {
	if op != stores.OpRead {
		return a.errf(op, ref, stores.ErrUnsupported, "Key Vault cannot check whether an agent's own identity may write without writing; only reads are checked")
	}
	name, version, err := a.locate(op, ref)
	if err != nil {
		return err
	}
	u := a.c.url(secretPath(name, version), nil)
	var tok secret.Value
	switch {
	case !cred.Token.IsZero():
		tok = copyValue(cred.Token)
	case cred.Federation != nil:
		if tok, err = a.agentToken(ctx, op, ref, cred.Federation, u); err != nil {
			return err
		}
	default:
		return a.errf(op, ref, stores.ErrPermission, "no agent credential")
	}
	defer tok.Wipe()
	resp, _, err := a.c.send(ctx, http.MethodGet, u, nil, tok)
	if err != nil {
		return a.fail(op, ref, err)
	}
	// The value, if any, is never looked at.
	defer secret.WipeBytes(resp.body)
	if resp.status >= 200 && resp.status < 300 {
		return nil
	}
	e := classify(resp.status, resp.body, []secret.Value{tok})
	if e.kind == stores.ErrPermission {
		e.msg = "the agent's own Entra ID identity may not read this secret: " + e.msg
	}
	return a.fail(op, ref, e)
}

// agentToken returns a copy of the agent's Key Vault access token,
// exchanging a new identity token when none is cached. The caller wipes it.
func (a *Adapter) agentToken(ctx context.Context, op stores.Op, ref stores.Ref, f *stores.Federation, probe string) (secret.Value, error) {
	if f.Method != stores.FederationAzure {
		return secret.Value{}, a.errf(op, ref, stores.ErrUnsupported, "token exchange method "+f.Method+" is not one this store takes ("+stores.FederationAzure+")")
	}
	tenant, clientID := f.Params["tenant"], f.Params["client-id"]
	if tenant == "" || clientID == "" || f.Token == nil {
		return secret.Value{}, a.errf(op, ref, stores.ErrPermission, "no agent credential")
	}
	if !tenantPattern.MatchString(tenant) {
		return secret.Value{}, a.errf(op, ref, stores.ErrInvalidRef, "tenant is not a tenant ID or domain")
	}
	authority, err := url.Parse(f.Param("authority", "https://login.microsoftonline.com"))
	if err != nil || authority.Scheme != "https" || authority.Host == "" {
		return secret.Value{}, a.errf(op, ref, stores.ErrInvalidRef, "authority must be an https URL")
	}
	if v, ok := a.agents.Get(f.Key); ok {
		return v, nil
	}
	ch, err := a.challenge(ctx, probe)
	if err != nil {
		return secret.Value{}, a.fail(op, ref, err)
	}
	jwt, err := f.Token()
	if err != nil {
		return secret.Value{}, a.errf(op, ref, stores.ErrPermission, "no identity token for the agent")
	}
	defer jwt.Wipe()
	var buf []byte
	buf = wire.AppendForm(buf, "grant_type", []byte("client_credentials"))
	buf = wire.AppendForm(buf, "client_id", []byte(clientID))
	buf = wire.AppendForm(buf, "scope", []byte(ch.scope))
	buf = wire.AppendForm(buf, "client_assertion_type", []byte("urn:ietf:params:oauth:client-assertion-type:jwt-bearer"))
	buf = wire.AppendFormValue(buf, "client_assertion", jwt)
	body := wire.NewBody(buf)
	defer body.Wipe()
	endpoint := strings.TrimRight(authority.String(), "/") + "/" + tenant + "/oauth2/v2.0/token"
	tok, ttl, err := a.entraToken(ctx, endpoint, body, jwt)
	if err != nil {
		return secret.Value{}, a.fail(op, ref, err)
	}
	a.agents.Put(f.Key, f.Session, tok, ttl)
	return copyValue(tok), nil
}

// challenge returns the vault's Bearer challenge (the token scope), asking
// the vault with an unauthenticated request to probe when none is known
// yet. The scope is checked against the vault's host, as for scrim's own
// token.
func (a *Adapter) challenge(ctx context.Context, probe string) (challenge, error) {
	if ch := a.c.currentChallenge(); ch != nil {
		return *ch, nil
	}
	resp, hdr, err := a.c.send(ctx, http.MethodGet, probe, nil, secret.Value{})
	if err != nil {
		return challenge{}, err
	}
	secret.WipeBytes(resp.body)
	if resp.status != http.StatusUnauthorized {
		return challenge{}, &apiError{status: resp.status, kind: stores.ErrUnavailable, msg: "the vault answered an unauthenticated request without a Bearer challenge"}
	}
	if err := a.c.learnChallenge(hdr.Values("WWW-Authenticate")); err != nil {
		return challenge{}, err
	}
	if ch := a.c.currentChallenge(); ch != nil {
		return *ch, nil
	}
	return challenge{}, &apiError{kind: stores.ErrPermission, msg: "the vault sent no usable Bearer challenge"}
}

// entraToken posts a client credentials request to Entra ID and returns
// the access token and its lifetime. Errors keep Entra's AADSTS code and
// description, never the assertion.
func (a *Adapter) entraToken(ctx context.Context, endpoint string, body *wire.Body, assertion secret.Value) (secret.Value, time.Duration, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, body.Reader())
	if err != nil {
		return secret.Value{}, 0, &apiError{kind: stores.ErrInvalidRef, msg: "cannot build the token request"}
	}
	req.ContentLength = int64(body.Len())
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := a.c.http.Do(req)
	if err != nil {
		return secret.Value{}, 0, &apiError{kind: stores.ErrUnavailable, msg: "Entra ID unreachable", cause: scrubURLError(err)}
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := wire.ReadBody(resp.Body)
	if err != nil {
		return secret.Value{}, 0, &apiError{kind: stores.ErrUnavailable, msg: "reading the token response failed"}
	}
	defer secret.WipeBytes(b)
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Error       string `json:"error"`
			Description string `json:"error_description"`
		}
		_ = json.Unmarshal(b, &e)
		kind := stores.ErrPermission
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
			kind = stores.ErrUnavailable
		}
		msg := fmt.Sprintf("Entra ID refused the agent's federated credential (HTTP %d)", resp.StatusCode)
		if d := wire.SafeDetail(firstLine(e.Description), assertion); d != "" {
			msg += ": " + d
		}
		return secret.Value{}, 0, &apiError{status: resp.StatusCode, kind: kind, msg: msg}
	}
	var out struct {
		AccessToken wire.Raw `json:"access_token"`
		ExpiresIn   int64    `json:"expires_in"`
	}
	err = json.Unmarshal(b, &out)
	defer out.AccessToken.Wipe()
	if err != nil || len(out.AccessToken) == 0 {
		return secret.Value{}, 0, &apiError{kind: stores.ErrUnavailable, msg: "malformed token response"}
	}
	v, err := out.AccessToken.Value()
	if err != nil {
		return secret.Value{}, 0, &apiError{kind: stores.ErrUnavailable, msg: "malformed token response"}
	}
	return v, time.Duration(out.ExpiresIn) * time.Second, nil
}

func firstLine(s string) string {
	l, _, _ := strings.Cut(s, "\n")
	return strings.TrimSpace(strings.TrimSuffix(l, "\r"))
}
