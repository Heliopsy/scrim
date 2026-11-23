// SPDX-License-Identifier: AGPL-3.0-only

package gcpsm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores"
	"github.com/heliopsy/scrim/internal/stores/internal/wire"
)

// stsEndpoint is Google's Security Token Service.
const stsEndpoint = "https://sts.googleapis.com"

// Permissions an agent's own identity must hold on a secret.
const (
	permAccess = "secretmanager.versions.access"
	permAdd    = "secretmanager.versions.add"
)

var (
	_ stores.AgentAccess      = (*Adapter)(nil)
	_ stores.AgentFederation  = (*Adapter)(nil)
	_ stores.SessionForgetter = (*Adapter)(nil)
)

// serviceAccountPattern is a service account email or unique ID, the only
// thing interpolated into the IAM Credentials path.
var serviceAccountPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@-]{0,253}$`)

// FederationMethods implements [stores.AgentFederation].
func (a *Adapter) FederationMethods() []string { return []string{stores.FederationGCP} }

// ForgetSession implements [stores.SessionForgetter].
func (a *Adapter) ForgetSession(id string) { a.agents.ForgetSession(id) }

// AgentCan implements [stores.AgentAccess]. It exchanges an identity token
// scrim signs for the agent at Google's STS (workload identity federation),
// impersonates the configured service account when there is one, and asks
// Secret Manager, with that token, whether it holds
// secretmanager.versions.access (read) or secretmanager.versions.add
// (write) on the secret (testIamPermissions). The value is never read with
// the agent's token. A static agent token (identity.store-credentials) is
// used as an access token as is.
func (a *Adapter) AgentCan(ctx context.Context, cred stores.AgentCredential, op stores.Op, ref stores.Ref) error {
	t, err := a.resolve(ctx, op, ref)
	if err != nil {
		return err
	}
	var tok secret.Value
	switch {
	case !cred.Token.IsZero():
		tok = clone(cred.Token)
	case cred.Federation != nil:
		if tok, err = a.agentToken(ctx, op, ref, cred.Federation); err != nil {
			return err
		}
	default:
		return a.errorf(op, ref, stores.ErrPermission, "no agent credential")
	}
	defer tok.Wipe()
	perm := permAccess
	if op == stores.OpWrite {
		perm = permAdd
	}
	body, _ := wire.AppendJSON(nil, map[string][]string{"permissions": {perm}})
	b, err := a.c.doAs(ctx, tok, http.MethodPost, t.path+":testIamPermissions", nil, wire.NewBody(body), nil)
	if err != nil {
		return a.fail(op, ref, err)
	}
	defer secret.WipeBytes(b)
	var out struct {
		Permissions []string `json:"permissions"`
	}
	if json.Unmarshal(b, &out) != nil {
		return a.errorf(op, ref, stores.ErrUnavailable, "malformed testIamPermissions response")
	}
	if slices.Contains(out.Permissions, perm) {
		return nil
	}
	return a.errorf(op, ref, stores.ErrPermission, "the agent's own Google identity lacks "+perm+" on this secret")
}

// agentToken returns a copy of the agent's access token, exchanging a new
// identity token when none is cached. The caller wipes it.
func (a *Adapter) agentToken(ctx context.Context, op stores.Op, ref stores.Ref, f *stores.Federation) (secret.Value, error) {
	if f.Method != stores.FederationGCP {
		return secret.Value{}, a.errorf(op, ref, stores.ErrUnsupported, "token exchange method "+f.Method+" is not one this store takes ("+stores.FederationGCP+")")
	}
	provider, sa := f.Params["provider"], f.Params["service-account"]
	if provider == "" || f.Token == nil {
		return secret.Value{}, a.errorf(op, ref, stores.ErrPermission, "no agent credential")
	}
	if sa != "" && !serviceAccountPattern.MatchString(sa) {
		return secret.Value{}, a.errorf(op, ref, stores.ErrInvalidRef, "service-account is not a service account email or ID")
	}
	if v, ok := a.agents.Get(f.Key); ok {
		return v, nil
	}
	jwt, err := f.Token()
	if err != nil {
		return secret.Value{}, a.errorf(op, ref, stores.ErrPermission, "no identity token for the agent")
	}
	tok, ttl, err := a.stsExchange(ctx, provider, jwt)
	jwt.Wipe()
	if err != nil {
		return secret.Value{}, a.fail(op, ref, err)
	}
	if sa != "" {
		imp, impTTL, err := a.impersonate(ctx, tok, sa)
		tok.Wipe()
		if err != nil {
			return secret.Value{}, a.fail(op, ref, err)
		}
		tok, ttl = imp, impTTL
	}
	a.agents.Put(f.Key, f.Session, tok, ttl)
	return clone(tok), nil
}

// stsExchange trades the agent's identity token for a federated access
// token (RFC 8693 at Google STS).
func (a *Adapter) stsExchange(ctx context.Context, provider string, jwt secret.Value) (secret.Value, time.Duration, error) {
	var buf []byte
	buf = wire.AppendForm(buf, "grant_type", []byte("urn:ietf:params:oauth:grant-type:token-exchange"))
	buf = wire.AppendForm(buf, "audience", []byte(provider))
	buf = wire.AppendForm(buf, "scope", []byte(scope))
	buf = wire.AppendForm(buf, "requested_token_type", []byte("urn:ietf:params:oauth:token-type:access_token"))
	buf = wire.AppendForm(buf, "subject_token_type", []byte("urn:ietf:params:oauth:token-type:jwt"))
	buf = wire.AppendFormValue(buf, "subject_token", jwt)
	body := wire.NewBody(buf)
	defer body.Wipe()
	b, status, err := a.post(ctx, strings.TrimRight(a.c.auth.sts, "/")+"/v1/token", "application/x-www-form-urlencoded", body, secret.Value{})
	if err != nil {
		return secret.Value{}, 0, err
	}
	defer secret.WipeBytes(b)
	if status != http.StatusOK {
		return secret.Value{}, 0, tokenStatus("Google STS refused the agent's identity token", status, b, jwt)
	}
	var out struct {
		AccessToken wire.Raw `json:"access_token"`
		ExpiresIn   int64    `json:"expires_in"`
	}
	err = json.Unmarshal(b, &out)
	defer out.AccessToken.Wipe()
	if err != nil || len(out.AccessToken) == 0 {
		return secret.Value{}, 0, &apiError{kind: stores.ErrUnavailable, msg: "malformed STS response"}
	}
	v, err := out.AccessToken.Value()
	if err != nil {
		return secret.Value{}, 0, &apiError{kind: stores.ErrUnavailable, msg: "malformed STS response"}
	}
	return v, time.Duration(out.ExpiresIn) * time.Second, nil
}

// impersonate mints a token for sa with the federated token (IAM
// Credentials generateAccessToken).
func (a *Adapter) impersonate(ctx context.Context, fed secret.Value, sa string) (secret.Value, time.Duration, error) {
	reqBody, _ := wire.AppendJSON(nil, map[string]any{"scope": []string{scope}, "lifetime": "3600s"})
	u := strings.TrimRight(a.c.auth.iam, "/") + "/v1/projects/-/serviceAccounts/" + sa + ":generateAccessToken"
	b, status, err := a.post(ctx, u, "application/json", wire.NewBody(reqBody), fed)
	if err != nil {
		return secret.Value{}, 0, err
	}
	defer secret.WipeBytes(b)
	if status != http.StatusOK {
		return secret.Value{}, 0, tokenStatus("IAM Credentials refused to impersonate "+sa+" for the agent", status, b, fed)
	}
	var out struct {
		AccessToken wire.Raw  `json:"accessToken"`
		ExpireTime  time.Time `json:"expireTime"`
	}
	err = json.Unmarshal(b, &out)
	defer out.AccessToken.Wipe()
	if err != nil || len(out.AccessToken) == 0 {
		return secret.Value{}, 0, &apiError{kind: stores.ErrUnavailable, msg: "malformed impersonation response"}
	}
	v, err := out.AccessToken.Value()
	if err != nil {
		return secret.Value{}, 0, &apiError{kind: stores.ErrUnavailable, msg: "malformed impersonation response"}
	}
	return v, time.Until(out.ExpireTime), nil
}

// post sends body to u, with bearer when it is set, and returns the
// response body (the caller wipes it) and status.
func (a *Adapter) post(ctx context.Context, u, contentType string, body *wire.Body, bearer secret.Value) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, body.Reader())
	if err != nil {
		return nil, 0, &apiError{kind: stores.ErrInvalidRef, msg: "cannot build the token request"}
	}
	req.ContentLength = int64(body.Len())
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Accept", "application/json")
	if !bearer.IsZero() {
		_ = bearer.Expose(func(b []byte) error { req.Header.Set("Authorization", "Bearer "+string(b)); return nil })
	}
	resp, err := a.c.http.Do(req)
	if err != nil {
		return nil, 0, &apiError{kind: stores.ErrUnavailable, msg: "token endpoint unreachable", cause: scrubURLError(err)}
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := wire.ReadBody(resp.Body)
	if err != nil {
		return nil, 0, &apiError{kind: stores.ErrUnavailable, msg: "reading the token response failed"}
	}
	return b, resp.StatusCode, nil
}

// tokenStatus classifies a refused token request: 429 and 5xx are an
// outage, anything else a refusal of the agent's identity. The endpoint's
// own description is kept only when it quotes none of involved.
func tokenStatus(what string, status int, body []byte, involved ...secret.Value) error {
	kind := stores.ErrPermission
	if status == http.StatusTooManyRequests || status >= 500 {
		kind = stores.ErrUnavailable
	}
	var e struct {
		Description string `json:"error_description"`
		Error       any    `json:"error"`
	}
	_ = json.Unmarshal(body, &e)
	desc := e.Description
	if desc == "" {
		if m, ok := e.Error.(map[string]any); ok {
			desc, _ = m["message"].(string)
		}
	}
	msg := fmt.Sprintf("%s (HTTP %d)", what, status)
	if d := wire.SafeDetail(desc, involved...); d != "" && !bytes.Contains([]byte(d), []byte("eyJ")) {
		msg += ": " + d
	}
	return &apiError{kind: kind, msg: msg}
}
