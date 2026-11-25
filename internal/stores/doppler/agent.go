// SPDX-License-Identifier: AGPL-3.0-only

package doppler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
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

// oidcLoginPath is Doppler's OIDC authentication for service account
// identities. It takes no bearer: the identity token is the credential.
const oidcLoginPath = "/v3/auth/oidc"

// FederationMethods implements [stores.AgentFederation].
func (a *Adapter) FederationMethods() []string { return []string{stores.FederationDoppler} }

// ForgetSession implements [stores.SessionForgetter]: the tokens agents of
// that scrim session obtained by OIDC are wiped.
func (a *Adapter) ForgetSession(id string) { a.agents.ForgetSession(id) }

// AgentCan implements [stores.AgentAccess]. The agent's token is a Doppler
// token held for it (identity.store-credentials): a service token for the
// config it may use, or a service account token whose workplace and project
// roles say what it may do. Or it is a short-lived service account identity
// token obtained with doppler-oidc, by presenting an identity token scrim's
// issuer signs for the agent at the identity the method names.
//
// Doppler has no call that reports what a token may do with a secret
// without using it, so a read is checked by reading: the secret is fetched
// with the agent's token (the same GET /v3/configs/config/secret Read
// makes) and the value is wiped unread. A value Doppler withholds from the
// token (restricted visibility) is [stores.ErrPermission]. Writes cannot be
// checked without writing and are refused as unsupported.
func (a *Adapter) AgentCan(ctx context.Context, cred stores.AgentCredential, op stores.Op, ref stores.Ref) error {
	switch {
	case !cred.KubernetesJWT.IsZero():
		return a.refuse(op, ref, stores.ErrUnsupported, "Kubernetes passthrough is not supported for Doppler; use doppler-oidc or a Doppler token in identity.store-credentials")
	case cred.Token.IsZero() && cred.Federation == nil:
		return a.refuse(op, ref, stores.ErrPermission, "no agent credential")
	case op != stores.OpRead:
		return a.refuse(op, ref, stores.ErrUnsupported,
			"Doppler cannot report whether a token may write without writing; only reads are checked per agent")
	}
	l, ok := splitSecret(ref.Path)
	if !ok {
		return a.refuse(op, ref, stores.ErrInvalidRef, secretForm)
	}
	if err := a.checkSelectors(op, ref); err != nil {
		return err
	}
	if ref.Field != "" && ref.Field != Field {
		return a.refuse(op, ref, stores.ErrNotFound, "Doppler secrets hold a single field named "+Field)
	}
	tok := cred.Token
	if tok.IsZero() {
		var err error
		if tok, err = a.agentToken(ctx, op, ref, cred.Federation); err != nil {
			return err
		}
		defer func() { tok.Wipe() }()
	}
	q := url.Values{"project": {l.project}, "config": {l.config}, "name": {l.name}}
	b, err := a.c.doAs(ctx, http.MethodGet, "/v3/configs/config/secret", q, nil, nil, tok)
	if err != nil && cred.Token.IsZero() && isAuthError(err) {
		// Doppler no longer accepts the cached token (revoked, or expired
		// early): log in once more.
		a.agents.Forget(cred.Federation.Key)
		tok.Wipe()
		if tok, err = a.agentToken(ctx, op, ref, cred.Federation); err != nil {
			return err
		}
		b, err = a.c.doAs(ctx, http.MethodGet, "/v3/configs/config/secret", q, nil, nil, tok)
	}
	if err != nil {
		err = a.fail(op, ref, err)
		var se *stores.Error
		if errors.As(err, &se) && se.Kind == stores.ErrPermission {
			se.Detail = "the agent's own Doppler token may not read this secret: " + se.Detail
		}
		return err
	}
	defer secret.WipeBytes(b)
	var s apiSecret
	err = json.Unmarshal(b, &s)
	defer s.wipe()
	if err != nil {
		return a.refuse(op, ref, stores.ErrUnavailable, "malformed secret response")
	}
	switch computed := bytes.TrimSpace(s.Value.Computed); {
	case len(computed) == 0:
		return a.refuse(op, ref, stores.ErrUnavailable, "secret response holds no computed value")
	case bytes.Equal(computed, []byte("null")):
		return a.refuse(op, ref, stores.ErrPermission,
			"Doppler withheld the value from the agent's own token (restricted visibility)")
	}
	return nil
}

// isAuthError reports whether err is Doppler refusing the token itself
// (HTTP 401), as opposed to refusing it this secret (403).
func isAuthError(err error) bool {
	var ae *apiError
	return errors.As(err, &ae) && ae.status == http.StatusUnauthorized
}

// agentToken returns a copy of the agent's Doppler token, logging in to its
// service account identity with OIDC when none is cached. The caller wipes
// it.
func (a *Adapter) agentToken(ctx context.Context, op stores.Op, ref stores.Ref, f *stores.Federation) (secret.Value, error) {
	switch {
	case f.Method != stores.FederationDoppler:
		return secret.Value{}, a.refuse(op, ref, stores.ErrUnsupported,
			"token exchange method "+f.Method+" is not one this store takes ("+stores.FederationDoppler+")")
	case f.Params["identity"] == "" || f.Token == nil:
		return secret.Value{}, a.refuse(op, ref, stores.ErrPermission, "no agent credential")
	}
	if t, ok := a.agents.Get(f.Key); ok {
		return t, nil
	}
	jwt, err := f.Token()
	if err != nil {
		return secret.Value{}, a.refuse(op, ref, stores.ErrPermission, "no identity token for the agent")
	}
	defer jwt.Wipe()
	tok, ttl, err := a.c.oidcLogin(ctx, f.Params["identity"], jwt)
	if err != nil {
		return secret.Value{}, a.fail(op, ref, err)
	}
	a.agents.Put(f.Key, f.Session, tok, ttl)
	return copyValue(tok), nil
}

// oidcLogin exchanges jwt at POST /v3/auth/oidc for a token of the service
// account identity named identity, and returns it with its lifetime. The
// body is built so the identity token never becomes a Go string; errors keep
// Doppler's message without either token.
func (c *client) oidcLogin(ctx context.Context, identity string, jwt secret.Value) (secret.Value, time.Duration, error) {
	buf, err := wire.AppendJSON(nil, map[string]string{"identity": identity})
	if err != nil {
		return secret.Value{}, 0, &apiError{kind: stores.ErrInvalidRef, msg: "cannot encode the OIDC login"}
	}
	buf = append(buf[:len(buf)-1], `,"token":`...)
	if buf, err = wire.AppendValue(buf, jwt); err != nil {
		secret.WipeBytes(buf)
		return secret.Value{}, 0, &apiError{kind: stores.ErrPermission, msg: "the identity token cannot be encoded"}
	}
	body := wire.NewBody(append(buf, '}'))
	defer body.Wipe()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url(oidcLoginPath, nil), body.Reader())
	if err != nil {
		return secret.Value{}, 0, &apiError{kind: stores.ErrInvalidRef, msg: "cannot build the OIDC login", cause: err}
	}
	req.ContentLength = int64(body.Len())
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return secret.Value{}, 0, &apiError{kind: stores.ErrUnavailable, msg: "store unreachable", cause: scrubURLError(err)}
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := wire.ReadBody(resp.Body)
	if err != nil {
		return secret.Value{}, 0, &apiError{kind: stores.ErrUnavailable, msg: "reading the OIDC login response failed", cause: err}
	}
	defer secret.WipeBytes(b)
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		e := classify(resp.StatusCode, b, []secret.Value{jwt})
		if e.kind != stores.ErrUnavailable {
			// A refused identity or token is a credential problem
			// whatever status Doppler picks.
			e.kind = stores.ErrPermission
		}
		e.msg = "OIDC login refused: " + e.msg
		return secret.Value{}, 0, e
	}
	var out struct {
		Token     wire.Raw `json:"token"`
		ExpiresAt string   `json:"expires_at"`
	}
	err = json.Unmarshal(b, &out)
	defer out.Token.Wipe()
	if err != nil {
		return secret.Value{}, 0, &apiError{kind: stores.ErrUnavailable, msg: "malformed OIDC login response"}
	}
	tok, err := out.Token.Value()
	if err != nil || tok.IsZero() {
		tok.Wipe()
		return secret.Value{}, 0, &apiError{kind: stores.ErrUnavailable, msg: "OIDC login response holds no token"}
	}
	// Doppler documents the token as short-lived and names its expiry; an
	// expiry it does not name is treated as unknown (cached one minute).
	var ttl time.Duration
	if exp, perr := time.Parse(time.RFC3339Nano, out.ExpiresAt); perr == nil {
		if ttl = time.Until(exp); ttl <= 0 {
			tok.Wipe()
			return secret.Value{}, 0, &apiError{kind: stores.ErrPermission,
				msg: fmt.Sprintf("OIDC login returned a token that expired at %s", exp.UTC().Format(time.RFC3339))}
		}
	}
	return tok, ttl, nil
}
