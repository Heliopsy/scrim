// SPDX-License-Identifier: AGPL-3.0-only

package vaultapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores"
	"github.com/heliopsy/scrim/internal/stores/internal/satoken"
	"github.com/heliopsy/scrim/internal/stores/internal/wire"
)

// Token lifecycle. A login (AppRole, Kubernetes or JWT) issues a token with
// a lease. Two thirds into the lease the client renews the token with
// renew-self when the store says it is renewable, and logs in again when it
// is not, when renewal fails or is refused, or when a renewal comes back
// shorter than asked for (the token's max TTL is near). A request refused
// with 403 drops the token and logs in again once before failing.

// currentToken returns a copy of the token to send, which the caller wipes,
// renewing it or logging in when there is none or its refresh time passed.
// The copy keeps a concurrent renewal from wiping a token mid-request.
func (c *Client) currentToken(ctx context.Context, r Request) (secret.Value, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return secret.Value{}, c.StoreErr(r, stores.ErrUnavailable, "adapter closed", nil)
	}
	now := c.Now()
	if !c.token.IsZero() && (c.refreshAt.IsZero() || now.Before(c.refreshAt)) {
		return CopyValue(c.token), nil
	}
	if !c.token.IsZero() && c.renewable && (c.expires.IsZero() || now.Before(c.expires)) {
		if c.renewLocked(ctx, r) == nil {
			return CopyValue(c.token), nil
		}
		// Whatever went wrong with the renewal, a new login is the fix.
	}
	if err := c.loginLocked(ctx, r); err != nil {
		return secret.Value{}, err
	}
	return CopyValue(c.token), nil
}

// loginLocked replaces the token with a fresh one for the configured method.
func (c *Client) loginLocked(ctx context.Context, r Request) error {
	start := c.Now()
	var (
		tok       secret.Value
		ttl       time.Duration
		renewable bool
		err       error
	)
	switch c.opts.AuthMethod {
	case AuthToken:
		if err = c.loadCredsLocked(ctx, r); err != nil {
			return err
		}
		tok = CopyValue(c.creds[OptAuthToken])
	case AuthAppRole:
		if err = c.loadCredsLocked(ctx, r); err != nil {
			return err
		}
		tok, ttl, renewable, err = c.loginAppRole(ctx, r)
	case AuthKubernetes:
		var jwt secret.Value
		// Read the file at every login: the kubelet rotates projected
		// tokens, and an old one stops working.
		if jwt, err = satoken.Read(c.opts.K8sTokenFile); err != nil {
			return c.StoreErr(r, stores.ErrPermission, fmt.Sprintf("option %s: %v", OptK8sTokenFile, err), nil)
		}
		tok, ttl, renewable, err = c.LoginKubernetes(ctx, r.Op, r.Ref, c.opts.K8sMount, c.opts.K8sRole, jwt)
		jwt.Wipe()
	case AuthJWT:
		var jwt secret.Value
		if jwt, err = c.readJWT(ctx, r); err != nil {
			return err
		}
		tok, ttl, renewable, err = c.LoginJWT(ctx, r.Op, r.Ref, c.opts.JWTMount, c.opts.JWTRole, jwt)
		jwt.Wipe()
	default:
		return c.StoreErr(r, stores.ErrPermission, "unsupported auth method "+c.opts.AuthMethod, nil)
	}
	if err != nil {
		return err
	}
	c.token.Wipe()
	c.token = tok
	c.ttl = ttl
	c.setLeaseLocked(start, ttl, renewable)
	return nil
}

// readJWT reads the JWT for a JWT login, from its file or its reference,
// at every login: whoever issues it rotates it.
func (c *Client) readJWT(ctx context.Context, r Request) (secret.Value, error) {
	if c.opts.JWTTokenFile != "" {
		jwt, err := satoken.Read(c.opts.JWTTokenFile)
		if err != nil {
			return secret.Value{}, c.StoreErr(r, stores.ErrPermission, fmt.Sprintf("option %s: %v", OptJWTTokenFile, err), nil)
		}
		return jwt, nil
	}
	jwt, err := c.resolve(ctx, c.opts.JWT)
	if err == nil && jwt.IsZero() {
		err = errors.New("resolved to an empty value")
	}
	if err != nil {
		return secret.Value{}, c.StoreErr(r, stores.ErrPermission, fmt.Sprintf("option %s: cannot resolve %s", OptJWT, c.opts.JWT), err)
	}
	return jwt, nil
}

// setLeaseLocked records a lease of ttl starting at start.
func (c *Client) setLeaseLocked(start time.Time, ttl time.Duration, renewable bool) {
	c.renewable = renewable && ttl > 0
	if ttl <= 0 {
		c.refreshAt, c.expires = time.Time{}, time.Time{}
		return
	}
	// Act at two thirds of the TTL, well before it ends, so a slow request
	// never carries an expired token.
	c.expires = start.Add(ttl)
	c.refreshAt = start.Add(ttl * 2 / 3)
}

// renewLocked extends the current token's lease by the login TTL.
func (c *Client) renewLocked(ctx context.Context, r Request) error {
	start := c.Now()
	tok := CopyValue(c.token)
	defer tok.Wipe()
	ttl, renewable, err := c.RenewSelf(ctx, r.Op, r.Ref, tok, c.ttl)
	if err != nil {
		return err
	}
	if ttl <= 0 {
		return c.StoreErr(r, stores.ErrPermission, "token renewal granted no lease", nil)
	}
	// A renewal shorter than asked for was capped by the max TTL: use what
	// is left, then log in again instead of renewing.
	c.setLeaseLocked(start, ttl, renewable && ttl >= c.ttl)
	return nil
}

// loadCredsLocked resolves the configured credential references once.
func (c *Client) loadCredsLocked(ctx context.Context, r Request) error {
	if c.creds != nil {
		return nil
	}
	keys := []string{OptAuthToken}
	refs := []config.SecretRef{c.opts.Token}
	if c.opts.AuthMethod == AuthAppRole {
		keys = []string{OptAppRoleRoleID, OptAppRoleSecretID}
		refs = []config.SecretRef{c.opts.RoleID, c.opts.SecretID}
	}
	creds := map[string]secret.Value{}
	for i, key := range keys {
		v, err := c.resolve(ctx, refs[i])
		if err == nil && v.IsZero() {
			err = errors.New("resolved to an empty value")
		}
		if err != nil {
			for _, v := range creds {
				v.Wipe()
			}
			// The reference names a source (env:, file:), not a value, and
			// is safe to show.
			return c.StoreErr(r, stores.ErrPermission,
				fmt.Sprintf("option %s: cannot resolve %s", key, refs[i]), err)
		}
		creds[key] = v
	}
	c.creds = creds
	return nil
}

type authResponse struct {
	Auth *struct {
		ClientToken   wire.Raw `json:"client_token"`
		LeaseDuration int64    `json:"lease_duration"`
		Renewable     bool     `json:"renewable"`
	} `json:"auth"`
}

// parseAuth decodes the auth block of a login or renewal reply. The token
// is returned as a new value; every other copy is wiped.
func (c *Client) parseAuth(r Request, body []byte, what string) (secret.Value, time.Duration, bool, error) {
	var ar authResponse
	err := json.Unmarshal(body, &ar)
	if ar.Auth != nil {
		defer ar.Auth.ClientToken.Wipe()
	}
	if err != nil || ar.Auth == nil {
		return secret.Value{}, 0, false, c.StoreErr(r, stores.ErrPermission, what+" returned no token", nil)
	}
	tok, err := ar.Auth.ClientToken.Value()
	if err != nil {
		tok.Wipe()
		return secret.Value{}, 0, false, c.StoreErr(r, stores.ErrPermission, what+" returned no token", nil)
	}
	return tok, time.Duration(ar.Auth.LeaseDuration) * time.Second, ar.Auth.Renewable, nil
}

// login posts body to auth/<mount>/login and returns the token it issues.
// It touches none of the client's own token state. method names the auth
// method in errors.
func (c *Client) login(ctx context.Context, op stores.Op, ref stores.Ref, method, mount string, body *wire.Body, involved []secret.Value) (secret.Value, time.Duration, bool, error) {
	r := Request{
		Op: op, Ref: ref, Method: http.MethodPost, NoAuth: true,
		Path: "auth/" + EscapePath(mount) + "/login", Body: body, Involved: involved,
		Namespace: c.opts.AuthNamespace,
	}
	resp, err := c.Attempt(ctx, r, secret.Value{})
	if err != nil {
		resp.Wipe()
		var se *stores.Error
		if errors.As(err, &se) {
			se.Detail = strings.TrimSpace(method + " login failed: " + se.Detail)
			// The store answers a bad role or credential with 400, and a
			// missing auth mount with 404 or 405: all mean scrim cannot log
			// in, which is a credentials problem, not a bad reference.
			if errors.Is(err, stores.ErrNotFound) || errors.Is(err, stores.ErrInvalidRef) {
				se.Kind = stores.ErrPermission
			}
		}
		return secret.Value{}, 0, false, err
	}
	defer resp.Wipe()
	tok, ttl, renewable, err := c.parseAuth(r, resp.Body, method+" login")
	if err == nil && tok.IsZero() {
		err = c.StoreErr(r, stores.ErrPermission, method+" login returned no token", nil)
	}
	return tok, ttl, renewable, err
}

func (c *Client) loginAppRole(ctx context.Context, r Request) (secret.Value, time.Duration, bool, error) {
	roleID, secretID := c.creds[OptAppRoleRoleID], c.creds[OptAppRoleSecretID]
	buf := []byte(`{"role_id":`)
	var err error
	if buf, err = wire.AppendValue(buf, roleID); err != nil {
		secret.WipeBytes(buf)
		return secret.Value{}, 0, false, c.StoreErr(r, stores.ErrPermission, "role ID is not valid UTF-8", nil)
	}
	buf = append(buf, `,"secret_id":`...)
	if buf, err = wire.AppendValue(buf, secretID); err != nil {
		secret.WipeBytes(buf)
		return secret.Value{}, 0, false, c.StoreErr(r, stores.ErrPermission, "secret ID is not valid UTF-8", nil)
	}
	body := wire.NewBody(append(buf, '}'))
	defer body.Wipe()
	return c.login(ctx, r.Op, r.Ref, "AppRole", c.opts.AppRoleMount, body, []secret.Value{roleID, secretID})
}

// LoginKubernetes logs in to the Kubernetes auth method mounted at mount as
// role, presenting jwt (a service account token), and returns the issued
// token, its TTL and whether it is renewable. It does not touch the
// client's own token, so it serves logins on behalf of other service
// accounts as well. jwt stays owned by the caller; the returned token is
// owned by the caller too. op and ref only label errors.
func (c *Client) LoginKubernetes(ctx context.Context, op stores.Op, ref stores.Ref, mount, role string, jwt secret.Value) (token secret.Value, ttl time.Duration, renewable bool, err error) {
	return c.loginJWTLike(ctx, op, ref, "Kubernetes", "service account token", mount, role, jwt)
}

// LoginJWT logs in to the JWT auth method mounted at mount as role,
// presenting jwt, like [Client.LoginKubernetes].
func (c *Client) LoginJWT(ctx context.Context, op stores.Op, ref stores.Ref, mount, role string, jwt secret.Value) (token secret.Value, ttl time.Duration, renewable bool, err error) {
	return c.loginJWTLike(ctx, op, ref, "JWT", "JWT", mount, role, jwt)
}

// loginJWTLike posts {"role":role,"jwt":jwt}, which Kubernetes and JWT
// auth both take.
func (c *Client) loginJWTLike(ctx context.Context, op stores.Op, ref stores.Ref, method, what, mount, role string, jwt secret.Value) (secret.Value, time.Duration, bool, error) {
	r := Request{Op: op, Ref: ref}
	if jwt.IsZero() {
		return secret.Value{}, 0, false, c.StoreErr(r, stores.ErrPermission, method+" login failed: empty "+what, nil)
	}
	buf, err := wire.AppendJSON([]byte(`{"role":`), role)
	if err != nil {
		return secret.Value{}, 0, false, c.StoreErr(r, stores.ErrInvalidRef, "cannot encode the role", err)
	}
	buf = append(buf, `,"jwt":`...)
	if buf, err = wire.AppendValue(buf, jwt); err != nil {
		secret.WipeBytes(buf)
		return secret.Value{}, 0, false, c.StoreErr(r, stores.ErrPermission, what+" is not valid UTF-8", nil)
	}
	body := wire.NewBody(append(buf, '}'))
	defer body.Wipe()
	return c.login(ctx, op, ref, method, mount, body, []secret.Value{jwt})
}

// RenewSelf renews token with auth/token/renew-self, asking for increment
// (zero leaves the choice to the store), and returns the new lease and
// whether the token can be renewed again. token stays owned by the caller.
// A failure is returned as is; the caller decides whether to log in again.
func (c *Client) RenewSelf(ctx context.Context, op stores.Op, ref stores.Ref, token secret.Value, increment time.Duration) (ttl time.Duration, renewable bool, err error) {
	var body *wire.Body
	if increment > 0 {
		body = wire.NewBody([]byte(`{"increment":"` + strconv.FormatInt(int64(increment/time.Second), 10) + `s"}`))
	}
	r := Request{
		Op: op, Ref: ref, Method: http.MethodPost, Path: "auth/token/renew-self",
		Body: body, Token: token, Involved: []secret.Value{token},
	}
	if token.IsZero() {
		return 0, false, c.StoreErr(r, stores.ErrPermission, "token renewal: no token", nil)
	}
	resp, err := c.Do(ctx, r)
	if err != nil {
		resp.Wipe()
		var se *stores.Error
		if errors.As(err, &se) {
			se.Detail = strings.TrimSpace("token renewal failed: " + se.Detail)
		}
		return 0, false, err
	}
	defer resp.Wipe()
	tok, ttl, renewable, err := c.parseAuth(r, resp.Body, "token renewal")
	tok.Wipe()
	return ttl, renewable, err
}

// DropToken forgets the token used, if it is still the current one, so the
// next request logs in again. A token another request already replaced is
// left alone.
func (c *Client) DropToken(used secret.Value) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.token.IsZero() && !c.token.Equal(used) {
		return
	}
	c.token.Wipe()
	c.token = secret.Value{}
	c.refreshAt, c.expires, c.renewable = time.Time{}, time.Time{}, false
}
