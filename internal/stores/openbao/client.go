// SPDX-License-Identifier: AGPL-3.0-only

package openbao

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores"
	"github.com/heliopsy/scrim/internal/stores/internal/wire"
)

// client speaks the OpenBao HTTP API for one instance: authentication,
// requests and the mapping of responses to stores error kinds.
type client struct {
	name    string
	opts    Options
	http    *http.Client
	resolve func(context.Context, config.SecretRef) (secret.Value, error)
	now     func() time.Time

	mu sync.Mutex
	// token is the token sent with requests: the configured token, or the
	// client token from the last AppRole login.
	token secret.Value
	// expires is when an AppRole token should be replaced; zero means
	// never (static tokens, or tokens without a TTL).
	expires time.Time
	// creds holds the resolved login material (token or role and secret
	// ID), kept for Credentials and for logging in again.
	creds  map[string]secret.Value
	closed bool
}

func newHTTPClient(o Options) (*http.Client, error) {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, ServerName: o.ServerName}
	if o.CAFile != "" {
		pem, err := os.ReadFile(o.CAFile)
		if err != nil {
			return nil, fmt.Errorf("option %q: %w", optCAFile, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("option %q: no PEM certificates in %s", optCAFile, o.CAFile)
		}
		tr.TLSClientConfig.RootCAs = pool
	}
	return &http.Client{
		Transport: tr,
		Timeout:   o.Timeout,
		// A redirect would resend the token elsewhere; OpenBao standbys
		// forward requests themselves, so refuse redirects outright.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}, nil
}

// apiError is an OpenBao error response.
type apiError struct {
	Errors []string `json:"errors"`
}

// response is a decoded reply: status and body. The body may hold secret
// values; the caller wipes it.
type response struct {
	status int
	body   []byte
}

func (r *response) wipe() {
	if r != nil {
		secret.WipeBytes(r.body)
	}
}

// request describes one API call.
type request struct {
	op     stores.Op
	ref    stores.Ref
	method string
	// path is relative to /v1/, already escaped.
	path  string
	query url.Values
	body  *wire.Body
	// involved are the values sent in this request, so an error message
	// echoing one is withheld.
	involved []secret.Value
	// noAuth sends no token (sys/health, login).
	noAuth bool
}

func (c *client) storeErr(r request, kind error, detail string, cause error) *stores.Error {
	e := stores.NewError(c.name, r.op, r.ref, kind, cause)
	e.Detail = detail
	return e
}

// do runs r, logging in first when needed and once more when the store
// rejects a token it should have accepted. A non-2xx status is returned as a
// classified error; the response is still returned for 404 bodies.
func (c *client) do(ctx context.Context, r request) (*response, error) {
	resp, err := c.attempt(ctx, r)
	if err == nil || r.noAuth || c.opts.AuthMethod != AuthAppRole || !errors.Is(err, stores.ErrPermission) {
		return resp, err
	}
	// A 403 with AppRole may be an expired or revoked client token. Log
	// in again once; a second 403 is a real policy refusal.
	resp.wipe()
	c.dropToken()
	return c.attempt(ctx, r)
}

func (c *client) attempt(ctx context.Context, r request) (*response, error) {
	var token secret.Value
	if !r.noAuth {
		var err error
		if token, err = c.currentToken(ctx, r); err != nil {
			return nil, err
		}
	}
	u := *c.opts.Address
	u.Path = c.opts.Address.Path + "/v1/" + r.path
	u.RawPath = c.opts.Address.EscapedPath() + "/v1/" + r.path
	if r.query != nil {
		u.RawQuery = r.query.Encode()
	}
	var body io.Reader
	if r.body != nil {
		body = r.body.Reader()
	}
	req, err := http.NewRequestWithContext(ctx, r.method, u.String(), body)
	if err != nil {
		return nil, c.storeErr(r, stores.ErrInvalidRef, "cannot build request", err)
	}
	if r.body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.opts.Namespace != "" {
		req.Header.Set("X-Vault-Namespace", c.opts.Namespace)
	}
	req.Header.Set("X-Vault-Request", "true")
	if !r.noAuth {
		// net/http takes header values as strings, so the token exists as a
		// Go string for the life of this request. This is the one place a
		// store credential leaves secret.Value; see the package docs.
		_ = token.Expose(func(b []byte) error {
			req.Header["X-Vault-Token"] = []string{string(b)}
			return nil
		})
	}
	hr, err := c.http.Do(req)
	if err != nil {
		return nil, c.storeErr(r, stores.ErrUnavailable, transportDetail(ctx, err), err)
	}
	defer func() { _ = hr.Body.Close() }()
	b, err := wire.ReadBody(hr.Body)
	if err != nil {
		return nil, c.storeErr(r, stores.ErrUnavailable, "reading response: "+err.Error(), nil)
	}
	resp := &response{status: hr.StatusCode, body: b}
	if hr.StatusCode >= 200 && hr.StatusCode < 300 {
		return resp, nil
	}
	kind, detail := classify(hr.StatusCode, b)
	if detail != "" {
		detail = wire.SafeDetail(detail, r.involved...)
	}
	if kind != stores.ErrNotFound {
		resp.wipe()
		resp = nil
	}
	return resp, c.storeErr(r, kind, detail, nil)
}

func transportDetail(ctx context.Context, err error) string {
	switch {
	case errors.Is(ctx.Err(), context.Canceled):
		return "request cancelled"
	case errors.Is(ctx.Err(), context.DeadlineExceeded), errors.Is(err, context.DeadlineExceeded):
		return "request timed out"
	}
	var ue *url.Error
	if errors.As(err, &ue) && ue.Timeout() {
		return "request timed out"
	}
	return "cannot reach the store"
}

// classify maps an OpenBao status to an error kind and the store's own
// message. OpenBao's messages for KV operations do not echo request data,
// but callers still pass them through wire.SafeDetail.
func classify(status int, body []byte) (kind error, detail string) { //nolint:staticcheck // kind is a sentinel, not a failure of classify
	var ae apiError
	_ = json.Unmarshal(body, &ae)
	msg := strings.Join(ae.Errors, "; ")
	switch {
	case status == http.StatusNotFound:
		return stores.ErrNotFound, ""
	case status == http.StatusForbidden || status == http.StatusUnauthorized:
		if msg == "" {
			msg = "permission denied"
		}
		return stores.ErrPermission, msg
	case status == http.StatusBadRequest && strings.Contains(msg, "check-and-set"):
		return stores.ErrConflict, msg
	case status == http.StatusBadRequest || status == http.StatusMethodNotAllowed:
		if msg == "" {
			msg = http.StatusText(status)
		}
		return stores.ErrInvalidRef, msg
	case status == http.StatusServiceUnavailable && strings.Contains(msg, "sealed"):
		return stores.ErrUnavailable, "store is sealed"
	default:
		if msg == "" {
			msg = http.StatusText(status)
		}
		return stores.ErrUnavailable, fmt.Sprintf("HTTP %d: %s", status, msg)
	}
}

// currentToken returns the token to send, logging in when there is none or
// it is about to expire.
func (c *client) currentToken(ctx context.Context, r request) (secret.Value, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return secret.Value{}, c.storeErr(r, stores.ErrUnavailable, "adapter closed", nil)
	}
	if !c.token.IsZero() && (c.expires.IsZero() || c.now().Before(c.expires)) {
		return c.token, nil
	}
	if err := c.loadCredsLocked(ctx, r); err != nil {
		return secret.Value{}, err
	}
	switch c.opts.AuthMethod {
	case AuthToken:
		c.token = copyValue(c.creds[optAuthToken])
		c.expires = time.Time{}
	case AuthAppRole:
		if err := c.loginAppRoleLocked(ctx, r); err != nil {
			return secret.Value{}, err
		}
	}
	return c.token, nil
}

// loadCredsLocked resolves the configured credential references once.
func (c *client) loadCredsLocked(ctx context.Context, r request) error {
	if c.creds != nil {
		return nil
	}
	keys := []string{optAuthToken}
	refs := []config.SecretRef{c.opts.Token}
	if c.opts.AuthMethod == AuthAppRole {
		keys = []string{optAppRoleRoleID, optAppRoleSecretID}
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
			return c.storeErr(r, stores.ErrPermission,
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
	} `json:"auth"`
}

func (c *client) loginAppRoleLocked(ctx context.Context, r request) error {
	buf := []byte(`{"role_id":`)
	var err error
	if buf, err = wire.AppendValue(buf, c.creds[optAppRoleRoleID]); err != nil {
		secret.WipeBytes(buf)
		return c.storeErr(r, stores.ErrPermission, "role ID is not valid UTF-8", nil)
	}
	buf = append(buf, `,"secret_id":`...)
	if buf, err = wire.AppendValue(buf, c.creds[optAppRoleSecretID]); err != nil {
		secret.WipeBytes(buf)
		return c.storeErr(r, stores.ErrPermission, "secret ID is not valid UTF-8", nil)
	}
	body := wire.NewBody(append(buf, '}'))
	defer body.Wipe()
	login := request{
		op: r.op, ref: r.ref, method: http.MethodPost, noAuth: true,
		path:     "auth/" + escapePath(c.opts.AppRoleMount) + "/login",
		body:     body,
		involved: []secret.Value{c.creds[optAppRoleRoleID], c.creds[optAppRoleSecretID]},
	}
	start := c.now()
	resp, err := c.attempt(ctx, login)
	if err != nil {
		var se *stores.Error
		if errors.As(err, &se) {
			se.Detail = strings.TrimSpace("AppRole login failed: " + se.Detail)
			// OpenBao answers a bad role or secret ID with 400, and a
			// missing AppRole mount with 404 or 405: all mean scrim cannot
			// log in, which is a credentials problem, not a bad reference.
			if errors.Is(err, stores.ErrNotFound) || errors.Is(err, stores.ErrInvalidRef) {
				se.Kind = stores.ErrPermission
			}
		}
		return err
	}
	defer resp.wipe()
	var ar authResponse
	if err := json.Unmarshal(resp.body, &ar); err != nil || ar.Auth == nil {
		return c.storeErr(r, stores.ErrPermission, "AppRole login returned no token", nil)
	}
	defer ar.Auth.ClientToken.Wipe()
	tok, err := ar.Auth.ClientToken.Value()
	if err != nil || tok.IsZero() {
		return c.storeErr(r, stores.ErrPermission, "AppRole login returned no token", nil)
	}
	c.token.Wipe()
	c.token = tok
	c.expires = time.Time{}
	if ar.Auth.LeaseDuration > 0 {
		// Replace the token at two thirds of its TTL, well before it
		// expires, so a slow request never carries an expired token.
		ttl := time.Duration(ar.Auth.LeaseDuration) * time.Second
		c.expires = start.Add(ttl * 2 / 3)
	}
	return nil
}

// dropToken forgets the current token so the next request logs in again.
func (c *client) dropToken() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.token.Wipe()
	c.token = secret.Value{}
}

// credentials returns copies of the login material and the current token.
func (c *client) credentials() []secret.Value {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []secret.Value
	for _, v := range c.creds {
		if !v.IsZero() {
			out = append(out, copyValue(v))
		}
	}
	if !c.token.IsZero() {
		out = append(out, copyValue(c.token))
	}
	return out
}

func (c *client) close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	c.token.Wipe()
	for _, v := range c.creds {
		v.Wipe()
	}
	c.creds = nil
	c.http.CloseIdleConnections()
}

func copyValue(v secret.Value) secret.Value {
	var out secret.Value
	_ = v.Expose(func(b []byte) error {
		out = secret.New(b)
		return nil
	})
	return out
}

// escapePath escapes each segment of a slash-separated path.
func escapePath(p string) string {
	segs := strings.Split(p, "/")
	for i, s := range segs {
		segs[i] = url.PathEscape(s)
	}
	return strings.Join(segs, "/")
}
