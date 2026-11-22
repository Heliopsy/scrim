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
	// client token from the last AppRole or Kubernetes login.
	token secret.Value
	// ttl is the lease the last login granted, and the increment asked for
	// when renewing. Zero means the token has no TTL.
	ttl time.Duration
	// refreshAt is when the token is renewed or replaced (two thirds into
	// its lease); expires is when the lease ends. Zero means never.
	refreshAt time.Time
	expires   time.Time
	// renewable is whether renew-self is worth trying at refreshAt. It is
	// cleared once a renewal comes back shorter than asked for, which means
	// the token's max TTL is near and only a new login helps.
	renewable bool
	// creds holds the resolved login material (token or role and secret
	// ID), kept for Credentials and for logging in again. Kubernetes auth
	// holds none: the service account token is read at each login and
	// wiped after it.
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
	// token, when set, is sent instead of the adapter's own token, and a
	// refusal is returned as is: the adapter neither logs in nor retries.
	// The caller owns it. It is for acting with a token scrim obtained on
	// someone else's behalf, and for renewing a token.
	token secret.Value
	// optional marks a lookup whose failure the caller ignores (labels): a
	// refusal is returned as is, without logging in again.
	optional bool
}

func (c *client) storeErr(r request, kind error, detail string, cause error) *stores.Error {
	e := stores.NewError(c.name, r.op, r.ref, kind, cause)
	e.Detail = detail
	return e
}

// do runs r with the adapter's token, logging in first when needed and once
// more when the store rejects a token it should have accepted. A request
// with its own token or none is sent once. A non-2xx status is returned as a
// classified error; the response is still returned for 404 bodies.
func (c *client) do(ctx context.Context, r request) (*response, error) {
	if r.noAuth || !r.token.IsZero() {
		return c.attempt(ctx, r, r.token)
	}
	tok, err := c.currentToken(ctx, r)
	if err != nil {
		return nil, err
	}
	resp, err := c.attempt(ctx, r, tok)
	if err == nil || c.opts.AuthMethod == AuthToken || r.optional || !errors.Is(err, stores.ErrPermission) {
		tok.Wipe()
		return resp, err
	}
	// A 403 on a login token may mean it expired or was revoked. Log in
	// again once; a second 403 is a real policy refusal.
	resp.wipe()
	c.dropToken(tok)
	tok.Wipe()
	if tok, err = c.currentToken(ctx, r); err != nil {
		return nil, err
	}
	defer tok.Wipe()
	return c.attempt(ctx, r, tok)
}

// attempt sends r once, with token unless r.noAuth.
func (c *client) attempt(ctx context.Context, r request, token secret.Value) (*response, error) {
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
		if err := token.Expose(func(b []byte) error {
			if len(b) == 0 {
				return secret.ErrWiped
			}
			req.Header["X-Vault-Token"] = []string{string(b)}
			return nil
		}); err != nil {
			return nil, c.storeErr(r, stores.ErrPermission, "no token to send", nil)
		}
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
