// SPDX-License-Identifier: AGPL-3.0-only

// Package vaultapi speaks the HTTP API that OpenBao and HashiCorp Vault
// share, for the openbao and vault store adapters: requests and the mapping
// of responses to stores error kinds, authentication (token, AppRole,
// Kubernetes and JWT) with token renewal, lease renewal and revocation, and
// mount information.
//
// Values never pass through Go strings on the way in or out: responses are
// returned as byte slices the caller decodes with package wire and wipes,
// and request bodies are wiped after sending. The one exception is the
// token header, which net/http only accepts as a string; it lives for the
// duration of a request.
package vaultapi

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
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

// Client speaks the API for one store instance. It is safe for concurrent
// use.
type Client struct {
	name    string
	opts    Options
	http    *http.Client
	resolve func(context.Context, config.SecretRef) (secret.Value, error)
	// Now is the clock, replaceable in tests.
	Now func() time.Time
	// Log receives warnings; never values.
	Log *slog.Logger

	mu sync.Mutex
	// token is the token sent with requests: the configured token, or the
	// client token from the last login.
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
	// ID), kept for Credentials and for logging in again. Kubernetes and
	// JWT auth hold none: the token is read at each login and wiped after.
	creds  map[string]secret.Value
	closed bool
}

// New returns a client for the instance name. It does not contact the
// store.
func New(name string, o Options, resolve func(context.Context, config.SecretRef) (secret.Value, error), log *slog.Logger) (*Client, error) {
	if resolve == nil {
		return nil, fmt.Errorf("store %s: no credential resolver", name)
	}
	hc, err := newHTTPClient(o)
	if err != nil {
		return nil, fmt.Errorf("store %s: %w", name, err)
	}
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Client{name: name, opts: o, http: hc, resolve: resolve, Now: time.Now, Log: log}, nil
}

// Name is the instance name.
func (c *Client) Name() string { return c.name }

// Options returns the connection options.
func (c *Client) Options() Options { return c.opts }

func newHTTPClient(o Options) (*http.Client, error) {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, ServerName: o.ServerName}
	if o.CAFile != "" {
		pem, err := os.ReadFile(o.CAFile)
		if err != nil {
			return nil, fmt.Errorf("option %q: %w", OptCAFile, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("option %q: no PEM certificates in %s", OptCAFile, o.CAFile)
		}
		tr.TLSClientConfig.RootCAs = pool
	}
	return &http.Client{
		Transport: tr,
		Timeout:   o.Timeout,
		// A redirect would resend the token elsewhere; standbys forward
		// requests themselves, so refuse redirects outright.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}, nil
}

// apiError is an error response.
type apiError struct {
	Errors []string `json:"errors"`
}

// Response is a decoded reply: status and body. The body may hold secret
// values; the caller wipes it.
type Response struct {
	Status int
	Body   []byte
}

// Wipe wipes the body. It accepts a nil response.
func (r *Response) Wipe() {
	if r != nil {
		secret.WipeBytes(r.Body)
	}
}

// Request describes one API call.
type Request struct {
	Op     stores.Op
	Ref    stores.Ref
	Method string
	// Path is relative to /v1/, already escaped.
	Path  string
	Query url.Values
	Body  *wire.Body
	// Involved are the values sent in this request, so an error message
	// echoing one is withheld.
	Involved []secret.Value
	// NoAuth sends no token (sys/health, login).
	NoAuth bool
	// Token, when set, is sent instead of the client's own token, and a
	// refusal is returned as is: the client neither logs in nor retries.
	// The caller owns it. It is for acting with a token scrim obtained on
	// someone else's behalf, and for renewing a token.
	Token secret.Value
	// Optional marks a lookup whose failure the caller ignores (labels): a
	// refusal is returned as is, without logging in again.
	Optional bool
	// Namespace, when set, replaces the configured namespace for this
	// request ("/" means the root namespace: no header).
	Namespace string
}

// StoreErr builds a stores error for r.
func (c *Client) StoreErr(r Request, kind error, detail string, cause error) *stores.Error {
	e := stores.NewError(c.name, r.Op, r.Ref, kind, cause)
	e.Detail = detail
	return e
}

// Do runs r with the client's token, logging in first when needed and once
// more when the store rejects a token it should have accepted. A request
// with its own token or none is sent once. A non-2xx status is returned as a
// classified error; the response is still returned for 404 bodies.
func (c *Client) Do(ctx context.Context, r Request) (*Response, error) {
	if r.NoAuth || !r.Token.IsZero() {
		return c.Attempt(ctx, r, r.Token)
	}
	tok, err := c.currentToken(ctx, r)
	if err != nil {
		return nil, err
	}
	resp, err := c.Attempt(ctx, r, tok)
	if err == nil || c.opts.AuthMethod == AuthToken || r.Optional || !errors.Is(err, stores.ErrPermission) {
		tok.Wipe()
		return resp, err
	}
	// A 403 on a login token may mean it expired or was revoked. Log in
	// again once; a second 403 is a real policy refusal.
	resp.Wipe()
	c.DropToken(tok)
	tok.Wipe()
	if tok, err = c.currentToken(ctx, r); err != nil {
		return nil, err
	}
	defer tok.Wipe()
	return c.Attempt(ctx, r, tok)
}

// Attempt sends r once, with token unless r.NoAuth.
func (c *Client) Attempt(ctx context.Context, r Request, token secret.Value) (*Response, error) {
	// r.Path is escaped already. Path must hold its decoded form: url.URL
	// uses RawPath only when it decodes to Path, and escapes Path again
	// otherwise, which sent "git hub" as "git%2520hub" (and so stored it as
	// "git%20hub") up to 0.4.
	decoded, err := url.PathUnescape(r.Path)
	if err != nil {
		return nil, c.StoreErr(r, stores.ErrInvalidRef, "cannot build request", err)
	}
	u := *c.opts.Address
	u.Path = c.opts.Address.Path + "/v1/" + decoded
	u.RawPath = c.opts.Address.EscapedPath() + "/v1/" + r.Path
	if r.Query != nil {
		u.RawQuery = r.Query.Encode()
	}
	var body io.Reader
	if r.Body != nil {
		body = r.Body.Reader()
	}
	req, err := http.NewRequestWithContext(ctx, r.Method, u.String(), body)
	if err != nil {
		return nil, c.StoreErr(r, stores.ErrInvalidRef, "cannot build request", err)
	}
	if r.Body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	ns := c.opts.Namespace
	if r.Namespace != "" {
		ns = strings.Trim(r.Namespace, "/")
	}
	if ns != "" {
		req.Header.Set("X-Vault-Namespace", ns)
	}
	req.Header.Set("X-Vault-Request", "true")
	if !r.NoAuth {
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
			return nil, c.StoreErr(r, stores.ErrPermission, "no token to send", nil)
		}
	}
	hr, err := c.http.Do(req)
	if err != nil {
		return nil, c.StoreErr(r, stores.ErrUnavailable, transportDetail(ctx, err), err)
	}
	defer func() { _ = hr.Body.Close() }()
	b, err := wire.ReadBody(hr.Body)
	if err != nil {
		return nil, c.StoreErr(r, stores.ErrUnavailable, "reading response: "+err.Error(), nil)
	}
	resp := &Response{Status: hr.StatusCode, Body: b}
	if hr.StatusCode >= 200 && hr.StatusCode < 300 {
		return resp, nil
	}
	kind, detail := Classify(hr.StatusCode, b)
	if detail != "" {
		detail = wire.SafeDetail(detail, r.Involved...)
	}
	if kind != stores.ErrNotFound {
		resp.Wipe()
		resp = nil
	}
	return resp, c.StoreErr(r, kind, detail, nil)
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

// Classify maps a status to an error kind and the store's own message. The
// store's messages for KV operations do not echo request data, but callers
// still pass them through wire.SafeDetail.
func Classify(status int, body []byte) (kind error, detail string) { //nolint:staticcheck // kind is a sentinel, not a failure of Classify
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

// Credentials returns copies of the login material and the current token.
func (c *Client) Credentials() []secret.Value {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []secret.Value
	for _, v := range c.creds {
		if !v.IsZero() {
			out = append(out, CopyValue(v))
		}
	}
	if !c.token.IsZero() {
		out = append(out, CopyValue(c.token))
	}
	return out
}

// TokenCopy returns a copy of the current token (zero when not logged in),
// which the caller wipes.
func (c *Client) TokenCopy() secret.Value {
	c.mu.Lock()
	defer c.mu.Unlock()
	return CopyValue(c.token)
}

// Close wipes the token and login material and closes idle connections.
// The client refuses requests afterwards.
func (c *Client) Close() {
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

// CopyValue returns a new value with v's bytes.
func CopyValue(v secret.Value) secret.Value {
	var out secret.Value
	_ = v.Expose(func(b []byte) error {
		out = secret.New(b)
		return nil
	})
	return out
}

// EscapePath escapes each segment of a slash-separated path, once.
func EscapePath(p string) string {
	segs := strings.Split(p, "/")
	for i, s := range segs {
		segs[i] = url.PathEscape(s)
	}
	return strings.Join(segs, "/")
}
