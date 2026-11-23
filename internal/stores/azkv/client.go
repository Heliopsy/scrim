// SPDX-License-Identifier: AGPL-3.0-only

package azkv

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"

	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores"
	"github.com/heliopsy/scrim/internal/stores/internal/wire"
)

// apiVersion is the Key Vault data plane REST API version scrim speaks.
const apiVersion = "7.5"

// apiError is a failed call, classified. msg is safe to show: the store's
// own message passed through wire.SafeDetail, or text of scrim's own.
type apiError struct {
	status int
	kind   error
	msg    string
	cause  error
}

func (e *apiError) Error() string {
	if e.status != 0 {
		return fmt.Sprintf("azkv: HTTP %d: %s", e.status, e.msg)
	}
	return "azkv: " + e.msg
}

func (e *apiError) Unwrap() error { return e.cause }

// Is matches the error's kind.
func (e *apiError) Is(target error) bool { return target == e.kind }

// errorBody is Key Vault's error envelope.
type errorBody struct {
	Error struct {
		Code       string `json:"code"`
		Message    string `json:"message"`
		InnerError *struct {
			Code string `json:"code"`
		} `json:"innererror"`
	} `json:"error"`
}

// challenge is what a Key Vault 401 says about how to get a token.
type challenge struct {
	scope  string
	tenant string
}

// client talks to one vault. It learns the token scope and tenant from the
// vault's first 401 challenge, as the Azure SDK does, checks the challenge
// names a resource the vault belongs to, and gets tokens from azidentity.
type client struct {
	base *url.URL
	http *http.Client
	s    *settings

	credMu sync.Mutex
	creds  *credentials

	mu     sync.Mutex
	chal   *challenge
	token  secret.Value
	expiry time.Time
	claims string
	now    func() time.Time
}

func newClient(s *settings) (*client, error) {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	if s.caPEM != nil {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(s.caPEM) {
			return nil, fmt.Errorf("option %s holds no PEM certificate", optCAFile)
		}
		tr.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	}
	return &client{
		base: s.vault,
		// Redirects are not followed: a vault never redirects, and a
		// redirect would carry the token elsewhere.
		http: &http.Client{Transport: tr, Timeout: s.timeout, CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}},
		s:   s,
		now: time.Now,
	}, nil
}

func (c *client) close() {
	c.mu.Lock()
	c.token.Wipe()
	c.mu.Unlock()
	c.credMu.Lock()
	if c.creds != nil {
		c.creds.wipe()
	}
	c.credMu.Unlock()
	c.http.CloseIdleConnections()
}

// credentials returns copies of the access token and every credential
// scrim resolved, for stores.CredentialHolder.
func (c *client) credentials() []secret.Value {
	var out []secret.Value
	c.mu.Lock()
	if !c.token.IsZero() {
		out = append(out, copyValue(c.token))
	}
	c.mu.Unlock()
	c.credMu.Lock()
	if c.creds != nil {
		for _, v := range c.creds.held {
			out = append(out, copyValue(v))
		}
	}
	c.credMu.Unlock()
	return out
}

func (c *client) credential(ctx context.Context) (*credentials, error) {
	c.credMu.Lock()
	defer c.credMu.Unlock()
	if c.creds != nil {
		return c.creds, nil
	}
	cr, err := buildCredential(ctx, c.s, c.http)
	if err != nil {
		return nil, &apiError{kind: stores.ErrPermission, msg: err.Error()}
	}
	c.creds = cr
	return cr, nil
}

// url builds a vault URL for path with the API version.
func (c *client) url(path string, q url.Values) string {
	u := *c.base
	u.Path = path
	if q == nil {
		q = url.Values{}
	}
	q.Set("api-version", apiVersion)
	u.RawQuery = q.Encode()
	return u.String()
}

// response is a completed exchange. body belongs to the caller, who wipes it.
type response struct {
	status int
	body   []byte
	date   time.Time
}

// do performs one authenticated call to the vault and returns a 2xx
// response or a classified error. involved are the values in the request,
// withheld from any store message that echoes them.
func (c *client) do(ctx context.Context, method, rawURL string, body *wire.Body, involved []secret.Value) (response, error) {
	cr, err := c.credential(ctx)
	if err != nil {
		return response{}, err
	}
	for attempt := 0; ; attempt++ {
		var tok secret.Value
		if !cr.static.IsZero() {
			tok = copyValue(cr.static)
		} else if ch := c.currentChallenge(); ch != nil {
			if tok, err = c.accessToken(ctx, cr, *ch); err != nil {
				return response{}, err
			}
		}
		// Without a challenge yet, the request goes out without a token
		// and without its body, so the vault answers 401 with the
		// challenge before seeing any value.
		send := body
		if tok.IsZero() {
			send = nil
		}
		resp, hdr, err := c.send(ctx, method, rawURL, send, tok)
		tok.Wipe()
		if err != nil {
			return response{}, err
		}
		if resp.status >= 200 && resp.status < 300 {
			return resp, nil
		}
		if resp.status == http.StatusUnauthorized && cr.static.IsZero() && attempt < 2 {
			secret.WipeBytes(resp.body)
			if err := c.learnChallenge(hdr.Values("WWW-Authenticate")); err != nil {
				return response{}, err
			}
			continue
		}
		defer secret.WipeBytes(resp.body)
		return response{}, classify(resp.status, resp.body, involved)
	}
}

func (c *client) send(ctx context.Context, method, rawURL string, body *wire.Body, tok secret.Value) (response, http.Header, error) {
	var r io.Reader
	if body != nil {
		r = body.Reader()
	}
	req, err := http.NewRequestWithContext(ctx, method, rawURL, r)
	if err != nil {
		return response{}, nil, &apiError{kind: stores.ErrInvalidRef, msg: "cannot build request", cause: err}
	}
	if body != nil {
		req.ContentLength = int64(body.Len())
		req.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(body.Reader()), nil }
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	if !tok.IsZero() {
		_ = tok.Expose(func(b []byte) error {
			// net/http takes the header as a string; it lives only for
			// this request.
			req.Header.Set("Authorization", "Bearer "+string(b))
			return nil
		})
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return response{}, nil, &apiError{kind: stores.ErrUnavailable, msg: "vault unreachable", cause: scrubURLError(err)}
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := wire.ReadBody(resp.Body)
	if err != nil {
		return response{}, nil, &apiError{kind: stores.ErrUnavailable, msg: "reading the response failed", cause: err}
	}
	out := response{status: resp.StatusCode, body: b}
	if d, err := http.ParseTime(resp.Header.Get("Date")); err == nil {
		out.date = d
	}
	return out, resp.Header, nil
}

func scrubURLError(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return fmt.Errorf("%s: %w", ue.Op, ue.Err)
	}
	return err
}

func (c *client) currentChallenge() *challenge {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.chal
}

// learnChallenge parses a Bearer challenge, checks it, and replaces the
// known one. A challenge carrying claims (continuous access evaluation)
// makes the next token request ask for them. The cached token is dropped
// either way: the vault refused it or there was none.
func (c *client) learnChallenge(headers []string) error {
	params := map[string]string{}
	for _, h := range headers {
		if p, ok := parseBearer(h); ok {
			params = p
			break
		}
	}
	authz := params["authorization"]
	if authz == "" {
		authz = params["authorization_uri"]
	}
	scope := params["scope"]
	if scope == "" && params["resource"] != "" {
		scope = strings.TrimRight(params["resource"], "/") + "/.default"
	}
	if authz == "" || scope == "" {
		return &apiError{status: http.StatusUnauthorized, kind: stores.ErrPermission, msg: "the vault refused the request without a usable Bearer challenge"}
	}
	au, err := url.Parse(authz)
	if err != nil || au.Host == "" {
		return &apiError{status: http.StatusUnauthorized, kind: stores.ErrPermission, msg: "the vault's challenge names no valid authority"}
	}
	tenant := strings.Trim(au.Path, "/")
	if i := strings.IndexByte(tenant, '/'); i >= 0 {
		tenant = tenant[:i]
	}
	if err := verifyResource(c.base.Hostname(), scope); err != nil {
		return err
	}
	claims := ""
	if params["error"] == "insufficient_claims" && params["claims"] != "" {
		if b, err := base64.StdEncoding.DecodeString(params["claims"]); err == nil {
			claims = string(b)
		} else if b, err := base64.RawURLEncoding.DecodeString(params["claims"]); err == nil {
			claims = string(b)
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.chal = &challenge{scope: scope, tenant: tenant}
	c.claims = claims
	c.token.Wipe()
	c.token, c.expiry = secret.Value{}, time.Time{}
	return nil
}

// verifyResource refuses a challenge whose resource is not a parent domain
// of the vault's host, as the Azure SDK does: otherwise a host posing as
// the vault could make scrim fetch a token for another resource and send it
// there.
func verifyResource(vaultHost, scope string) error {
	u, err := url.Parse(scope)
	if err != nil || u.Hostname() == "" {
		return &apiError{status: http.StatusUnauthorized, kind: stores.ErrPermission, msg: "the vault's challenge names no valid resource"}
	}
	rh := strings.ToLower(u.Hostname())
	vh := strings.ToLower(vaultHost)
	if rh == vh {
		return nil
	}
	// A domain suffix only counts between names: "0.0.1" is no parent of
	// the address 10.0.0.1.
	if net.ParseIP(rh) == nil && net.ParseIP(vh) == nil && strings.HasSuffix(vh, "."+rh) {
		return nil
	}
	return &apiError{status: http.StatusUnauthorized, kind: stores.ErrPermission,
		msg: "the vault's challenge names resource " + rh + ", which the vault host " + vh + " is not part of; refusing to request a token for it"}
}

// parseBearer parses `Bearer k="v", k2="v2"`.
func parseBearer(h string) (map[string]string, bool) {
	scheme, rest, _ := strings.Cut(strings.TrimSpace(h), " ")
	if !strings.EqualFold(scheme, "Bearer") {
		return nil, false
	}
	out := map[string]string{}
	for rest = strings.TrimSpace(rest); rest != ""; {
		k, v, ok := strings.Cut(rest, "=")
		if !ok {
			break
		}
		k = strings.ToLower(strings.TrimSpace(k))
		v = strings.TrimSpace(v)
		if strings.HasPrefix(v, `"`) {
			end := strings.IndexByte(v[1:], '"')
			if end < 0 {
				break
			}
			out[k] = v[1 : end+1]
			rest = strings.TrimLeft(strings.TrimSpace(v[end+2:]), ",")
		} else {
			val, after, _ := strings.Cut(v, ",")
			out[k] = strings.TrimSpace(val)
			rest = after
		}
		rest = strings.TrimSpace(rest)
	}
	return out, true
}

// accessToken returns a copy of a token for ch, getting a new one from
// azidentity when there is none or it expires within five minutes.
func (c *client) accessToken(ctx context.Context, cr *credentials, ch challenge) (secret.Value, error) {
	c.mu.Lock()
	if !c.token.IsZero() && c.now().Add(5*time.Minute).Before(c.expiry) {
		t := copyValue(c.token)
		c.mu.Unlock()
		return t, nil
	}
	claims := c.claims
	c.mu.Unlock()
	// The vault's tenant is asked for, as the Azure SDK does: a credential
	// configured for another tenant refuses rather than authenticate
	// somewhere it was not meant to.
	opts := policy.TokenRequestOptions{Scopes: []string{ch.scope}, TenantID: ch.tenant, Claims: claims, EnableCAE: true}
	if c.s.method == methodManaged {
		// Managed identities have one tenant; the request may not name one.
		opts.TenantID = ""
	}
	at, err := cr.cred.GetToken(ctx, opts)
	if err != nil {
		return secret.Value{}, &apiError{kind: tokenKind(err), msg: "token request failed: " + wire.SafeDetail(scrubCredError(err))}
	}
	v := secret.FromString(at.Token)
	c.mu.Lock()
	c.token.Wipe()
	c.token, c.expiry, c.claims = copyValue(v), at.ExpiresOn, ""
	c.mu.Unlock()
	return v, nil
}

// classify maps an HTTP status and Key Vault's error envelope to a store
// error kind.
func classify(status int, body []byte, involved []secret.Value) *apiError {
	var eb errorBody
	_ = json.Unmarshal(body, &eb)
	msg := wire.SafeDetail(eb.Error.Message, involved...)
	if msg == "" {
		msg = http.StatusText(status)
	}
	e := &apiError{status: status, msg: msg}
	inner := ""
	if eb.Error.InnerError != nil {
		inner = eb.Error.InnerError.Code
	}
	switch {
	case status == http.StatusForbidden && inner == "SecretDisabled":
		e.kind = stores.ErrNotFound
		e.msg = "the secret version is disabled"
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		e.kind = stores.ErrPermission
	case status == http.StatusNotFound:
		e.kind = stores.ErrNotFound
	case status == http.StatusConflict:
		e.kind = stores.ErrConflict
		if strings.Contains(strings.ToLower(eb.Error.Message), "deleted") {
			e.msg = "the name is held by a soft-deleted secret; recover or purge it first"
		}
	case status == http.StatusTooManyRequests || status >= 500:
		e.kind = stores.ErrUnavailable
	case status >= 400 && status < 500:
		e.kind = stores.ErrInvalidRef
	default:
		e.kind = stores.ErrUnavailable
	}
	return e
}
