// SPDX-License-Identifier: AGPL-3.0-only

package bws

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores"
	"github.com/heliopsy/scrim/internal/stores/internal/wire"
	"github.com/heliopsy/scrim/internal/stores/vaultwarden/bwcrypto"
)

// deviceTypeSDK is the Device-Type header the official SDK sends (its
// DeviceType::SDK); the SDK marks it as a required header.
const deviceTypeSDK = "21"

// userAgent identifies scrim to Bitwarden.
const userAgent = "scrim"

// apiError is a failed call, classified. msg is safe to show: a status text
// or the server's message passed through wire.SafeDetail.
type apiError struct {
	status int
	kind   error
	msg    string
	cause  error
}

func (e *apiError) Error() string {
	if e.status != 0 {
		return fmt.Sprintf("bws: HTTP %d: %s", e.status, e.msg)
	}
	return "bws: " + e.msg
}

func (e *apiError) Unwrap() error { return e.cause }

// Is matches the error's kind, so errors.Is works before the error is
// wrapped in a stores.Error.
func (e *apiError) Is(target error) bool { return target == e.kind }

// client talks to the Bitwarden identity and API services as a Secrets
// Manager machine account. It logs in with the access token, keeps the
// bearer token as a secret.Value, and decrypts the organisation key once.
type client struct {
	s    *settings
	http *http.Client
	now  func() time.Time

	mu sync.Mutex
	// raw is the access token as configured, resolved at the first login.
	raw    secret.Value
	tok    *accessToken
	bearer secret.Value
	expiry time.Time
	org    string
	// orgKey encrypts every secret, key name and project name of the
	// organisation. It does not change between logins, so it is set once
	// and wiped at close; callers may use it without holding mu.
	orgKey bwcrypto.SymmetricKey
	closed bool
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
	return &client{s: s, http: &http.Client{Transport: tr, Timeout: s.timeout}, now: time.Now}, nil
}

func (c *client) close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	c.raw.Wipe()
	c.tok.wipe()
	c.bearer.Wipe()
	c.orgKey.Wipe()
}

// credentials returns copies of every credential the client holds: the
// access token, its client secret and key parts on their own, and the
// current bearer token.
func (c *client) credentials() []secret.Value {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []secret.Value
	add := func(v secret.Value) {
		if !v.IsZero() && !v.Wiped() {
			_ = v.Expose(func(b []byte) error { out = append(out, secret.New(b)); return nil })
		}
	}
	add(c.raw)
	if c.tok != nil {
		add(c.tok.clientSecret)
		add(c.tok.keyText)
	}
	add(c.bearer)
	return out
}

func endpoint(base *url.URL, path string, q url.Values) string {
	u := *base
	u.Path = strings.TrimRight(u.Path, "/") + path
	if q != nil {
		u.RawQuery = q.Encode()
	}
	return u.String()
}

// session returns a copy of a valid bearer token and the organisation ID,
// logging in when there is no token, it is about to expire, or force is set.
func (c *client) session(ctx context.Context, force bool) (secret.Value, string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return secret.Value{}, "", &apiError{kind: stores.ErrUnavailable, msg: "adapter is closed"}
	}
	if force || c.bearer.IsZero() || !c.now().Before(c.expiry) {
		if err := c.login(ctx); err != nil {
			return secret.Value{}, "", err
		}
	}
	var tok secret.Value
	_ = c.bearer.Expose(func(b []byte) error { tok = secret.New(b); return nil })
	return tok, c.org, nil
}

// identityResponse is the identity server's answer to a client credentials
// login (the SDK's IdentityTokenPayloadResponse). AccessToken is wire.Raw so
// the bearer token never becomes a Go string here.
type identityResponse struct {
	AccessToken      wire.Raw `json:"access_token"`
	ExpiresIn        int64    `json:"expires_in"`
	TokenType        string   `json:"token_type"`
	EncryptedPayload string   `json:"encrypted_payload"`
	Error            string   `json:"error"`
	ErrorDescription string   `json:"error_description"`
}

// login runs the access token login of bitwarden-core
// (auth/login/access_token.rs) for scrim's own machine account and keeps the
// session. c.mu is held.
func (c *client) login(ctx context.Context) error {
	if c.tok == nil {
		v, err := c.s.resolve(ctx, c.s.tokenRef)
		if err != nil {
			return &apiError{kind: stores.ErrPermission, msg: fmt.Sprintf("option %s: cannot resolve %s", optToken, c.s.tokenRef), cause: err}
		}
		tok, err := parseAccessToken(v)
		if err != nil {
			v.Wipe()
			return &apiError{kind: stores.ErrPermission, msg: fmt.Sprintf("option %s: %v", optToken, err)}
		}
		c.raw, c.tok = v, tok
	}
	bearer, org, ttl, payload, err := c.loginWith(ctx, c.tok, c.raw)
	if err != nil {
		return err
	}
	if !c.orgKey.Valid() {
		k, err := orgKeyFromPayload(c.tok.key, payload)
		if err != nil {
			bearer.Wipe()
			return &apiError{kind: stores.ErrPermission, msg: err.Error()}
		}
		c.orgKey = k
	} else if org != c.org {
		bearer.Wipe()
		return &apiError{kind: stores.ErrPermission, msg: "the access token now belongs to another organization"}
	}
	c.bearer.Wipe()
	c.bearer, c.org = bearer, org
	// Log in again a little before the token expires.
	c.expiry = c.now().Add(ttl - min(ttl/10, time.Minute))
	return nil
}

// loginWith logs in as the machine account tok belongs to (raw is the
// access token as written, redacted from errors) and returns the bearer
// token, which the caller owns, the organisation it names, its lifetime and
// the encrypted_payload, still encrypted. It touches no session state, so
// it serves scrim's own login and an agent's alike.
func (c *client) loginWith(ctx context.Context, tok *accessToken, raw secret.Value) (bearer secret.Value, org string, ttl time.Duration, payload string, err error) {
	// scope, client_id, client_secret, grant_type: the field order of the
	// SDK's AccessTokenRequest, form-encoded.
	form := []byte("scope=api.secrets&client_id=" + url.QueryEscape(tok.id) + "&client_secret=")
	_ = tok.clientSecret.Expose(func(b []byte) error { form = appendFormEscaped(form, b); return nil })
	form = append(form, "&grant_type=client_credentials"...)
	body := wire.NewBody(form)
	defer body.Wipe()

	fail := func(e *apiError) (secret.Value, string, time.Duration, string, error) {
		return secret.Value{}, "", 0, "", e
	}
	req, rerr := http.NewRequestWithContext(ctx, http.MethodPost, endpoint(c.s.identity, "/connect/token", nil), body.Reader())
	if rerr != nil {
		return fail(&apiError{kind: stores.ErrInvalidRef, msg: "cannot build the login request", cause: rerr})
	}
	req.ContentLength = int64(body.Len())
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Device-Type", deviceTypeSDK)
	req.Header.Set("User-Agent", userAgent)
	resp, rerr := c.http.Do(req)
	if rerr != nil {
		return fail(&apiError{kind: stores.ErrUnavailable, msg: "identity server unreachable", cause: scrubURLError(rerr)})
	}
	defer func() { _ = resp.Body.Close() }()
	b, rerr := wire.ReadBody(resp.Body)
	if rerr != nil {
		return fail(&apiError{kind: stores.ErrUnavailable, msg: "reading the login response failed", cause: rerr})
	}
	defer secret.WipeBytes(b)
	var ir identityResponse
	jerr := json.Unmarshal(b, &ir)
	defer ir.AccessToken.Wipe()
	switch {
	case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
		return fail(&apiError{status: resp.StatusCode, kind: stores.ErrUnavailable, msg: "identity server: " + http.StatusText(resp.StatusCode)})
	case resp.StatusCode != http.StatusOK:
		// invalid_client: the access token was revoked, expired or never
		// existed. The description is the server's own text.
		msg := "login refused"
		if ir.Error != "" {
			msg += ": " + wire.SafeDetail(ir.Error+" "+ir.ErrorDescription, tok.clientSecret, tok.keyText, raw)
		}
		return fail(&apiError{status: resp.StatusCode, kind: stores.ErrPermission, msg: msg})
	case jerr != nil:
		return fail(&apiError{status: resp.StatusCode, kind: stores.ErrUnavailable, msg: "login response is not JSON"})
	}
	q := bytes.TrimSpace(ir.AccessToken)
	if len(q) < 2 || q[0] != '"' || ir.EncryptedPayload == "" {
		return fail(&apiError{kind: stores.ErrPermission, msg: "login response has no access token or encrypted payload; the token may not be a machine account access token"})
	}
	tb, uerr := wire.Unquote(q)
	if uerr != nil {
		return fail(&apiError{kind: stores.ErrUnavailable, msg: "login response has a malformed access token"})
	}
	bearer = secret.Adopt(tb)
	org, oerr := jwtOrganization(bearer)
	if oerr != nil {
		bearer.Wipe()
		return fail(&apiError{kind: stores.ErrPermission, msg: oerr.Error()})
	}
	ttl = time.Duration(ir.ExpiresIn) * time.Second
	if ttl <= 0 {
		ttl = time.Hour
	}
	return bearer, org, ttl, ir.EncryptedPayload, nil
}

// appendFormEscaped percent-encodes b for an application/x-www-form-urlencoded
// body without passing it through a string. Unreserved characters stay as
// they are, as url.QueryEscape does, except that space becomes %20.
func appendFormEscaped(dst, b []byte) []byte {
	const hex = "0123456789ABCDEF"
	for _, c := range b {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '_', c == '.', c == '~':
			dst = append(dst, c)
		default:
			dst = append(dst, '%', hex[c>>4], hex[c&0xf])
		}
	}
	return dst
}

// scrubURLError drops the URL from a transport error.
func scrubURLError(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return fmt.Errorf("%s: %w", ue.Op, ue.Err)
	}
	return err
}

// errorBody is the API's error envelope.
type errorBody struct {
	Message string `json:"message"`
}

// classify maps an API status to a store error kind. Request bodies hold only
// ciphertext and IDs, so the server's message cannot echo a value; it is
// still passed through wire.SafeDetail.
func classify(status int, body []byte) *apiError {
	var eb errorBody
	_ = json.Unmarshal(body, &eb)
	msg := wire.SafeDetail(eb.Message)
	if msg == "" {
		msg = http.StatusText(status)
	}
	e := &apiError{status: status, msg: msg}
	switch {
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		e.kind = stores.ErrPermission
	case status == http.StatusNotFound:
		e.kind = stores.ErrNotFound
	case status == http.StatusTooManyRequests || status >= 500:
		e.kind = stores.ErrUnavailable
	default:
		e.kind = stores.ErrInvalidRef
	}
	return e
}

// call performs an authenticated API request with a JSON body (which holds
// no plaintext value) and decodes a 2xx answer into out. A 401 logs in again
// once.
func (c *client) call(ctx context.Context, method, path string, q url.Values, in, out any) error {
	var reqBody []byte
	if in != nil {
		var err error
		if reqBody, err = json.Marshal(in); err != nil {
			return &apiError{kind: stores.ErrInvalidRef, msg: "cannot encode the request", cause: err}
		}
	}
	for attempt := 0; ; attempt++ {
		tok, _, err := c.session(ctx, attempt > 0)
		if err != nil {
			return err
		}
		status, b, err := c.send(ctx, method, endpoint(c.s.api, path, q), reqBody, tok)
		tok.Wipe()
		if err != nil {
			return err
		}
		if status == http.StatusUnauthorized && attempt == 0 {
			continue
		}
		if status < 200 || status > 299 {
			return classify(status, b)
		}
		if out == nil {
			return nil
		}
		if err := json.Unmarshal(b, out); err != nil {
			return &apiError{status: status, kind: stores.ErrUnavailable, msg: "response is not the expected JSON"}
		}
		return nil
	}
}

func (c *client) send(ctx context.Context, method, u string, body []byte, tok secret.Value) (int, []byte, error) {
	var r io.Reader
	if body != nil {
		r = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, r)
	if err != nil {
		return 0, nil, &apiError{kind: stores.ErrInvalidRef, msg: "cannot build request", cause: err}
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json; charset=utf-8")
	}
	req.Header.Set("Device-Type", deviceTypeSDK)
	req.Header.Set("User-Agent", userAgent)
	_ = tok.Expose(func(b []byte) error {
		// net/http takes the header as a string; it lives only for this
		// request. See the package documentation.
		req.Header.Set("Authorization", "Bearer "+string(b))
		return nil
	})
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, nil, &apiError{kind: stores.ErrUnavailable, msg: "store unreachable", cause: scrubURLError(err)}
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := wire.ReadBody(resp.Body)
	if err != nil {
		return 0, nil, &apiError{kind: stores.ErrUnavailable, msg: "reading the response failed", cause: err}
	}
	return resp.StatusCode, b, nil
}
