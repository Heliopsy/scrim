// SPDX-License-Identifier: AGPL-3.0-only

package infisical

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
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores"
	"github.com/heliopsy/scrim/internal/stores/internal/satoken"
	"github.com/heliopsy/scrim/internal/stores/internal/wire"
)

// apiError is a failed call, classified. msg is the store's own message,
// already passed through wire.SafeDetail.
type apiError struct {
	status int
	kind   error
	msg    string
	cause  error
}

func (e *apiError) Error() string {
	if e.status != 0 {
		return fmt.Sprintf("infisical: HTTP %d: %s", e.status, e.msg)
	}
	return "infisical: " + e.msg
}

func (e *apiError) Unwrap() error { return e.cause }

// Is matches the error's kind, so errors.Is works before the error is
// wrapped in a stores.Error.
func (e *apiError) Is(target error) bool { return target == e.kind }

// errorBody is Infisical's error envelope.
type errorBody struct {
	StatusCode int    `json:"statusCode"`
	Message    string `json:"message"`
	Error      string `json:"error"`
}

// client is a small typed client for the parts of the Infisical API scrim
// uses. It holds the client secret and the current access token as
// secret.Value and logs in again when the token nears expiry or is refused.
type client struct {
	base     *url.URL
	http     *http.Client
	settings *settings
	now      func() time.Time

	mu sync.Mutex
	// clientID and clientSecret are resolved at the first login.
	clientID     string
	clientSecret secret.Value
	token        secret.Value
	expiry       time.Time

	projMu   sync.Mutex
	projects map[string]string // slug -> id
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
		base:     s.address,
		http:     &http.Client{Transport: tr, Timeout: s.timeout},
		settings: s,
		now:      time.Now,
		projects: map[string]string{},
	}, nil
}

func (c *client) url(path string, q url.Values) string {
	u := *c.base
	u.Path = strings.TrimRight(u.Path, "/") + path
	if q != nil {
		u.RawQuery = q.Encode()
	}
	return u.String()
}

// classify maps an HTTP status and Infisical's error envelope to a store
// error kind.
func classify(status int, body []byte, involved []secret.Value) *apiError {
	var eb errorBody
	_ = json.Unmarshal(body, &eb)
	msg := wire.SafeDetail(eb.Message, involved...)
	if msg == "" {
		msg = http.StatusText(status)
	}
	e := &apiError{status: status, msg: msg}
	lower := strings.ToLower(eb.Message)
	switch {
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		e.kind = stores.ErrPermission
	case status == http.StatusNotFound:
		e.kind = stores.ErrNotFound
	case status == http.StatusConflict,
		status == http.StatusBadRequest && strings.Contains(lower, "already exists"):
		e.kind = stores.ErrConflict
	case status == http.StatusTooManyRequests || status >= 500:
		e.kind = stores.ErrUnavailable
	default:
		// A request Infisical considers malformed (bad environment slug,
		// invalid key name) is a reference problem.
		e.kind = stores.ErrInvalidRef
	}
	return e
}

// isTokenError reports whether a refusal is about the access token itself,
// which a fresh login can fix, rather than about permissions.
func isTokenError(status int, body []byte) bool {
	if status == http.StatusUnauthorized {
		return true
	}
	if status != http.StatusForbidden {
		return false
	}
	var eb errorBody
	_ = json.Unmarshal(body, &eb)
	return eb.Error == "TokenError" || strings.Contains(strings.ToLower(eb.Message), "token")
}

// send performs one HTTP exchange. Network errors and timeouts are
// ErrUnavailable. The returned body belongs to the caller, who wipes it.
func (c *client) send(ctx context.Context, method, u string, body *wire.Body, auth bool) (int, []byte, error) {
	var r io.Reader
	if body != nil {
		r = body.Reader()
	}
	req, err := http.NewRequestWithContext(ctx, method, u, r)
	if err != nil {
		return 0, nil, &apiError{kind: stores.ErrInvalidRef, msg: "cannot build request", cause: err}
	}
	if body != nil {
		req.ContentLength = int64(body.Len())
		req.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(body.Reader()), nil }
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if auth {
		tok, err := c.accessToken(ctx)
		if err != nil {
			return 0, nil, err
		}
		defer tok.Wipe()
		_ = tok.Expose(func(b []byte) error {
			// net/http needs the header as a string; it lives only for
			// this request. See the package documentation.
			req.Header.Set("Authorization", "Bearer "+string(b))
			return nil
		})
	}
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

// scrubURLError drops the URL from a transport error: query strings name
// projects and paths, which are metadata, but there is no reason to repeat
// them in a cause.
func scrubURLError(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return fmt.Errorf("%s: %w", ue.Op, ue.Err)
	}
	return err
}

// do performs an authenticated call, logging in again once if the token is
// refused. It returns the body of a 2xx response, which the caller wipes.
func (c *client) do(ctx context.Context, method, path string, q url.Values, body *wire.Body, involved []secret.Value) ([]byte, error) {
	u := c.url(path, q)
	for attempt := 0; ; attempt++ {
		status, b, err := c.send(ctx, method, u, body, true)
		if err != nil {
			return nil, err
		}
		if status >= 200 && status < 300 {
			return b, nil
		}
		if attempt == 0 && isTokenError(status, b) {
			secret.WipeBytes(b)
			c.dropToken()
			continue
		}
		e := classify(status, b, involved)
		secret.WipeBytes(b)
		return nil, e
	}
}

func (c *client) dropToken() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.token.Wipe()
	c.token = secret.Value{}
	c.expiry = time.Time{}
}

// accessToken returns a copy of the current token, which the caller wipes,
// logging in again when there is none or it expires within a tenth of its
// lifetime (at least 30 seconds). Both methods replace the token by a fresh
// login rather than renewing it, so its max TTL never matters. The copy
// keeps a concurrent login from wiping a token mid-request.
func (c *client) accessToken(ctx context.Context) (secret.Value, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token.IsZero() || !c.now().Before(c.expiry) {
		if _, err := c.loginLocked(ctx); err != nil {
			return secret.Value{}, err
		}
	}
	return copyValue(c.token), nil
}

type loginResponse struct {
	AccessToken wire.Raw `json:"accessToken"`
	ExpiresIn   int64    `json:"expiresIn"`
}

func (c *client) loginLocked(ctx context.Context) (secret.Value, error) {
	var (
		body     *wire.Body
		path     string
		what     string
		involved []secret.Value
		err      error
	)
	switch c.settings.method {
	case methodKubernetesAuth:
		var jwt secret.Value
		// Read the file at every login: the kubelet rotates projected
		// tokens, and an old one stops working.
		if jwt, err = satoken.Read(c.settings.tokenFile); err != nil {
			return secret.Value{}, &apiError{kind: stores.ErrPermission, msg: fmt.Sprintf("option %s: %v", optK8sTokenFile, err)}
		}
		defer jwt.Wipe()
		if body, err = kubernetesLoginBody(c.settings.identityID, jwt); err != nil {
			return secret.Value{}, err
		}
		path, what, involved = "/api/v1/auth/kubernetes-auth/login", "Kubernetes Auth", []secret.Value{jwt}
	default:
		if body, err = c.universalLoginBody(ctx); err != nil {
			return secret.Value{}, err
		}
		path, what, involved = "/api/v1/auth/universal-auth/login", "universal auth", []secret.Value{c.clientSecret}
	}
	defer body.Wipe()

	status, b, err := c.send(ctx, http.MethodPost, c.url(path, nil), body, false)
	if err != nil {
		return secret.Value{}, err
	}
	defer secret.WipeBytes(b)
	if status < 200 || status >= 300 {
		e := classify(status, b, involved)
		if e.kind == stores.ErrNotFound || e.kind == stores.ErrInvalidRef {
			// A login refused for a bad identity, client ID, secret or
			// service account token is a credential problem whatever
			// status Infisical picks.
			e.kind = stores.ErrPermission
		}
		e.msg = what + " login refused: " + e.msg
		return secret.Value{}, e
	}
	var lr loginResponse
	if err := json.Unmarshal(b, &lr); err != nil {
		lr.AccessToken.Wipe()
		return secret.Value{}, &apiError{kind: stores.ErrUnavailable, msg: "malformed login response"}
	}
	tok, err := lr.AccessToken.Value()
	lr.AccessToken.Wipe()
	if err != nil || tok.IsZero() {
		return secret.Value{}, &apiError{kind: stores.ErrUnavailable, msg: "login response holds no access token"}
	}
	ttl := time.Duration(lr.ExpiresIn) * time.Second
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	margin := max(ttl/10, 30*time.Second)
	if margin >= ttl {
		margin = ttl / 2
	}
	c.token.Wipe()
	c.token = tok
	c.expiry = c.now().Add(ttl - margin)
	return tok, nil
}

// universalLoginBody resolves the client credentials at the first login and
// encodes them. The caller wipes the body.
func (c *client) universalLoginBody(ctx context.Context) (*wire.Body, error) {
	if c.clientSecret.IsZero() {
		id, sec, err := c.settings.resolveCredentials(ctx)
		if err != nil {
			return nil, &apiError{kind: stores.ErrPermission, msg: err.Error()}
		}
		c.clientID, c.clientSecret = id, sec
	}
	buf, err := wire.AppendJSON(nil, map[string]string{"clientId": c.clientID})
	if err != nil {
		return nil, &apiError{kind: stores.ErrInvalidRef, msg: "cannot encode login", cause: err}
	}
	buf = append(buf[:len(buf)-1], `,"clientSecret":`...)
	buf, err = wire.AppendValue(buf, c.clientSecret)
	if err != nil {
		secret.WipeBytes(buf)
		return nil, &apiError{kind: stores.ErrPermission, msg: "client secret cannot be encoded", cause: err}
	}
	return wire.NewBody(append(buf, '}')), nil
}

// kubernetesLoginBody encodes a Kubernetes Auth login for identityID with
// jwt, a service account token. The caller wipes the body; jwt stays owned
// by the caller.
func kubernetesLoginBody(identityID string, jwt secret.Value) (*wire.Body, error) {
	buf, err := wire.AppendJSON(nil, map[string]string{"identityId": identityID})
	if err != nil {
		return nil, &apiError{kind: stores.ErrInvalidRef, msg: "cannot encode login", cause: err}
	}
	buf = append(buf[:len(buf)-1], `,"jwt":`...)
	buf, err = wire.AppendValue(buf, jwt)
	if err != nil {
		secret.WipeBytes(buf)
		return nil, &apiError{kind: stores.ErrPermission, msg: "service account token cannot be encoded", cause: err}
	}
	return wire.NewBody(append(buf, '}')), nil
}

// credentials returns copies of the client secret and the current token.
func (c *client) credentials() []secret.Value {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []secret.Value
	if !c.clientSecret.IsZero() {
		out = append(out, copyValue(c.clientSecret))
	}
	if !c.token.IsZero() {
		out = append(out, copyValue(c.token))
	}
	return out
}

func (c *client) close() {
	c.dropToken()
	c.mu.Lock()
	c.clientSecret.Wipe()
	c.mu.Unlock()
	c.http.CloseIdleConnections()
}

var uuidPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// projectID resolves a project slug to its ID, once. A UUID is used as is.
func (c *client) projectID(ctx context.Context, project string) (string, error) {
	if uuidPattern.MatchString(project) {
		return project, nil
	}
	c.projMu.Lock()
	id, ok := c.projects[project]
	c.projMu.Unlock()
	if ok {
		return id, nil
	}
	b, err := c.do(ctx, http.MethodGet, "/api/v1/projects/slug/"+url.PathEscape(project), nil, nil, nil)
	if err != nil {
		return "", err
	}
	defer secret.WipeBytes(b)
	var p struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(b, &p); err != nil || p.ID == "" {
		return "", &apiError{kind: stores.ErrUnavailable, msg: "malformed project response"}
	}
	c.projMu.Lock()
	c.projects[project] = p.ID
	c.projMu.Unlock()
	return p.ID, nil
}

// status checks the unauthenticated status endpoint.
func (c *client) status(ctx context.Context) error {
	st, b, err := c.send(ctx, http.MethodGet, c.url("/api/status", nil), nil, false)
	if err != nil {
		return err
	}
	secret.WipeBytes(b)
	if st != http.StatusOK {
		e := classify(st, b, nil)
		if e.kind != stores.ErrPermission {
			e.kind = stores.ErrUnavailable
		}
		return e
	}
	return nil
}

func copyValue(v secret.Value) secret.Value {
	var out secret.Value
	_ = v.Expose(func(b []byte) error {
		out = secret.New(b)
		return nil
	})
	return out
}
