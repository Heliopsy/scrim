// SPDX-License-Identifier: AGPL-3.0-only

package doppler

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
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores"
	"github.com/heliopsy/scrim/internal/stores/internal/wire"
)

// apiError is a failed call, classified. msg is Doppler's own message,
// already passed through wire.SafeDetail.
type apiError struct {
	status int
	kind   error
	msg    string
	cause  error
}

func (e *apiError) Error() string {
	if e.status != 0 {
		return fmt.Sprintf("doppler: HTTP %d: %s", e.status, e.msg)
	}
	return "doppler: " + e.msg
}

func (e *apiError) Unwrap() error { return e.cause }

// Is matches the error's kind, so errors.Is works before the error is
// wrapped in a stores.Error.
func (e *apiError) Is(target error) bool { return target == e.kind }

// errorBody is Doppler's error envelope: {"messages": [...], "success": false}.
type errorBody struct {
	Messages []string `json:"messages"`
}

// classify maps an HTTP status and Doppler's error envelope to a store error
// kind.
func classify(status int, body []byte, involved []secret.Value) *apiError {
	var eb errorBody
	_ = json.Unmarshal(body, &eb)
	msg := wire.SafeDetail(strings.Join(eb.Messages, "; "), involved...)
	if msg == "" {
		msg = http.StatusText(status)
	}
	e := &apiError{status: status, msg: msg}
	switch {
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		e.kind = stores.ErrPermission
	case status == http.StatusNotFound:
		e.kind = stores.ErrNotFound
	case status == http.StatusConflict:
		e.kind = stores.ErrConflict
	case status == http.StatusTooManyRequests || status >= 500:
		e.kind = stores.ErrUnavailable
	default:
		// A request Doppler considers malformed (an invalid secret name,
		// a value its value type rejects) is a reference problem.
		e.kind = stores.ErrInvalidRef
	}
	return e
}

// client is a small typed client for the parts of the Doppler v3 API scrim
// uses. Doppler tokens are static bearer tokens: there is no login, so the
// client resolves the configured token once and keeps it as a secret.Value.
type client struct {
	base     *url.URL
	http     *http.Client
	settings *settings
	now      func() time.Time

	mu    sync.Mutex
	token secret.Value

	infoMu sync.Mutex
	// me is what /v3/me says about the token's workplace, looked up once.
	me cached[meInfo]
	// configs caches config details by "<project>/<config>".
	configs map[string]cached[configInfo]
}

// infoRetry is how long a failed details lookup is remembered.
const infoRetry = 5 * time.Minute

// cached is a details lookup and when it was made. ok is false for a lookup
// that failed (Doppler refused it: a service token may not describe its
// config), which is retried after infoRetry.
type cached[T any] struct {
	v       T
	ok      bool
	fetched time.Time
}

// meInfo is the part of GET /v3/me labels use.
type meInfo struct {
	Type      string `json:"type"`
	Workplace struct {
		Slug string `json:"slug"`
		Name string `json:"name"`
	} `json:"workplace"`
}

// configInfo is the part of GET /v3/configs/config labels use.
type configInfo struct {
	Name        string `json:"name"`
	Root        *bool  `json:"root"`
	Locked      *bool  `json:"locked"`
	Inheritable *bool  `json:"inheritable"`
	Environment string `json:"environment"`
	Project     string `json:"project"`
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
		configs:  map[string]cached[configInfo]{},
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

// bearer returns a copy of the token, resolving it on first use. The copy
// keeps Close from wiping a token mid-request.
func (c *client) bearer(ctx context.Context) (secret.Value, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token.IsZero() {
		v, err := c.settings.resolveToken(ctx)
		if err != nil {
			return secret.Value{}, &apiError{kind: stores.ErrPermission, msg: err.Error()}
		}
		c.token = v
	}
	return copyValue(c.token), nil
}

// response is one HTTP exchange's outcome. body belongs to the caller, who
// wipes it.
type response struct {
	status int
	header http.Header
	body   []byte
}

// send performs one authenticated HTTP exchange with scrim's own token.
// Network errors and timeouts are ErrUnavailable.
func (c *client) send(ctx context.Context, method, u string, body *wire.Body, header http.Header) (response, error) {
	return c.sendAs(ctx, method, u, body, header, secret.Value{})
}

// sendAs is send with the bearer as, a token held for an agent
// (agent.go), or scrim's own token when as is zero. The caller keeps
// ownership of as.
func (c *client) sendAs(ctx context.Context, method, u string, body *wire.Body, header http.Header, as secret.Value) (response, error) {
	var r io.Reader
	if body != nil {
		r = body.Reader()
	}
	req, err := http.NewRequestWithContext(ctx, method, u, r)
	if err != nil {
		return response{}, &apiError{kind: stores.ErrInvalidRef, msg: "cannot build request", cause: err}
	}
	if body != nil {
		req.ContentLength = int64(body.Len())
		req.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(body.Reader()), nil }
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range header {
		req.Header[k] = v
	}
	req.Header.Set("Accept", "application/json")
	tok := copyValue(as)
	if as.IsZero() {
		var err error
		if tok, err = c.bearer(ctx); err != nil {
			return response{}, err
		}
	}
	defer tok.Wipe()
	_ = tok.Expose(func(b []byte) error {
		// net/http needs the header as a string; it lives only for this
		// request. See the package documentation.
		req.Header.Set("Authorization", "Bearer "+string(b))
		return nil
	})
	resp, err := c.http.Do(req)
	if err != nil {
		return response{}, &apiError{kind: stores.ErrUnavailable, msg: "store unreachable", cause: scrubURLError(err)}
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := wire.ReadBody(resp.Body)
	if err != nil {
		return response{}, &apiError{kind: stores.ErrUnavailable, msg: "reading the response failed", cause: err}
	}
	return response{status: resp.StatusCode, header: resp.Header, body: b}, nil
}

// scrubURLError drops the URL from a transport error: the query names the
// project, config and secret, which are metadata, but there is no reason to
// repeat them in a cause.
func scrubURLError(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return fmt.Errorf("%s: %w", ue.Op, ue.Err)
	}
	return err
}

// do performs an authenticated call and returns the body of a 2xx response,
// which the caller wipes. involved are values in the request that Doppler
// might echo in an error message.
func (c *client) do(ctx context.Context, method, path string, q url.Values, body *wire.Body, involved []secret.Value) ([]byte, error) {
	return c.doAs(ctx, method, path, q, body, involved, secret.Value{})
}

// doAs is do with the bearer as (sendAs). as is added to involved, so an
// error never quotes it.
func (c *client) doAs(ctx context.Context, method, path string, q url.Values, body *wire.Body, involved []secret.Value, as secret.Value) ([]byte, error) {
	if !as.IsZero() {
		involved = append(slices.Clone(involved), as)
	}
	r, err := c.sendAs(ctx, method, c.url(path, q), body, nil, as)
	if err != nil {
		return nil, err
	}
	if r.status >= 200 && r.status < 300 {
		return r.body, nil
	}
	e := classify(r.status, r.body, involved)
	secret.WipeBytes(r.body)
	return nil, e
}

// getJSON performs an authenticated GET of metadata (never values) and
// decodes it into out.
func (c *client) getJSON(ctx context.Context, path string, q url.Values, out any) error {
	b, err := c.do(ctx, http.MethodGet, path, q, nil, nil)
	if err != nil {
		return err
	}
	defer secret.WipeBytes(b)
	if err := json.Unmarshal(b, out); err != nil {
		return &apiError{kind: stores.ErrUnavailable, msg: "malformed response from " + path}
	}
	return nil
}

// whoami fetches GET /v3/me, which checks the token and names its workplace.
func (c *client) whoami(ctx context.Context) (meInfo, error) {
	var m meInfo
	if err := c.getJSON(ctx, "/v3/me", nil, &m); err != nil {
		return meInfo{}, err
	}
	c.infoMu.Lock()
	c.me = cached[meInfo]{v: m, ok: true, fetched: c.now()}
	c.infoMu.Unlock()
	return m, nil
}

// workplace returns the token's workplace for labels, looked up once. A
// failure is not an error: labels then go without it.
func (c *client) workplace(ctx context.Context) meInfo {
	c.infoMu.Lock()
	m := c.me
	c.infoMu.Unlock()
	if m.ok || (!m.fetched.IsZero() && c.now().Sub(m.fetched) < infoRetry) {
		return m.v
	}
	got, err := c.whoami(ctx)
	if err != nil {
		if !errors.Is(err, stores.ErrUnavailable) && ctx.Err() == nil {
			c.infoMu.Lock()
			c.me = cached[meInfo]{fetched: c.now()}
			c.infoMu.Unlock()
		}
		return meInfo{}
	}
	return got
}

// configDetails returns the config's details for labels, looked up once per
// config. A failure is not an error: labels then carry what the reference
// says, and the lookup is retried after infoRetry. A transient failure is not
// remembered.
func (c *client) configDetails(ctx context.Context, project, config string) (configInfo, bool) {
	key := project + "/" + config
	c.infoMu.Lock()
	ci, ok := c.configs[key]
	c.infoMu.Unlock()
	if ok && (ci.ok || c.now().Sub(ci.fetched) < infoRetry) {
		return ci.v, ci.ok
	}
	var resp struct {
		Config configInfo `json:"config"`
	}
	err := c.getJSON(ctx, "/v3/configs/config", url.Values{"project": {project}, "config": {config}}, &resp)
	switch {
	case err == nil && resp.Config.Name == config:
		ci = cached[configInfo]{v: resp.Config, ok: true, fetched: c.now()}
	case err != nil && (errors.Is(err, stores.ErrUnavailable) || ctx.Err() != nil):
		return configInfo{}, false
	default:
		ci = cached[configInfo]{fetched: c.now()}
	}
	c.infoMu.Lock()
	c.configs[key] = ci
	c.infoMu.Unlock()
	return ci.v, ci.ok
}

// cachedConfig returns what is cached about a config, without contacting
// Doppler.
func (c *client) cachedConfig(project, config string) (configInfo, bool) {
	c.infoMu.Lock()
	defer c.infoMu.Unlock()
	ci := c.configs[project+"/"+config]
	return ci.v, ci.ok
}

// cachedWorkplace returns the cached workplace, without contacting Doppler.
func (c *client) cachedWorkplace() meInfo {
	c.infoMu.Lock()
	defer c.infoMu.Unlock()
	return c.me.v
}

// names lists the names of the secrets in a config (GET
// /v3/configs/config/secrets/names), without values, with or without
// Doppler's managed DOPPLER_* secrets.
func (c *client) names(ctx context.Context, project, config string, managed bool) ([]string, error) {
	var resp struct {
		Names []string `json:"names"`
	}
	q := url.Values{
		"project":                 {project},
		"config":                  {config},
		"include_dynamic_secrets": {"false"},
		"include_managed_secrets": {strconv.FormatBool(managed)},
	}
	if err := c.getJSON(ctx, "/v3/configs/config/secrets/names", q, &resp); err != nil {
		return nil, err
	}
	return resp.Names, nil
}

// credentials returns a copy of the token, once resolved.
func (c *client) credentials() []secret.Value {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token.IsZero() {
		return nil
	}
	return []secret.Value{copyValue(c.token)}
}

func (c *client) close() {
	c.mu.Lock()
	c.token.Wipe()
	c.token = secret.Value{}
	c.mu.Unlock()
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
