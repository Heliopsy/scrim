// SPDX-License-Identifier: AGPL-3.0-only

package onepassword

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
	"github.com/heliopsy/scrim/internal/stores/internal/wire"
)

// idPattern is the shape of 1Password vault and item IDs.
var idPattern = regexp.MustCompile(`^[0-9a-z]{26}$`)

func isID(s string) bool { return idPattern.MatchString(s) }

// apiError is a failed call, classified. msg is the server's own message,
// already passed through wire.SafeDetail.
type apiError struct {
	status int
	kind   error
	msg    string
	cause  error
}

func (e *apiError) Error() string {
	if e.status != 0 {
		return fmt.Sprintf("onepassword: HTTP %d: %s", e.status, e.msg)
	}
	return "onepassword: " + e.msg
}

func (e *apiError) Unwrap() error { return e.cause }

// Is matches the error's kind.
func (e *apiError) Is(target error) bool { return target == e.kind }

// errorBody is the Connect error envelope: {"status": 404, "message": "..."}.
type errorBody struct {
	Status  int    `json:"status"`
	Message string `json:"message"`
}

// apiVault is a vault as GET /v1/vaults returns it.
type apiVault struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Type string `json:"type"`
}

type apiURL struct {
	Label   string `json:"label"`
	Primary bool   `json:"primary"`
	Href    string `json:"href"`
}

// apiSummary is an item as GET /v1/vaults/{id}/items returns it: everything
// but sections, fields and files, so no value.
type apiSummary struct {
	ID    string `json:"id"`
	Title string `json:"title"`
	Vault struct {
		ID string `json:"id"`
	} `json:"vault"`
	Category     string    `json:"category"`
	URLs         []apiURL  `json:"urls"`
	Favorite     bool      `json:"favorite"`
	Tags         []string  `json:"tags"`
	Version      int       `json:"version"`
	State        string    `json:"state"`
	CreatedAt    time.Time `json:"createdAt"`
	UpdatedAt    time.Time `json:"updatedAt"`
	LastEditedBy string    `json:"lastEditedBy"`
}

type apiSection struct {
	ID    string `json:"id"`
	Label string `json:"label,omitempty"`
}

type sectionRef struct {
	ID string `json:"id"`
}

// apiField is one item field. Value is wire.Raw so it never becomes a Go
// string and prints as a marker. The TOTP code Connect derives from an OTP
// field is not decoded at all.
type apiField struct {
	ID      string      `json:"id"`
	Section *sectionRef `json:"section"`
	Type    string      `json:"type"`
	Purpose string      `json:"purpose"`
	Label   string      `json:"label"`
	Value   wire.Raw    `json:"value"`
}

// apiItem is a full item, GET /v1/vaults/{id}/items/{id}.
type apiItem struct {
	apiSummary
	Sections []apiSection `json:"sections"`
	Fields   []apiField   `json:"fields"`
}

func (it *apiItem) wipe() {
	for _, f := range it.Fields {
		f.Value.Wipe()
	}
}

// client is a small typed client for the parts of the Connect API scrim
// uses.
type client struct {
	base *url.URL
	http *http.Client
	s    *settings
	now  func() time.Time

	mu    sync.Mutex
	token secret.Value

	vmu    sync.Mutex
	vaults map[string]vaultEntry // by the vault as a reference spells it
}

type vaultEntry struct {
	v       apiVault
	fetched time.Time
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
		base:   s.address,
		http:   &http.Client{Transport: tr, Timeout: s.timeout},
		s:      s,
		now:    time.Now,
		vaults: map[string]vaultEntry{},
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

// classify maps an HTTP status and the Connect error envelope to a store
// error kind.
func classify(status int, body []byte, involved []secret.Value) *apiError {
	var eb errorBody
	_ = json.Unmarshal(body, &eb)
	msg := wire.SafeDetail(eb.Message, involved...)
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
	case status == http.StatusRequestEntityTooLarge:
		e.kind = stores.ErrUnsupported
	case status == http.StatusTooManyRequests || status >= 500:
		// Connect answers 5xx while it cannot sync with 1Password.com.
		e.kind = stores.ErrUnavailable
	default:
		e.kind = stores.ErrInvalidRef
	}
	return e
}

// accessToken returns a copy of the Connect token, resolving it on first
// use. The caller wipes the copy.
func (c *client) accessToken(ctx context.Context) (secret.Value, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token.IsZero() {
		v, err := c.s.resolve(ctx, c.s.tokenRef)
		if err != nil {
			return secret.Value{}, &apiError{kind: stores.ErrPermission, msg: fmt.Sprintf("option %s: cannot resolve %s", optToken, c.s.tokenRef), cause: err}
		}
		if v.IsZero() {
			v.Wipe()
			return secret.Value{}, &apiError{kind: stores.ErrPermission, msg: fmt.Sprintf("option %s resolved to an empty value", optToken)}
		}
		c.token = v
	}
	return copyValue(c.token), nil
}

// dropToken forgets the token, so the next request resolves it again (a
// rotated token file is picked up after a 401).
func (c *client) dropToken() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.token.Wipe()
	c.token = secret.Value{}
}

func (c *client) credentials() []secret.Value {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token.IsZero() {
		return nil
	}
	return []secret.Value{copyValue(c.token)}
}

func (c *client) close() { c.dropToken() }

func copyValue(v secret.Value) secret.Value {
	var out secret.Value
	_ = v.Expose(func(b []byte) error { out = secret.New(b); return nil })
	return out
}

// send performs one HTTP exchange, with bearer as the Authorization bearer
// token, or none when bearer is zero. Network errors and timeouts are
// ErrUnavailable. The returned body belongs to the caller, who wipes it.
func (c *client) send(ctx context.Context, method, u string, body *wire.Body, bearer secret.Value) (int, []byte, error) {
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
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	if !bearer.IsZero() {
		_ = bearer.Expose(func(b []byte) error {
			// net/http takes the header as a string; it lives only for
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

// sendAuth performs one exchange with scrim's own Connect token.
func (c *client) sendAuth(ctx context.Context, method, u string, body *wire.Body) (int, []byte, error) {
	tok, err := c.accessToken(ctx)
	if err != nil {
		return 0, nil, err
	}
	defer tok.Wipe()
	return c.send(ctx, method, u, body, tok)
}

// scrubURLError drops the URL from a transport error.
func scrubURLError(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return fmt.Errorf("%s: %w", ue.Op, ue.Err)
	}
	return err
}

// do performs an authenticated call, resolving the token again once if it is
// refused. It returns the body of a 2xx response, which the caller wipes.
func (c *client) do(ctx context.Context, method, path string, q url.Values, body *wire.Body, involved []secret.Value) ([]byte, error) {
	u := c.url(path, q)
	for attempt := 0; ; attempt++ {
		status, b, err := c.sendAuth(ctx, method, u, body)
		if err != nil {
			return nil, err
		}
		if status >= 200 && status < 300 {
			return b, nil
		}
		if attempt == 0 && status == http.StatusUnauthorized {
			secret.WipeBytes(b)
			c.dropToken()
			continue
		}
		e := classify(status, b, involved)
		secret.WipeBytes(b)
		return nil, e
	}
}

// doAs performs a call with as, a Connect token held for an agent, as the
// bearer instead of scrim's own token. as is used as is: there is no retry
// and nothing is cached. It returns the body of a 2xx response, which the
// caller wipes.
func (c *client) doAs(ctx context.Context, method, path string, q url.Values, as secret.Value) ([]byte, error) {
	if as.IsZero() {
		return nil, &apiError{kind: stores.ErrPermission, msg: "no agent credential"}
	}
	status, b, err := c.send(ctx, method, c.url(path, q), nil, as)
	if err != nil {
		return nil, err
	}
	if status >= 200 && status < 300 {
		return b, nil
	}
	e := classify(status, b, []secret.Value{as})
	secret.WipeBytes(b)
	return nil, e
}

// getJSON performs a GET whose response holds no value and decodes it.
func (c *client) getJSON(ctx context.Context, path string, q url.Values, out any) error {
	b, err := c.do(ctx, http.MethodGet, path, q, nil, nil)
	return decodeWiped(b, err, out)
}

// decodeWiped decodes the body of a call that returned b and err, and
// wipes b.
func decodeWiped(b []byte, err error, out any) error {
	if err != nil {
		return err
	}
	defer secret.WipeBytes(b)
	if err := json.Unmarshal(b, out); err != nil {
		return &apiError{kind: stores.ErrUnavailable, msg: "malformed response", cause: err}
	}
	return nil
}

// eqFilter is a SCIM "attr eq" filter, the only kind Connect supports.
func eqFilter(attr, value string) url.Values {
	esc := strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(value)
	return url.Values{"filter": {attr + ` eq "` + esc + `"`}}
}

// vault resolves a vault as a reference names it, by ID or by name. Results
// are cached for vault-cache-ttl; a failure is not.
func (c *client) vault(ctx context.Context, name string) (apiVault, error) {
	c.vmu.Lock()
	e, ok := c.vaults[name]
	c.vmu.Unlock()
	if ok && c.now().Sub(e.fetched) < c.s.vaultTTL {
		return e.v, nil
	}
	v, err := c.lookupVault(ctx, name)
	if err != nil {
		return apiVault{}, err
	}
	c.vmu.Lock()
	c.vaults[name] = vaultEntry{v: v, fetched: c.now()}
	c.vmu.Unlock()
	return v, nil
}

// cachedVault returns a cached vault without contacting Connect.
func (c *client) cachedVault(name string) (apiVault, bool) {
	c.vmu.Lock()
	defer c.vmu.Unlock()
	e, ok := c.vaults[name]
	return e.v, ok
}

// forgetVault drops a cached vault, after Connect said it is gone.
func (c *client) forgetVault(name string) {
	c.vmu.Lock()
	delete(c.vaults, name)
	c.vmu.Unlock()
}

func (c *client) lookupVault(ctx context.Context, name string) (apiVault, error) {
	if isID(name) {
		var v apiVault
		err := c.getJSON(ctx, "/v1/vaults/"+name, nil, &v)
		if err == nil {
			return v, nil
		}
		if !errors.Is(err, stores.ErrNotFound) {
			return apiVault{}, err
		}
		// Not an ID after all: a vault whose name looks like one.
	}
	var vs []apiVault
	if err := c.getJSON(ctx, "/v1/vaults", eqFilter("name", name), &vs); err != nil {
		return apiVault{}, err
	}
	var exact []apiVault
	for _, v := range vs {
		if v.Name == name {
			exact = append(exact, v)
		}
	}
	if len(exact) == 0 {
		exact = vs
	}
	switch len(exact) {
	case 0:
		return apiVault{}, &apiError{kind: stores.ErrNotFound, msg: "vault " + quote(name) + " not found or not shared with the Connect server"}
	case 1:
		return exact[0], nil
	}
	return apiVault{}, &apiError{kind: stores.ErrInvalidRef, msg: fmt.Sprintf("%d vaults are named %s; use the vault ID", len(exact), quote(name))}
}

// items lists the summaries of the active items in a vault, optionally only
// those titled title. Summaries never hold values.
func (c *client) items(ctx context.Context, vaultID, title string) ([]apiSummary, error) {
	var out []apiSummary
	if err := c.getJSON(ctx, "/v1/vaults/"+vaultID+"/items", titleFilter(title), &out); err != nil {
		return nil, err
	}
	return activeTitled(out, title), nil
}

// itemsAs is items with as, a Connect token held for an agent, as the
// bearer.
func (c *client) itemsAs(ctx context.Context, vaultID, title string, as secret.Value) ([]apiSummary, error) {
	var out []apiSummary
	b, err := c.doAs(ctx, http.MethodGet, "/v1/vaults/"+vaultID+"/items", titleFilter(title), as)
	if err := decodeWiped(b, err, &out); err != nil {
		return nil, err
	}
	return activeTitled(out, title), nil
}

func titleFilter(title string) url.Values {
	if title == "" {
		return nil
	}
	return eqFilter("title", title)
}

// activeTitled keeps the active summaries titled title (all when title is
// empty).
func activeTitled(sums []apiSummary, title string) []apiSummary {
	active := sums[:0]
	for _, s := range sums {
		// Connect does not return archived or deleted items today; the
		// state attribute says so if it ever does.
		if s.State == "" && (title == "" || s.Title == title) {
			active = append(active, s)
		}
	}
	return active
}

// item fetches a full item, values included. The caller wipes the returned
// body and the item's values.
func (c *client) item(ctx context.Context, vaultID, itemID string) (*apiItem, []byte, error) {
	b, err := c.do(ctx, http.MethodGet, "/v1/vaults/"+vaultID+"/items/"+itemID, nil, nil, nil)
	if err != nil {
		return nil, nil, err
	}
	var it apiItem
	if err := json.Unmarshal(b, &it); err != nil {
		it.wipe()
		secret.WipeBytes(b)
		return nil, nil, &apiError{kind: stores.ErrUnavailable, msg: "malformed item", cause: err}
	}
	return &it, b, nil
}

// heartbeat checks the server answers, without a token.
func (c *client) heartbeat(ctx context.Context) error {
	status, b, err := c.send(ctx, http.MethodGet, c.url("/heartbeat", nil), nil, secret.Value{})
	if err != nil {
		return err
	}
	secret.WipeBytes(b)
	if status != http.StatusOK {
		return &apiError{status: status, kind: stores.ErrUnavailable, msg: "heartbeat failed"}
	}
	return nil
}

func quote(s string) string { return fmt.Sprintf("%q", s) }
