// SPDX-License-Identifier: AGPL-3.0-only

package vaultwarden

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores/internal/wire"
	"github.com/heliopsy/scrim/internal/stores/vaultwarden/bwcrypto"
)

// deviceType 21 is "SDK" in Bitwarden's device type list; the server only
// records it.
const deviceType = "21"

// maxBody caps how much of a response is read. A sync of a few thousand
// items is a few MiB.
const maxBody = 64 << 20

// apiError is an HTTP-level failure. Message is the server's own message,
// truncated; it never contains plaintext because the server only ever
// receives ciphertext and hashes.
type apiError struct {
	Status  int
	Message string
}

func (e *apiError) Error() string {
	if e.Message == "" {
		return fmt.Sprintf("HTTP %d", e.Status)
	}
	return fmt.Sprintf("HTTP %d: %s", e.Status, e.Message)
}

// netError marks a transport failure (connection refused, timeout, TLS).
type netError struct{ err error }

func (e *netError) Error() string { return "transport: " + e.err.Error() }
func (e *netError) Unwrap() error { return e.err }

// client is a thin Bitwarden API client. It holds no keys; the session layer
// passes the access token in.
type client struct {
	base     *url.URL
	http     *http.Client
	deviceID string
}

func newClient(base *url.URL, hc *http.Client, deviceID string) *client {
	return &client{base: base, http: hc, deviceID: deviceID}
}

func (c *client) endpoint(p string, q url.Values) string {
	u := *c.base
	u.Path = strings.TrimSuffix(u.Path, "/") + p
	if q != nil {
		u.RawQuery = q.Encode()
	}
	return u.String()
}

func (c *client) do(req *http.Request, out any) error {
	body, err := c.doRaw(req)
	if err != nil {
		return err
	}
	// The body can hold the access token; what is kept is copied out of it.
	defer secret.WipeBytes(body)
	if out == nil || len(body) == 0 {
		return nil
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("decode %s response: %w", req.URL.Path, err)
	}
	return nil
}

// doRaw sends req and returns the body of a 2xx response, which the caller
// owns. The body of an error response is wiped once its message is taken.
func (c *client) doRaw(req *http.Request) ([]byte, error) {
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Bitwarden-Client-Name", "scrim")
	req.Header.Set("Bitwarden-Client-Version", "2025.1.0")
	req.Header.Set("Device-Type", deviceType)
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, &netError{err: sanitizeURLError(err)}
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		secret.WipeBytes(body)
		return nil, &netError{err: err}
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		msg := serverMessage(body)
		secret.WipeBytes(body)
		return nil, &apiError{Status: resp.StatusCode, Message: msg}
	}
	return body, nil
}

// sanitizeURLError drops the URL from a url.Error: query strings could carry
// identifiers, and the operation is named by the caller anyway.
func sanitizeURLError(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err
	}
	return err
}

// serverMessage extracts a short message from a Bitwarden error body.
func serverMessage(body []byte) string {
	var e struct {
		Message          string `json:"message"`
		ErrorDescription string `json:"error_description"`
		Error            string `json:"error"`
		ErrorModel       struct {
			Message string `json:"message"`
		} `json:"errorModel"`
	}
	_ = json.Unmarshal(body, &e)
	msg := e.ErrorModel.Message
	if msg == "" {
		msg = e.Message
	}
	if msg == "" {
		msg = e.ErrorDescription
	}
	if msg == "" {
		msg = e.Error
	}
	msg = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, msg)
	if len(msg) > 200 {
		msg = msg[:200] + "..."
	}
	return msg
}

func (c *client) jsonRequest(ctx context.Context, method, path string, q url.Values, token string, in any) (*http.Request, error) {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return nil, err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.endpoint(path, q), body)
	if err != nil {
		return nil, err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return req, nil
}

// preloginResponse holds an account's KDF parameters.
type preloginResponse struct {
	Kdf            int  `json:"kdf"`
	KdfIterations  int  `json:"kdfIterations"`
	KdfMemory      *int `json:"kdfMemory"`
	KdfParallelism *int `json:"kdfParallelism"`
}

func (p preloginResponse) params() bwcrypto.KDFParams {
	k := bwcrypto.KDFParams{Type: bwcrypto.KDFType(p.Kdf), Iterations: p.KdfIterations}
	if p.KdfMemory != nil {
		k.MemoryMiB = *p.KdfMemory
	}
	if p.KdfParallelism != nil {
		k.Parallelism = *p.KdfParallelism
	}
	return k
}

func (c *client) prelogin(ctx context.Context, email string) (bwcrypto.KDFParams, error) {
	req, err := c.jsonRequest(ctx, http.MethodPost, "/identity/accounts/prelogin", nil, "", map[string]string{"email": email})
	if err != nil {
		return bwcrypto.KDFParams{}, err
	}
	var out preloginResponse
	if err := c.do(req, &out); err != nil {
		return bwcrypto.KDFParams{}, err
	}
	return out.params(), nil
}

// tokenResponse is the identity endpoint's answer. Key and PrivateKey are
// ciphertext; AccessToken and RefreshToken are credentials.
type tokenResponse struct {
	AccessToken    wire.Raw `json:"access_token"`
	ExpiresIn      int      `json:"expires_in"`
	RefreshToken   wire.Raw `json:"refresh_token"`
	Key            string   `json:"Key"`
	PrivateKey     string   `json:"PrivateKey"`
	Kdf            int      `json:"Kdf"`
	KdfIterations  int      `json:"KdfIterations"`
	KdfMemory      *int     `json:"KdfMemory"`
	KdfParallelism *int     `json:"KdfParallelism"`
}

func (t tokenResponse) params() bwcrypto.KDFParams {
	return preloginResponse{Kdf: t.Kdf, KdfIterations: t.KdfIterations, KdfMemory: t.KdfMemory, KdfParallelism: t.KdfParallelism}.params()
}

// session is a logged-in token. The access token is a credential and lives
// in a secret.Value.
type session struct {
	token   secret.Value
	expires time.Time
	resp    tokenResponse // with AccessToken and RefreshToken cleared
}

func (c *client) token(ctx context.Context, form url.Values) (session, error) {
	form.Set("deviceType", deviceType)
	form.Set("deviceIdentifier", c.deviceID)
	form.Set("deviceName", "scrim")
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint("/identity/connect/token", nil),
		strings.NewReader(form.Encode()))
	// The form holds the client secret or password hash: clear it now.
	for k := range form {
		form[k] = nil
	}
	if err != nil {
		return session{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	var out tokenResponse
	if err := c.do(req, &out); err != nil {
		return session{}, err
	}
	// The tokens are decoded as raw bytes, never Go strings, and wiped
	// here; the access token lives on in the session's secret value.
	defer out.AccessToken.Wipe()
	defer out.RefreshToken.Wipe()
	tok, err := out.AccessToken.Value()
	if err != nil || tok.IsZero() {
		tok.Wipe()
		return session{}, errors.New("identity endpoint returned no access token")
	}
	s := session{token: tok, resp: out}
	s.resp.AccessToken, s.resp.RefreshToken = nil, nil
	if out.ExpiresIn > 0 {
		s.expires = time.Now().Add(time.Duration(out.ExpiresIn) * time.Second)
	} else {
		s.expires = time.Now().Add(time.Hour)
	}
	return s, nil
}

// loginAPIKey logs in with a personal API key (client_credentials grant).
func (c *client) loginAPIKey(ctx context.Context, clientID string, clientSecret secret.Value) (session, error) {
	var s session
	err := clientSecret.Expose(func(cs []byte) error {
		form := url.Values{
			"grant_type":    {"client_credentials"},
			"scope":         {"api"},
			"client_id":     {clientID},
			"client_secret": {string(cs)},
		}
		var err error
		s, err = c.token(ctx, form)
		return err
	})
	return s, err
}

// loginPassword logs in with the master password hash (password grant). It
// fails if the account requires two-factor authentication: use an API key.
func (c *client) loginPassword(ctx context.Context, email string, hash secret.Value) (session, error) {
	var s session
	err := hash.Expose(func(h []byte) error {
		form := url.Values{
			"grant_type": {"password"},
			"scope":      {"api offline_access"},
			"client_id":  {"cli"},
			"username":   {email},
			"password":   {string(h)},
		}
		var err error
		s, err = c.token(ctx, form)
		return err
	})
	return s, err
}

func (c *client) authed(ctx context.Context, s session, method, path string, q url.Values, in, out any) error {
	var err error
	terr := s.token.Expose(func(tok []byte) error {
		var req *http.Request
		// net/http needs the header as a string; that copy lives until the
		// request is garbage collected.
		req, err = c.jsonRequest(ctx, method, path, q, string(tok), in)
		if err != nil {
			return nil //nolint:nilerr // err is the outer variable, checked after Expose returns
		}
		err = c.do(req, out)
		return nil
	})
	if terr != nil {
		return terr
	}
	return err
}

// authedRaw is authed for a response the caller inspects and wipes: it
// returns the raw body of a 2xx response.
func (c *client) authedRaw(ctx context.Context, s session, method, path string, q url.Values) ([]byte, error) {
	var (
		body []byte
		err  error
	)
	terr := s.token.Expose(func(tok []byte) error {
		var req *http.Request
		req, err = c.jsonRequest(ctx, method, path, q, string(tok), nil)
		if err != nil {
			return nil //nolint:nilerr // err is the outer variable, checked after Expose returns
		}
		body, err = c.doRaw(req)
		return nil
	})
	if terr != nil {
		secret.WipeBytes(body)
		return nil, terr
	}
	return body, err
}

// revisionDate returns the account's revision date, which changes whenever
// anything in the vault changes. It is cheap and drives change detection.
func (c *client) revisionDate(ctx context.Context, s session) (int64, error) {
	var raw json.RawMessage
	if err := c.authed(ctx, s, http.MethodGet, "/api/accounts/revision-date", nil, nil, &raw); err != nil {
		return 0, err
	}
	n, err := strconv.ParseInt(strings.Trim(string(raw), `"`), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("revision date: %w", err)
	}
	return n, nil
}

func (c *client) sync(ctx context.Context, s session) (*syncResponse, error) {
	var out syncResponse
	if err := c.authed(ctx, s, http.MethodGet, "/api/sync", url.Values{"excludeDomains": {"true"}}, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *client) createFolder(ctx context.Context, s session, encName string) (string, error) {
	var out struct {
		ID string `json:"id"`
	}
	if err := c.authed(ctx, s, http.MethodPost, "/api/folders", nil, map[string]string{"name": encName}, &out); err != nil {
		return "", err
	}
	return out.ID, nil
}

func (c *client) createCipher(ctx context.Context, s session, ci *cipherRequest, collectionIDs []string) (*cipherJSON, error) {
	var out cipherJSON
	var err error
	if ci.OrganizationID != nil {
		err = c.authed(ctx, s, http.MethodPost, "/api/ciphers/create", nil,
			map[string]any{"cipher": ci, "collectionIds": collectionIDs}, &out)
	} else {
		err = c.authed(ctx, s, http.MethodPost, "/api/ciphers", nil, ci, &out)
	}
	if err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *client) updateCipher(ctx context.Context, s session, id string, ci *cipherRequest) (*cipherJSON, error) {
	var out cipherJSON
	if err := c.authed(ctx, s, http.MethodPut, "/api/ciphers/"+url.PathEscape(id), nil, ci, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// isTransport reports whether err is a network-level failure or a server
// error that means "try again later".
func isTransport(err error) bool {
	var ne *netError
	if errors.As(err, &ne) {
		return true
	}
	var nerr net.Error
	if errors.As(err, &nerr) {
		return true
	}
	var ae *apiError
	if errors.As(err, &ae) {
		return ae.Status >= 500 || ae.Status == http.StatusTooManyRequests
	}
	return errors.Is(err, context.DeadlineExceeded)
}

func httpStatus(err error) int {
	var ae *apiError
	if errors.As(err, &ae) {
		return ae.Status
	}
	return 0
}
