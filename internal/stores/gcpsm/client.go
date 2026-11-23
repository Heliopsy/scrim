// SPDX-License-Identifier: AGPL-3.0-only

package gcpsm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores"
	"github.com/heliopsy/scrim/internal/stores/internal/wire"
)

// apiError is a failed call, classified. msg is Google's own message,
// already passed through wire.SafeDetail.
type apiError struct {
	status int
	code   string // google.rpc.Code name: NOT_FOUND, ALREADY_EXISTS, ...
	kind   error
	msg    string
	cause  error
}

func (e *apiError) Error() string {
	if e.status != 0 {
		return fmt.Sprintf("gcpsm: HTTP %d %s: %s", e.status, e.code, e.msg)
	}
	return "gcpsm: " + e.msg
}

func (e *apiError) Unwrap() error        { return e.cause }
func (e *apiError) Is(target error) bool { return target == e.kind }

// errorBody is Google's JSON error envelope.
type errorBody struct {
	Error struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Status  string `json:"status"`
	} `json:"error"`
}

// client is a small typed client for the Secret Manager REST API (v1).
type client struct {
	base *url.URL
	http *http.Client
	auth *authenticator
}

// classify maps an HTTP status and Google's error envelope to a store error
// kind.
func classify(status int, body []byte, involved []secret.Value) *apiError {
	var eb errorBody
	_ = json.Unmarshal(body, &eb)
	msg := wire.SafeDetail(eb.Error.Message, involved...)
	if msg == "" {
		msg = http.StatusText(status)
	}
	e := &apiError{status: status, code: eb.Error.Status, msg: msg}
	switch {
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		e.kind = stores.ErrPermission
	case status == http.StatusNotFound:
		e.kind = stores.ErrNotFound
	case status == http.StatusConflict:
		// ALREADY_EXISTS on create; ABORTED on an etag mismatch.
		e.kind = stores.ErrConflict
	case eb.Error.Status == "FAILED_PRECONDITION":
		// A disabled or destroyed version: there is no value to read.
		e.kind = stores.ErrNotFound
	case status == http.StatusTooManyRequests || status >= 500:
		e.kind = stores.ErrUnavailable
	default:
		// INVALID_ARGUMENT: a name, label or annotation Google refuses.
		e.kind = stores.ErrInvalidRef
	}
	return e
}

// do performs one authenticated call and returns the body of a 2xx
// response, which the caller wipes. path is relative to /v1/; its segments
// are validated names that need no escaping. involved are values the
// request carries, kept out of messages.
func (c *client) do(ctx context.Context, method, path string, q url.Values, body *wire.Body, involved []secret.Value) ([]byte, error) {
	tok, err := c.auth.token(ctx)
	if err != nil {
		return nil, err
	}
	defer tok.Wipe()
	return c.doAs(ctx, tok, method, path, q, body, involved)
}

// doAs is [client.do] with the access token tok, which stays the
// caller's: an agent's own token (agent.go) or scrim's.
func (c *client) doAs(ctx context.Context, tok secret.Value, method, path string, q url.Values, body *wire.Body, involved []secret.Value) ([]byte, error) {
	u := *c.base
	u.Path = strings.TrimRight(u.Path, "/") + "/v1/" + path
	if q != nil {
		u.RawQuery = q.Encode()
	}
	var r io.Reader
	if body != nil {
		r = body.Reader()
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), r)
	if err != nil {
		return nil, &apiError{kind: stores.ErrInvalidRef, msg: "cannot build request", cause: err}
	}
	if body != nil {
		req.ContentLength = int64(body.Len())
		req.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(body.Reader()), nil }
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	_ = tok.Expose(func(b []byte) error {
		// net/http takes the header as a string; it lives for this
		// request only.
		req.Header.Set("Authorization", "Bearer "+string(b))
		return nil
	})
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, &apiError{kind: stores.ErrUnavailable, msg: "store unreachable", cause: scrubURLError(err)}
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := wire.ReadBody(resp.Body)
	if err != nil {
		return nil, &apiError{kind: stores.ErrUnavailable, msg: "reading the response failed", cause: err}
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return b, nil
	}
	e := classify(resp.StatusCode, b, append(slices.Clone(involved), tok))
	secret.WipeBytes(b)
	return nil, e
}

// getJSON performs a call and decodes a response that holds no value.
func (c *client) getJSON(ctx context.Context, method, path string, q url.Values, out any) error {
	b, err := c.do(ctx, method, path, q, nil, nil)
	if err != nil {
		return err
	}
	defer secret.WipeBytes(b)
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(b, out); err != nil {
		return &apiError{kind: stores.ErrUnavailable, msg: "malformed response"}
	}
	return nil
}

// scrubURLError drops the URL from a transport error.
func scrubURLError(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return fmt.Errorf("%s: %w", ue.Op, ue.Err)
	}
	return err
}
