// SPDX-License-Identifier: AGPL-3.0-only

package approval

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/heliopsy/scrim/internal/breakglass"
	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/secret"
)

// AdminURL is where the CLI reaches the admin API.
var AdminURL = config.Register(config.Spec[string]{
	Key:         "admin.url",
	Default:     "",
	Description: "Address of the scrim admin API for operator commands: unix:/path/to/socket or http(s)://host:port. Empty means unix:$XDG_RUNTIME_DIR/scrim/admin.sock.",
	Flag:        true,
})

// DefaultAdminSocket is the admin socket path when admin.url is empty.
func DefaultAdminSocket() string {
	dir := os.Getenv("XDG_RUNTIME_DIR")
	if dir == "" {
		dir = os.TempDir()
	}
	return filepath.Join(dir, "scrim", "admin.sock")
}

// Client calls the admin API.
type Client struct {
	base  string
	hc    *http.Client
	token secret.Value
}

// WithToken returns a copy of c that presents token as a bearer token, for
// a TCP admin listener (admin.token). The Unix socket ignores it.
func (c *Client) WithToken(token secret.Value) *Client {
	out := *c
	out.token = token
	return &out
}

// NewClient returns a client for addr (see [AdminURL]).
func NewClient(addr string) (*Client, error) {
	if addr == "" {
		addr = "unix:" + DefaultAdminSocket()
	}
	if path, ok := strings.CutPrefix(addr, "unix:"); ok {
		d := net.Dialer{Timeout: 5 * time.Second}
		tr := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return d.DialContext(ctx, "unix", path)
		}}
		return &Client{base: "http://scrim", hc: &http.Client{Transport: tr, Timeout: 30 * time.Second}}, nil
	}
	u, err := url.Parse(addr)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("admin.url %q: want unix:/path or http(s)://host:port", addr)
	}
	return &Client{base: strings.TrimRight(addr, "/"), hc: &http.Client{Timeout: 30 * time.Second}}, nil
}

// NewClientWith uses hc and base directly, for tests.
func NewClientWith(base string, hc *http.Client) *Client {
	return &Client{base: strings.TrimRight(base, "/"), hc: hc}
}

// APIError is an error response from the admin API.
type APIError struct {
	Status int
	ErrorBody
}

func (e *APIError) Error() string { return e.ErrorBody.Error }

// Is maps API error codes back to the package errors.
func (e *APIError) Is(target error) bool {
	switch e.Code {
	case "already_decided":
		return target == ErrSettled
	case "expired":
		return target == ErrExpired
	case "deny_all":
		return target == breakglass.ErrActive
	case "deny_all_configured":
		return target == breakglass.ErrConfigured
	}
	return false
}

func (c *Client) do(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, body)
	if err != nil {
		return err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if !c.token.IsZero() {
		if err := c.token.Expose(func(b []byte) error {
			req.Header.Set("Authorization", "Bearer "+string(b))
			return nil
		}); err != nil {
			return err
		}
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("admin API: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode >= 300 {
		e := &APIError{Status: resp.StatusCode}
		if json.Unmarshal(data, &e.ErrorBody) != nil || e.ErrorBody.Error == "" {
			e.ErrorBody = ErrorBody{Error: fmt.Sprintf("admin API answered %s", resp.Status), Code: "http"}
		}
		return e
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("admin API: decoding response: %w", err)
	}
	return nil
}

// ListApprovals lists approvals; status and agent may be empty.
func (c *Client) ListApprovals(ctx context.Context, status, agent string) ([]ApprovalView, error) {
	q := url.Values{}
	if status != "" {
		q.Set("status", status)
	}
	if agent != "" {
		q.Set("agent", agent)
	}
	var out []ApprovalView
	err := c.do(ctx, http.MethodGet, "/v1/approvals?"+q.Encode(), nil, &out)
	return out, err
}

// GetApproval returns one approval.
func (c *Client) GetApproval(ctx context.Context, id string) (ApprovalView, error) {
	var out ApprovalView
	err := c.do(ctx, http.MethodGet, "/v1/approvals/"+url.PathEscape(id), nil, &out)
	return out, err
}

// Decide approves or denies an approval.
func (c *Client) Decide(ctx context.Context, id string, approve bool, ttl time.Duration, reason string) (DecisionResult, error) {
	verb := "deny"
	if approve {
		verb = "approve"
	}
	body := DecideBody{Reason: reason}
	if ttl > 0 {
		body.TTL = ttl.String()
	}
	var out DecisionResult
	err := c.do(ctx, http.MethodPost, "/v1/approvals/"+url.PathEscape(id)+"/"+verb, body, &out)
	return out, err
}

// ListGrants lists grants.
func (c *Client) ListGrants(ctx context.Context, agent string, all bool) ([]GrantView, error) {
	q := url.Values{}
	if agent != "" {
		q.Set("agent", agent)
	}
	if all {
		q.Set("active", "false")
	}
	var out []GrantView
	err := c.do(ctx, http.MethodGet, "/v1/grants?"+q.Encode(), nil, &out)
	return out, err
}

// RevokeGrant revokes a grant.
func (c *Client) RevokeGrant(ctx context.Context, id, reason string) (GrantView, error) {
	var out GrantView
	err := c.do(ctx, http.MethodPost, "/v1/grants/"+url.PathEscape(id)+"/revoke", ReasonBody{Reason: reason}, &out)
	return out, err
}

// DenyAll reads the break-glass status.
func (c *Client) DenyAll(ctx context.Context) (breakglass.Status, error) {
	var out breakglass.Status
	err := c.do(ctx, http.MethodGet, "/v1/deny-all", nil, &out)
	return out, err
}

// SetDenyAll engages or releases break-glass.
func (c *Client) SetDenyAll(ctx context.Context, active bool, reason string) (breakglass.Status, error) {
	var out breakglass.Status
	err := c.do(ctx, http.MethodPost, "/v1/deny-all", DenyAllBody{Active: active, Reason: reason}, &out)
	return out, err
}
