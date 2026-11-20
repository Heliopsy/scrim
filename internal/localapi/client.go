// SPDX-License-Identifier: AGPL-3.0-only

package localapi

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
	"os"
	"strconv"
	"time"

	"github.com/heliopsy/scrim/internal/agenttools"
	"github.com/heliopsy/scrim/internal/identity"
	"github.com/heliopsy/scrim/internal/secret"
)

// Client calls the local API over its Unix socket.
type Client struct {
	socket string
	token  secret.Value
	hc     *http.Client
}

// NewClient returns a client for the socket at path, presenting token when
// it is not zero.
func NewClient(path string, token secret.Value) *Client {
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", path)
		},
		DisableCompression: true,
		MaxIdleConns:       2,
		IdleConnTimeout:    30 * time.Second,
	}
	return &Client{socket: path, token: token, hc: &http.Client{Transport: tr}}
}

// FromEnv returns a client for $SCRIM_API_SOCKET (or the default socket)
// with the session token in $SCRIM_SESSION_TOKEN, if any.
func FromEnv() *Client {
	var tok secret.Value
	if t := os.Getenv(EnvToken); t != "" {
		tok = secret.FromString(t)
	}
	return NewClient(SocketPath(), tok)
}

// Socket is the path the client dials.
func (c *Client) Socket() string { return c.socket }

// Close releases idle connections.
func (c *Client) Close() { c.hc.CloseIdleConnections() }

func (c *Client) do(ctx context.Context, method, path string, q url.Values, body io.Reader, ctype string, out any) error {
	u := "http://scrim/" + Version + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return agenttools.Errorf(agenttools.CodeInternal, "building the request failed")
	}
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	if !c.token.IsZero() {
		_ = c.token.Expose(func(t []byte) error {
			req.Header.Set("Authorization", "Bearer "+string(t))
			return nil
		})
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return agenttools.Errorf(agenttools.CodeUnavailable, "the call to scrim was cancelled")
		}
		return agenttools.Errorf(agenttools.CodeUnavailable, "cannot reach scrim at %s; is the control plane running?", c.socket)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return agenttools.Errorf(agenttools.CodeUnavailable, "reading the response from scrim failed")
	}
	if resp.StatusCode >= 300 {
		var eb ErrorBody
		if json.Unmarshal(raw, &eb) != nil || eb.Error.Code == "" {
			return agenttools.Errorf(agenttools.CodeInternal, "scrim answered %d", resp.StatusCode)
		}
		e := eb.Error
		return &e
	}
	if v := resp.Header.Get(HeaderAPIVersion); v != "" && v != Version {
		return agenttools.Errorf(agenttools.CodeUnavailable, "scrim speaks API %s, this client %s", v, Version)
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("%w: %w", errUnexpected, err)
	}
	return nil
}

func (c *Client) json(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	ctype := ""
	if in != nil {
		raw, err := json.Marshal(in)
		if err != nil {
			return agenttools.Errorf(agenttools.CodeInternal, "encoding the request failed")
		}
		body, ctype = bytes.NewReader(raw), "application/json"
	}
	return c.do(ctx, method, path, nil, body, ctype, out)
}

// Version returns the server's API version.
func (c *Client) Version(ctx context.Context) (VersionInfo, error) {
	var out VersionInfo
	return out, c.do(ctx, http.MethodGet, "/version", nil, nil, "", &out)
}

// Endpoints returns where the daemon behind the socket offers its
// listeners, and whether it is ready.
func (c *Client) Endpoints(ctx context.Context) (Endpoints, error) {
	var out Endpoints
	return out, c.do(ctx, http.MethodGet, "/endpoints", nil, nil, "", &out)
}

// WhoAmI returns the caller's identity as the server sees it.
func (c *Client) WhoAmI(ctx context.Context) (identity.Identity, error) {
	var out identity.Identity
	return out, c.do(ctx, http.MethodGet, "/whoami", nil, nil, "", &out)
}

// Minted is a new session: its token, shown once, and its description.
type Minted struct {
	Token   secret.Value
	Session SessionInfo
}

// Mint asks for a session token bound to the calling process tree.
func (c *Client) Mint(ctx context.Context, in MintInput) (Minted, error) {
	var out struct {
		Token   json.RawMessage `json:"token"`
		Session SessionInfo     `json:"session"`
	}
	if err := c.json(ctx, http.MethodPost, "/sessions", in, &out); err != nil {
		return Minted{}, err
	}
	defer secret.WipeBytes(out.Token)
	raw := bytes.Trim(out.Token, `"`)
	if !identity.LooksLikeToken(raw) {
		return Minted{}, fmt.Errorf("%w: no session token in the answer", errUnexpected)
	}
	return Minted{Token: secret.New(raw), Session: out.Session}, nil
}

// EndSession revokes the caller's own session.
func (c *Client) EndSession(ctx context.Context) error {
	return c.do(ctx, http.MethodDelete, "/sessions/self", nil, nil, "", nil)
}

// RevokeSession revokes a session by ID.
func (c *Client) RevokeSession(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodDelete, "/sessions/"+url.PathEscape(id), nil, nil, "", nil)
}

// List calls secrets_list.
func (c *Client) List(ctx context.Context, in agenttools.ListInput) (agenttools.ListOutput, error) {
	q := url.Values{}
	for k, v := range map[string]string{"store": in.Store, "prefix": in.Prefix, "binding": in.Binding} {
		if v != "" {
			q.Set(k, v)
		}
	}
	var out agenttools.ListOutput
	return out, c.do(ctx, http.MethodGet, "/secrets", q, nil, "", &out)
}

// Request calls secret_request.
func (c *Client) Request(ctx context.Context, in agenttools.RequestInput) (agenttools.RequestOutput, error) {
	var out agenttools.RequestOutput
	return out, c.json(ctx, http.MethodPost, "/secrets/request", in, &out)
}

// Generate calls secret_gen.
func (c *Client) Generate(ctx context.Context, in agenttools.GenInput) (agenttools.WriteOutput, error) {
	var out agenttools.WriteOutput
	return out, c.json(ctx, http.MethodPost, "/secrets/generate", in, &out)
}

// Check asks whether a write would be allowed.
func (c *Client) Check(ctx context.Context, in agenttools.CheckInput) (agenttools.CheckOutput, error) {
	var out agenttools.CheckOutput
	return out, c.json(ctx, http.MethodPost, "/secrets/check", in, &out)
}

// Put sends a value to be stored. The value is wiped before Put returns.
func (c *Client) Put(ctx context.Context, in agenttools.PutInput, v secret.Value) (agenttools.WriteOutput, error) {
	defer v.Wipe()
	q := url.Values{"ref": {in.Ref}}
	if in.Store != "" {
		q.Set("store", in.Store)
	}
	if in.Overwrite {
		q.Set("overwrite", strconv.FormatBool(true))
	}
	if in.Origin != "" {
		q.Set("origin", in.Origin)
	}
	var out agenttools.WriteOutput
	err := v.Expose(func(b []byte) error {
		return c.do(ctx, http.MethodPut, "/secrets/value", q, bytes.NewReader(b), "application/octet-stream", &out)
	})
	if errors.Is(err, secret.ErrWiped) {
		return out, agenttools.Errorf(agenttools.CodeInternal, "the value was wiped before it was sent")
	}
	return out, err
}

// Capture runs a secret_capture: it checks policy, runs the command here, on
// the agent's side, and sends only the extracted value to scrim. The
// command's output never leaves this process.
func (c *Client) Capture(ctx context.Context, in agenttools.CaptureInput) (agenttools.CaptureOutput, error) {
	if err := agenttools.CheckCapture(in); err != nil {
		return agenttools.CaptureOutput{}, err
	}
	ok, err := c.Check(ctx, agenttools.CheckInput{Tool: agenttools.ToolSecretCapture, Ref: in.Ref, Store: in.Store})
	if err != nil {
		return agenttools.CaptureOutput{}, err
	}
	if !ok.Allowed {
		return agenttools.CaptureOutput{}, agenttools.Errorf(agenttools.CodeDenied, "%s; the command was not run", ok.Reason)
	}
	v, exit, err := agenttools.RunCapture(ctx, in)
	if err != nil {
		return agenttools.CaptureOutput{ExitCode: exit}, err
	}
	w, err := c.Put(ctx, agenttools.PutInput{Ref: in.Ref, Store: in.Store, Overwrite: in.Overwrite, Origin: agenttools.ToolSecretCapture}, v)
	if err != nil {
		return agenttools.CaptureOutput{ExitCode: exit}, err
	}
	return agenttools.CaptureOutput{WriteOutput: w, ExitCode: exit}, nil
}

// Ask calls secret_ask_human.
func (c *Client) Ask(ctx context.Context, in agenttools.AskInput) (agenttools.AskOutput, error) {
	var out agenttools.AskOutput
	return out, c.json(ctx, http.MethodPost, "/asks", in, &out)
}

// Status calls approval_status.
func (c *Client) Status(ctx context.Context, in agenttools.StatusInput) (agenttools.StatusOutput, error) {
	var out agenttools.StatusOutput
	if in.ID == "" {
		return out, agenttools.Errorf(agenttools.CodeInvalid, "id is required")
	}
	return out, c.do(ctx, http.MethodGet, "/status/"+url.PathEscape(in.ID), nil, nil, "", &out)
}

// Grants calls grants_list.
func (c *Client) Grants(ctx context.Context) (agenttools.GrantsOutput, error) {
	var out agenttools.GrantsOutput
	return out, c.do(ctx, http.MethodGet, "/grants", nil, nil, "", &out)
}
