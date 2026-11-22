// SPDX-License-Identifier: AGPL-3.0-only

package gcpsm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores"
	"github.com/heliopsy/scrim/internal/stores/internal/wire"
)

// scope is the OAuth scope Secret Manager needs.
const scope = "https://www.googleapis.com/auth/cloud-platform"

// iamCredentialsEndpoint is where impersonated tokens are minted.
const iamCredentialsEndpoint = "https://iamcredentials.googleapis.com"

// allowedTypes are the credential file types accepted by reference. Every
// one names Google endpoints itself; scrim passes the file to
// golang.org/x/oauth2/google, which validates it for that type.
var allowedTypes = []google.CredentialsType{
	google.ServiceAccount,
	google.ExternalAccount,
	google.ImpersonatedServiceAccount,
	google.AuthorizedUser,
	google.ExternalAccountAuthorizedUser,
}

// authenticator produces access tokens. It resolves credential references
// and finds Application Default Credentials on first use, never at
// construction, so building an adapter contacts nothing.
type authenticator struct {
	s    *settings
	http *http.Client
	// iam is the IAM Credentials endpoint (tests point it at a fake).
	iam string

	mu      sync.Mutex
	ts      oauth2.TokenSource
	project string // from the credentials, when they name one
	// held are credentials scrim resolved (a static token, a service
	// account private key), last is the access token most recently used.
	held []secret.Value
	last secret.Value
	// known is project once init succeeded, readable without mu (which is
	// held across token requests).
	known atomic.Pointer[string]
}

func newAuthenticator(s *settings, hc *http.Client) *authenticator {
	return &authenticator{s: s, http: hc, iam: iamCredentialsEndpoint}
}

// authError is a failure to obtain a token, classified, without the
// library's message (which can quote a token endpoint's response).
type authError struct {
	kind error
	msg  string
}

func (e *authError) Error() string        { return "gcpsm auth: " + e.msg }
func (e *authError) Is(target error) bool { return target == e.kind }

// init builds the token source once.
func (a *authenticator) init(ctx context.Context) error {
	if a.ts != nil {
		return nil
	}
	// A failed earlier attempt may have kept credentials; start afresh.
	for _, v := range a.held {
		v.Wipe()
	}
	a.held = nil
	// Token sources keep this context for later refreshes, so it must
	// outlive the request; it only carries the HTTP client.
	bg := context.WithValue(context.Background(), oauth2.HTTPClient, a.http)
	var base oauth2.TokenSource
	switch a.s.method {
	case methodAccessToken:
		v, err := a.s.resolve(ctx, a.s.tokenRef)
		if err != nil {
			return &authError{kind: stores.ErrPermission, msg: fmt.Sprintf("option %s: cannot resolve %s: %v", optToken, a.s.tokenRef, err)}
		}
		if v.IsZero() {
			v.Wipe()
			return &authError{kind: stores.ErrPermission, msg: "option " + optToken + " resolved to an empty value"}
		}
		a.held = append(a.held, v)
		var tok string
		_ = v.Expose(func(b []byte) error { tok = string(bytes.TrimSpace(b)); return nil })
		// A static token has no expiry scrim knows of; Google refuses it
		// once it lapses and every call fails as permission denied.
		base = oauth2.StaticTokenSource(&oauth2.Token{AccessToken: tok, TokenType: "Bearer"})
	case methodCredentials:
		v, err := a.s.resolve(ctx, a.s.credRef)
		if err != nil {
			return &authError{kind: stores.ErrPermission, msg: fmt.Sprintf("option %s: cannot resolve %s: %v", optCredentials, a.s.credRef, err)}
		}
		defer v.Wipe()
		var creds *google.Credentials
		err = v.Expose(func(b []byte) error {
			var head struct {
				Type       string   `json:"type"`
				PrivateKey wire.Raw `json:"private_key"`
			}
			if json.Unmarshal(b, &head) != nil {
				return errors.New("option " + optCredentials + " is not a JSON credentials file")
			}
			if len(head.PrivateKey) > 0 {
				if pk, err := head.PrivateKey.Value(); err == nil {
					a.held = append(a.held, pk)
				}
				head.PrivateKey.Wipe()
			}
			t := google.CredentialsType(head.Type)
			if !slices.Contains(allowedTypes, t) {
				return fmt.Errorf("option %s: credentials type %q is not supported", optCredentials, head.Type)
			}
			c, err := google.CredentialsFromJSONWithType(bg, b, t, scope)
			if err != nil {
				return fmt.Errorf("option %s: invalid %s credentials", optCredentials, head.Type)
			}
			creds = c
			return nil
		})
		if err != nil {
			return &authError{kind: stores.ErrPermission, msg: err.Error()}
		}
		base, a.project = creds.TokenSource, creds.ProjectID
	default: // methodADC
		creds, err := google.FindDefaultCredentials(bg, scope)
		if err != nil {
			return &authError{kind: stores.ErrPermission, msg: "no Application Default Credentials found (GOOGLE_APPLICATION_CREDENTIALS, gcloud's application default file, or the metadata server)"}
		}
		base, a.project = creds.TokenSource, creds.ProjectID
	}
	if a.s.impersonate != "" {
		base = oauth2.ReuseTokenSource(nil, &impersonator{
			ctx: bg, http: a.http, base: base, endpoint: a.iam,
			account: a.s.impersonate, delegates: a.s.delegates,
		})
	}
	a.ts = base
	p := a.project
	a.known.Store(&p)
	return nil
}

// knownProject is the project the credentials named, once they were used.
func (a *authenticator) knownProject() string {
	if p := a.known.Load(); p != nil {
		return *p
	}
	return ""
}

// token returns the current access token. The caller wipes it.
func (a *authenticator) token(ctx context.Context) (secret.Value, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.init(ctx); err != nil {
		return secret.Value{}, err
	}
	t, err := a.ts.Token()
	if err != nil {
		return secret.Value{}, classifyTokenError(err)
	}
	if t.AccessToken == "" {
		return secret.Value{}, &authError{kind: stores.ErrPermission, msg: "the credentials produced an empty access token"}
	}
	// net/http and x/oauth2 hold the token as a string; scrim keeps a
	// wipeable copy for the redaction set and builds the header from it.
	v := secret.FromString(t.AccessToken)
	if !a.last.Equal(v) {
		a.last.Wipe()
		a.last = clone(v)
	}
	return v, nil
}

// projectID is the project the credentials name, after init.
func (a *authenticator) projectID(ctx context.Context) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.init(ctx); err != nil {
		return "", err
	}
	return a.project, nil
}

// credentials returns copies of every credential held.
func (a *authenticator) credentials() []secret.Value {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]secret.Value, 0, len(a.held)+1)
	for _, v := range a.held {
		out = append(out, clone(v))
	}
	if !a.last.IsZero() {
		out = append(out, clone(a.last))
	}
	return out
}

func (a *authenticator) close() {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, v := range a.held {
		v.Wipe()
	}
	a.held = nil
	a.last.Wipe()
}

// classifyTokenError maps a token source failure: a refusal by the token
// endpoint is a permission problem, anything else (network, 5xx) an outage.
func classifyTokenError(err error) error {
	var re *oauth2.RetrieveError
	if errors.As(err, &re) && re.Response != nil {
		code := re.Response.StatusCode
		switch {
		case code == http.StatusTooManyRequests || code >= 500:
			return &authError{kind: stores.ErrUnavailable, msg: fmt.Sprintf("token endpoint answered HTTP %d", code)}
		default:
			return &authError{kind: stores.ErrPermission, msg: fmt.Sprintf("token endpoint refused the credentials (HTTP %d)", code)}
		}
	}
	var ie *impersonationError
	if errors.As(err, &ie) {
		return &authError{kind: ie.kind, msg: ie.msg}
	}
	return &authError{kind: stores.ErrUnavailable, msg: "cannot obtain an access token"}
}

// impersonator mints access tokens for a service account with the IAM
// Credentials API (generateAccessToken), authenticated by base.
type impersonator struct {
	ctx       context.Context
	http      *http.Client
	base      oauth2.TokenSource
	endpoint  string
	account   string
	delegates []string
}

type impersonationError struct {
	kind error
	msg  string
}

func (e *impersonationError) Error() string { return e.msg }

func (i *impersonator) Token() (*oauth2.Token, error) {
	bt, err := i.base.Token()
	if err != nil {
		return nil, err
	}
	body := map[string]any{"scope": []string{scope}, "lifetime": "3600s"}
	if len(i.delegates) > 0 {
		ds := make([]string, len(i.delegates))
		for n, d := range i.delegates {
			ds[n] = "projects/-/serviceAccounts/" + d
		}
		body["delegates"] = ds
	}
	b, _ := json.Marshal(body)
	u := strings.TrimRight(i.endpoint, "/") + "/v1/projects/-/serviceAccounts/" + i.account + ":generateAccessToken"
	req, err := http.NewRequestWithContext(i.ctx, http.MethodPost, u, bytes.NewReader(b))
	if err != nil {
		return nil, &impersonationError{kind: stores.ErrInvalidRef, msg: "cannot build the impersonation request"}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+bt.AccessToken)
	resp, err := i.http.Do(req)
	if err != nil {
		return nil, &impersonationError{kind: stores.ErrUnavailable, msg: "IAM Credentials unreachable"}
	}
	defer func() { _ = resp.Body.Close() }()
	rb, err := wire.ReadBody(resp.Body)
	if err != nil {
		return nil, &impersonationError{kind: stores.ErrUnavailable, msg: "reading the impersonation response failed"}
	}
	defer secret.WipeBytes(rb)
	switch {
	case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
		return nil, &impersonationError{kind: stores.ErrUnavailable, msg: fmt.Sprintf("IAM Credentials answered HTTP %d", resp.StatusCode)}
	case resp.StatusCode != http.StatusOK:
		return nil, &impersonationError{kind: stores.ErrPermission, msg: fmt.Sprintf("IAM Credentials refused to impersonate %s (HTTP %d)", i.account, resp.StatusCode)}
	}
	var out struct {
		AccessToken string    `json:"accessToken"`
		ExpireTime  time.Time `json:"expireTime"`
	}
	if json.Unmarshal(rb, &out) != nil || out.AccessToken == "" {
		return nil, &impersonationError{kind: stores.ErrUnavailable, msg: "malformed impersonation response"}
	}
	return &oauth2.Token{AccessToken: out.AccessToken, TokenType: "Bearer", Expiry: out.ExpireTime}, nil
}

// clone copies v into a new Value the caller owns.
func clone(v secret.Value) secret.Value {
	var out secret.Value
	_ = v.Expose(func(b []byte) error { out = secret.New(b); return nil })
	return out
}
