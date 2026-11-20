// SPDX-License-Identifier: AGPL-3.0-only

// Package kube identifies in-cluster callers by their projected Kubernetes
// service account tokens (specs/agent-identity "Kubernetes service account
// identity").
//
// A pod mounts a projected token with scrim's audience and sends it where a
// session token would go (design D14): the password of
// `Proxy-Authorization: Basic k8s:<token>` on the forward proxy, or the value
// of `x-scrim-session` on a base-URL listener. The data plane holds it for
// the request and hands it to the control plane in the ask; [Reviewer]
// verifies it with the cluster's TokenReview API, asking for scrim's audience
// so a token minted for any other audience (the pod's default API token) is
// refused, and [Mapper] turns the service account into an agent.
//
// A verified token is cached by its SHA-256 until it expires or the cache
// lifetime passes, whichever is first, so a busy pod costs one TokenReview
// per cache lifetime. Refusals are not cached. The token itself is never
// stored, logged or returned.
package kube

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/heliopsy/scrim/internal/secret"
)

// In-cluster defaults: where every pod finds its own service account.
const (
	DefaultCAFile    = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	DefaultTokenFile = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	DefaultAudience  = "scrim"
)

// Extra keys the API server sets on a token bound to a pod.
const (
	extraPodName = "authentication.kubernetes.io/pod-name"
	extraPodUID  = "authentication.kubernetes.io/pod-uid"
	saPrefix     = "system:serviceaccount:"
)

// Reasons a token is refused. They are safe to log and audit.
var (
	// ErrNotAuthenticated: the cluster did not accept the token (bad
	// signature, expired, deleted pod or service account, or another
	// audience: the API server reports a wrong audience this way).
	ErrNotAuthenticated = errors.New("kubernetes token not authenticated")
	// ErrWrongAudience: the cluster accepted the token, but not for scrim's
	// audience.
	ErrWrongAudience = errors.New("kubernetes token is not for scrim's audience")
	// ErrNotServiceAccount: the token belongs to something other than a
	// service account.
	ErrNotServiceAccount = errors.New("kubernetes token is not a service account token")
	// ErrMalformed: the token is not shaped like a JWT.
	ErrMalformed = errors.New("kubernetes token is malformed")
)

// Account is a verified service account and the pod its token is bound to.
type Account struct {
	Namespace      string
	ServiceAccount string
	// UID is the service account's UID.
	UID string
	// Pod and PodUID are set when the token is bound to a pod (every
	// projected token is).
	Pod    string
	PodUID string
	// ExpiresAt is the token's expiry, zero if it has none.
	ExpiresAt time.Time
}

// Options configure a Reviewer. Zero values take the in-cluster defaults.
type Options struct {
	// APIServer is the API server's base URL. Empty uses
	// https://$KUBERNETES_SERVICE_HOST:$KUBERNETES_SERVICE_PORT.
	APIServer string
	// CAFile verifies the API server's certificate.
	CAFile string
	// TokenFile holds scrim's own service account token, which authorises
	// the TokenReview call (RBAC: create tokenreviews, for example through
	// the system:auth-delegator cluster role). It is re-read on every call,
	// since the kubelet rotates it.
	TokenFile string
	// Audience is the audience agents' tokens must carry.
	Audience string
	// CacheTTL bounds how long a verified token is reused without asking
	// the cluster again; zero means one minute, negative disables the cache.
	CacheTTL time.Duration
	// Timeout bounds one TokenReview call; zero means ten seconds.
	Timeout time.Duration
	// Client overrides the HTTP client (tests).
	Client *http.Client
	Now    func() time.Time
}

// Reviewer verifies service account tokens with the TokenReview API.
type Reviewer struct {
	o      Options
	client *http.Client
	now    func() time.Time

	mu    sync.Mutex
	cache map[[32]byte]cached
}

type cached struct {
	acct  Account
	until time.Time
}

// maxCache bounds the cache; when full, expired entries are dropped and,
// if that is not enough, the cache starts over.
const maxCache = 4096

// NewReviewer returns a Reviewer. It fails when the API server cannot be
// determined or its CA cannot be read.
func NewReviewer(o Options) (*Reviewer, error) {
	if o.Audience == "" {
		o.Audience = DefaultAudience
	}
	if o.TokenFile == "" {
		o.TokenFile = DefaultTokenFile
	}
	if o.CacheTTL == 0 {
		o.CacheTTL = time.Minute
	}
	if o.Timeout <= 0 {
		o.Timeout = 10 * time.Second
	}
	if o.APIServer == "" {
		host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
		if host == "" || port == "" {
			return nil, errors.New("kube: identity.kubernetes.api-server is empty and KUBERNETES_SERVICE_HOST/PORT are not set (not running in a pod)")
		}
		o.APIServer = "https://" + net.JoinHostPort(host, port)
	}
	o.APIServer = strings.TrimSuffix(o.APIServer, "/")
	r := &Reviewer{o: o, client: o.Client, now: o.Now, cache: map[[32]byte]cached{}}
	if r.now == nil {
		r.now = time.Now
	}
	if r.client == nil {
		caFile := o.CAFile
		if caFile == "" {
			caFile = DefaultCAFile
		}
		pem, err := os.ReadFile(caFile) // #nosec G304 -- operator-configured path
		if err != nil {
			return nil, fmt.Errorf("kube: reading identity.kubernetes.ca-file %s: %w", caFile, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("kube: identity.kubernetes.ca-file %s holds no certificate", caFile)
		}
		r.client = &http.Client{Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
			Proxy:           nil,
		}}
	}
	return r, nil
}

// Audience is the audience the reviewer requires.
func (r *Reviewer) Audience() string { return r.o.Audience }

// Review verifies tok and returns its service account. The token is not
// kept; the caller wipes it.
func (r *Reviewer) Review(ctx context.Context, tok []byte) (Account, error) {
	tok = bytes.TrimSpace(tok)
	exp, ok := expiry(tok)
	if !ok || bytes.IndexFunc(tok, func(r rune) bool { return r > 0x7f || !isTokenByte(byte(r)) }) >= 0 {
		return Account{}, ErrMalformed
	}
	key := sha256.Sum256(tok)
	now := r.now()
	if !exp.IsZero() && !now.Before(exp) {
		return Account{}, ErrNotAuthenticated
	}
	if a, ok := r.lookup(key, now); ok {
		return a, nil
	}
	a, err := r.review(ctx, tok)
	if err != nil {
		return Account{}, err
	}
	a.ExpiresAt = exp
	r.store(key, a, now)
	return a, nil
}

func (r *Reviewer) lookup(key [32]byte, now time.Time) (Account, bool) {
	if r.o.CacheTTL < 0 {
		return Account{}, false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	c, ok := r.cache[key]
	if !ok || !now.Before(c.until) {
		delete(r.cache, key)
		return Account{}, false
	}
	return c.acct, true
}

func (r *Reviewer) store(key [32]byte, a Account, now time.Time) {
	if r.o.CacheTTL < 0 {
		return
	}
	until := now.Add(r.o.CacheTTL)
	if !a.ExpiresAt.IsZero() && a.ExpiresAt.Before(until) {
		until = a.ExpiresAt
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.cache) >= maxCache {
		for k, c := range r.cache {
			if !now.Before(c.until) {
				delete(r.cache, k)
			}
		}
		if len(r.cache) >= maxCache {
			r.cache = map[[32]byte]cached{}
		}
	}
	r.cache[key] = cached{acct: a, until: until}
}

type tokenReview struct {
	APIVersion string            `json:"apiVersion"`
	Kind       string            `json:"kind"`
	Spec       tokenReviewSpec   `json:"spec"`
	Status     tokenReviewStatus `json:"status"`
}

type tokenReviewSpec struct {
	Token     string   `json:"token,omitempty"`
	Audiences []string `json:"audiences,omitempty"`
}

type tokenReviewStatus struct {
	Authenticated bool     `json:"authenticated"`
	Audiences     []string `json:"audiences"`
	Error         string   `json:"error"`
	User          struct {
		Username string              `json:"username"`
		UID      string              `json:"uid"`
		Extra    map[string][]string `json:"extra"`
	} `json:"user"`
}

// review calls the TokenReview API. Errors never carry the token, scrim's
// own token or the API server's free-text answer.
func (r *Reviewer) review(ctx context.Context, tok []byte) (Account, error) {
	ctx, cancel := context.WithTimeout(ctx, r.o.Timeout)
	defer cancel()
	body, err := reviewBody(tok, r.o.Audience)
	if err != nil {
		return Account{}, err
	}
	defer secret.WipeBytes(body)
	own, err := os.ReadFile(r.o.TokenFile) // #nosec G304 -- operator-configured path
	if err != nil {
		return Account{}, fmt.Errorf("kube: reading scrim's own token (identity.kubernetes.token-file): %w", errors.Unwrap(err))
	}
	defer secret.WipeBytes(own)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.o.APIServer+"/apis/authentication.k8s.io/v1/tokenreviews", bytes.NewReader(body))
	if err != nil {
		return Account{}, errors.New("kube: building the TokenReview request")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	auth := make([]byte, 0, len("Bearer ")+len(own))
	auth = append(auth, "Bearer "...)
	auth = append(auth, bytes.TrimSpace(own)...)
	req.Header["Authorization"] = []string{string(auth)}
	secret.WipeBytes(auth)
	resp, err := r.client.Do(req)
	delete(req.Header, "Authorization")
	if err != nil {
		if ctx.Err() != nil {
			return Account{}, fmt.Errorf("kube: TokenReview at %s timed out", r.o.APIServer)
		}
		return Account{}, fmt.Errorf("kube: TokenReview at %s failed: %s", r.o.APIServer, transportCause(err))
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return Account{}, fmt.Errorf("kube: reading the TokenReview answer: %w", err)
	}
	defer secret.WipeBytes(raw)
	switch {
	case resp.StatusCode == http.StatusUnauthorized:
		return Account{}, fmt.Errorf("kube: the API server refused scrim's own token for TokenReview (HTTP %d)", resp.StatusCode)
	case resp.StatusCode == http.StatusForbidden:
		return Account{}, fmt.Errorf("kube: scrim's service account may not create tokenreviews (HTTP %d); bind it to system:auth-delegator", resp.StatusCode)
	case resp.StatusCode/100 != 2:
		return Account{}, fmt.Errorf("kube: TokenReview answered HTTP %d", resp.StatusCode)
	}
	var tr tokenReview
	if err := json.Unmarshal(raw, &tr); err != nil {
		return Account{}, errors.New("kube: TokenReview answer is not valid JSON")
	}
	st := tr.Status
	if !st.Authenticated {
		return Account{}, ErrNotAuthenticated
	}
	if !contains(st.Audiences, r.o.Audience) {
		return Account{}, ErrWrongAudience
	}
	rest, ok := strings.CutPrefix(st.User.Username, saPrefix)
	ns, sa, ok2 := strings.Cut(rest, ":")
	if !ok || !ok2 || ns == "" || sa == "" || strings.Contains(sa, ":") {
		return Account{}, ErrNotServiceAccount
	}
	a := Account{Namespace: ns, ServiceAccount: sa, UID: st.User.UID}
	if v := st.User.Extra[extraPodName]; len(v) == 1 {
		a.Pod = v[0]
	}
	if v := st.User.Extra[extraPodUID]; len(v) == 1 {
		a.PodUID = v[0]
	}
	return a, nil
}

// reviewBody builds the TokenReview request by hand, so the only copy of
// the token is one the caller wipes.
func reviewBody(tok []byte, audience string) ([]byte, error) {
	for _, b := range tok {
		if !isTokenByte(b) {
			return nil, ErrMalformed
		}
	}
	aud, err := json.Marshal(audience)
	if err != nil {
		return nil, err
	}
	b := make([]byte, 0, len(tok)+len(aud)+128)
	b = append(b, `{"apiVersion":"authentication.k8s.io/v1","kind":"TokenReview","spec":{"token":"`...)
	b = append(b, tok...)
	b = append(b, `","audiences":[`...)
	b = append(b, aud...)
	b = append(b, `]}}`...)
	return b, nil
}

func isTokenByte(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || b == '-' || b == '_' || b == '.'
}

// expiry reads the unverified exp claim of a JWT, so the cache never
// outlives the token. ok is false for anything not shaped like a JWT. The
// claims are trusted only after the cluster verified the token.
func expiry(tok []byte) (time.Time, bool) {
	parts := bytes.Split(tok, []byte("."))
	if len(parts) != 3 || len(parts[0]) == 0 || len(parts[1]) == 0 || len(parts[2]) == 0 || len(tok) > 16<<10 {
		return time.Time{}, false
	}
	payload := make([]byte, base64.RawURLEncoding.DecodedLen(len(parts[1])))
	n, err := base64.RawURLEncoding.Decode(payload, bytes.TrimRight(parts[1], "="))
	if err != nil {
		return time.Time{}, false
	}
	var claims struct {
		Exp json.Number `json:"exp"`
	}
	if err := json.Unmarshal(payload[:n], &claims); err != nil {
		return time.Time{}, false
	}
	if claims.Exp == "" {
		return time.Time{}, true
	}
	sec, err := claims.Exp.Int64()
	if err != nil {
		return time.Time{}, false
	}
	return time.Unix(sec, 0), true
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// transportCause names a transport failure without echoing the request.
func transportCause(err error) string {
	var ne net.Error
	switch {
	case errors.As(err, &ne) && ne.Timeout():
		return "timeout"
	case strings.Contains(err.Error(), "certificate"):
		return "TLS verification failed"
	case strings.Contains(err.Error(), "connection refused"):
		return "connection refused"
	default:
		return "transport error"
	}
}
