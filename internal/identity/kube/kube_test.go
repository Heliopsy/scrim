// SPDX-License-Identifier: AGPL-3.0-only

package kube

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeAPI is a TokenReview endpoint that knows a set of tokens.
type fakeAPI struct {
	srv   *httptest.Server
	calls atomic.Int64
	mu    sync.Mutex
	// tokens maps a token to the review it gets.
	tokens map[string]tokenReviewStatus
	// reviewer is the bearer token scrim must present.
	reviewer string
	status   int
	gotAuth  []string
	gotAud   [][]string
}

func newFakeAPI(t *testing.T) *fakeAPI {
	t.Helper()
	f := &fakeAPI{tokens: map[string]tokenReviewStatus{}}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.calls.Add(1)
		f.mu.Lock()
		defer f.mu.Unlock()
		f.gotAuth = append(f.gotAuth, r.Header.Get("Authorization"))
		if r.URL.Path != "/apis/authentication.k8s.io/v1/tokenreviews" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		if f.status != 0 {
			http.Error(w, `{"message":"echo `+r.Header.Get("Authorization")+`"}`, f.status)
			return
		}
		if r.Header.Get("Authorization") != "Bearer "+f.reviewer {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		var tr tokenReview
		if err := json.NewDecoder(r.Body).Decode(&tr); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		f.gotAud = append(f.gotAud, tr.Spec.Audiences)
		st, ok := f.tokens[tr.Spec.Token]
		switch {
		case !ok:
			st = tokenReviewStatus{Error: "invalid bearer token " + tr.Spec.Token}
		case len(st.Audiences) > 0 && (len(tr.Spec.Audiences) != 1 || tr.Spec.Audiences[0] != st.Audiences[0]):
			// The API server refuses a token whose audience does not
			// intersect the requested ones.
			st = tokenReviewStatus{Error: "token audiences is invalid for the target audiences"}
		}
		tr.Status = st
		_ = json.NewEncoder(w).Encode(tr)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// jwt builds a token-shaped string with exp; the signature is random, so
// every token is distinct and the test can grep for it.
func jwt(exp time.Time) string {
	h := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","kid":"k"}`))
	p := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"aud":["scrim"],"exp":%d,"sub":"x"}`, exp.Unix())))
	return h + "." + p + "." + base64.RawURLEncoding.EncodeToString([]byte(randHex(24)))
}

func saStatus(ns, sa, pod string) tokenReviewStatus {
	st := tokenReviewStatus{Authenticated: true, Audiences: []string{"scrim"}}
	st.User.Username = saPrefix + ns + ":" + sa
	st.User.UID = "uid-" + sa
	st.User.Extra = map[string][]string{extraPodName: {pod}, extraPodUID: {"poduid-" + pod}}
	return st
}

func newReviewer(t *testing.T, f *fakeAPI, o Options) (*Reviewer, string) {
	t.Helper()
	dir := t.TempDir()
	f.reviewer = "reviewer-" + randHex(16)
	tf := filepath.Join(dir, "token")
	if err := os.WriteFile(tf, []byte(f.reviewer+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	o.APIServer, o.TokenFile, o.Client = f.srv.URL, tf, f.srv.Client()
	r, err := NewReviewer(o)
	if err != nil {
		t.Fatal(err)
	}
	return r, tf
}

func TestReviewMapsTheServiceAccount(t *testing.T) {
	f := newFakeAPI(t)
	r, _ := newReviewer(t, f, Options{})
	tok := jwt(time.Now().Add(time.Hour))
	f.tokens[tok] = saStatus("agents", "agent-a", "pod-1")
	a, err := r.Review(t.Context(), []byte(tok))
	if err != nil {
		t.Fatal(err)
	}
	if a.Namespace != "agents" || a.ServiceAccount != "agent-a" || a.Pod != "pod-1" || a.PodUID != "poduid-pod-1" || a.UID != "uid-agent-a" {
		t.Fatalf("account %+v", a)
	}
	if a.ExpiresAt.IsZero() {
		t.Fatal("no expiry")
	}
	if len(f.gotAud) != 1 || len(f.gotAud[0]) != 1 || f.gotAud[0][0] != "scrim" {
		t.Fatalf("TokenReview asked for audiences %v, want [scrim]", f.gotAud)
	}
}

func TestReviewRefusals(t *testing.T) {
	f := newFakeAPI(t)
	r, _ := newReviewer(t, f, Options{})
	exp := time.Now().Add(time.Hour)

	wrongAud := jwt(exp)
	st := saStatus("agents", "agent-a", "p")
	st.Audiences = []string{"https://kubernetes.default.svc"}
	f.tokens[wrongAud] = st

	// An API server that accepts the token but reports no audiences.
	acceptedOther := jwt(exp)
	st = saStatus("agents", "agent-a", "p")
	st.Audiences = nil
	f.tokens[acceptedOther] = st

	user := jwt(exp)
	st = saStatus("agents", "agent-a", "p")
	st.User.Username = "alice"
	f.tokens[user] = st

	for name, c := range map[string]struct {
		tok  string
		want error
	}{
		"unknown token":   {jwt(exp), ErrNotAuthenticated},
		"wrong audience":  {wrongAud, ErrNotAuthenticated},
		"no audience":     {acceptedOther, ErrWrongAudience},
		"not an SA":       {user, ErrNotServiceAccount},
		"expired":         {jwt(time.Now().Add(-time.Minute)), ErrNotAuthenticated},
		"not a JWT":       {"scrim_st_abc", ErrMalformed},
		"bad payload":     {"eyJhbGciOiJSUzI1NiJ9.!!!.c2ln", ErrMalformed},
		"quote injection": {`eyJhbGciOiJSUzI1NiJ9.eyJleHAiOjF9.a"b`, ErrMalformed},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := r.Review(t.Context(), []byte(c.tok))
			if !errors.Is(err, c.want) {
				t.Fatalf("err %v, want %v", err, c.want)
			}
			if strings.Contains(err.Error(), c.tok) || strings.Contains(err.Error(), f.reviewer) {
				t.Fatal("the error holds a token")
			}
		})
	}
	if n := f.calls.Load(); n != 4 {
		t.Fatalf("%d TokenReview calls, want 4 (expired and malformed tokens are refused locally)", n)
	}
}

func TestReviewAPIErrorsHoldNoToken(t *testing.T) {
	f := newFakeAPI(t)
	r, tf := newReviewer(t, f, Options{})
	tok := jwt(time.Now().Add(time.Hour))
	f.tokens[tok] = saStatus("agents", "a", "p")
	for _, code := range []int{http.StatusForbidden, http.StatusUnauthorized, http.StatusInternalServerError} {
		f.status = code
		_, err := r.Review(t.Context(), []byte(tok))
		if err == nil || errors.Is(err, ErrNotAuthenticated) {
			t.Fatalf("HTTP %d: %v", code, err)
		}
		if strings.Contains(err.Error(), tok) || strings.Contains(err.Error(), f.reviewer) || strings.Contains(err.Error(), "echo") {
			t.Fatalf("HTTP %d: the error echoes the answer: %v", code, err)
		}
	}
	f.status = 0
	if err := os.Remove(tf); err != nil {
		t.Fatal(err)
	}
	_, err := r.Review(t.Context(), []byte(tok))
	if err == nil || !strings.Contains(err.Error(), "identity.kubernetes.token-file") {
		t.Fatalf("missing reviewer token: %v", err)
	}
}

func TestReviewerTokenIsReread(t *testing.T) {
	f := newFakeAPI(t)
	r, tf := newReviewer(t, f, Options{CacheTTL: -1})
	tok := jwt(time.Now().Add(time.Hour))
	f.tokens[tok] = saStatus("agents", "a", "p")
	if _, err := r.Review(t.Context(), []byte(tok)); err != nil {
		t.Fatal(err)
	}
	// The kubelet rotates scrim's own token: the next call uses the new one.
	f.reviewer = "rotated-" + randHex(8)
	if err := os.WriteFile(tf, []byte(f.reviewer), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Review(t.Context(), []byte(tok)); err != nil {
		t.Fatal(err)
	}
	if got := f.gotAuth[len(f.gotAuth)-1]; got != "Bearer "+f.reviewer {
		t.Fatal("the rotated reviewer token was not used")
	}
}

func TestReviewCache(t *testing.T) {
	f := newFakeAPI(t)
	now := time.Now()
	clock := func() time.Time { return now }
	r, _ := newReviewer(t, f, Options{CacheTTL: time.Minute, Now: clock})
	tok := jwt(now.Add(90 * time.Second))
	f.tokens[tok] = saStatus("agents", "a", "p")
	for range 3 {
		if _, err := r.Review(t.Context(), []byte(tok)); err != nil {
			t.Fatal(err)
		}
	}
	if n := f.calls.Load(); n != 1 {
		t.Fatalf("%d calls within the cache lifetime, want 1", n)
	}
	now = now.Add(61 * time.Second)
	if _, err := r.Review(t.Context(), []byte(tok)); err != nil {
		t.Fatal(err)
	}
	if n := f.calls.Load(); n != 2 {
		t.Fatalf("%d calls after the cache lifetime, want 2", n)
	}
	// The cache never outlives the token.
	now = now.Add(30 * time.Second)
	if _, err := r.Review(t.Context(), []byte(tok)); !errors.Is(err, ErrNotAuthenticated) {
		t.Fatalf("expired cached token: %v", err)
	}
	// Refusals are not cached: a token the cluster starts accepting works.
	other := jwt(now.Add(time.Hour))
	if _, err := r.Review(t.Context(), []byte(other)); !errors.Is(err, ErrNotAuthenticated) {
		t.Fatal(err)
	}
	f.tokens[other] = saStatus("agents", "b", "p")
	if a, err := r.Review(t.Context(), []byte(other)); err != nil || a.ServiceAccount != "b" {
		t.Fatalf("%+v %v", a, err)
	}
}

func TestNewReviewerOutsideACluster(t *testing.T) {
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	t.Setenv("KUBERNETES_SERVICE_PORT", "")
	if _, err := NewReviewer(Options{}); err == nil || !strings.Contains(err.Error(), "identity.kubernetes.api-server") {
		t.Fatalf("err %v", err)
	}
	if _, err := NewReviewer(Options{APIServer: "https://127.0.0.1:1", CAFile: filepath.Join(t.TempDir(), "none")}); err == nil {
		t.Fatal("missing CA file accepted")
	}
}
