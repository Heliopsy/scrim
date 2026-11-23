// SPDX-License-Identifier: AGPL-3.0-only

package openbao

import (
	"crypto/rand"
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
	"testing"
	"time"

	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores"
)

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// fakeJWT is shaped like a service account token, so a leak is easy to spot.
func fakeJWT() string { return "eyJhbGciOiJSUzI1NiJ9." + randHex(24) + "." + randHex(16) }

// k8sServer is an OpenBao with Kubernetes auth at auth/kubernetes: it
// accepts the JWTs in jwts for role "scrim", issues renewable tokens and
// serves reads to valid tokens.
type k8sServer struct {
	mu        sync.Mutex
	jwts      map[string]bool
	tokens    map[string]bool
	seenJWTs  []string
	issued    []string
	logins    int
	renews    int
	ttl       int
	renewable bool
	// renewCap, when positive, caps the lease a renewal grants, as the
	// token's max TTL would.
	renewCap   int
	renewFail  int // status renew-self answers with, when non-zero
	increments []string
	denyAll    bool
	// echoJWT makes a refused login quote the JWT back, as a careless
	// store might.
	echoJWT bool
}

func newK8sServer(jwt string) *k8sServer {
	return &k8sServer{jwts: map[string]bool{jwt: true}, tokens: map[string]bool{}, ttl: 30, renewable: true}
}

func (s *k8sServer) handler(t *testing.T) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		switch r.URL.Path {
		case "/v1/sys/health":
			writeJSON(w, 200, map[string]any{"initialized": true, "sealed": false})
			return
		case "/v1/auth/kubernetes/login":
			var body map[string]string
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				writeJSON(w, 400, map[string]any{"errors": []string{"bad body"}})
				return
			}
			s.seenJWTs = append(s.seenJWTs, body["jwt"])
			if body["role"] != "scrim" {
				writeJSON(w, 400, map[string]any{"errors": []string{fmt.Sprintf("invalid role name %q", body["role"])}})
				return
			}
			if !s.jwts[body["jwt"]] {
				msg := "permission denied"
				if s.echoJWT {
					msg = "service account token " + body["jwt"] + " is not valid"
				}
				writeJSON(w, 403, map[string]any{"errors": []string{msg}})
				return
			}
			s.logins++
			tok := "hvs.k8s-" + randHex(12)
			s.tokens[tok] = true
			s.issued = append(s.issued, tok)
			writeJSON(w, 200, map[string]any{"auth": map[string]any{"client_token": tok, "lease_duration": s.ttl, "renewable": s.renewable}})
			return
		case "/v1/auth/token/renew-self":
			tok := r.Header.Get("X-Vault-Token")
			if !s.tokens[tok] {
				writeJSON(w, 403, map[string]any{"errors": []string{"permission denied"}})
				return
			}
			s.renews++
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			s.increments = append(s.increments, body["increment"])
			if s.renewFail != 0 {
				writeJSON(w, s.renewFail, map[string]any{"errors": []string{"lease is not renewable"}})
				return
			}
			lease := s.ttl
			if s.renewCap > 0 && s.renewCap < lease {
				lease = s.renewCap
			}
			writeJSON(w, 200, map[string]any{"auth": map[string]any{"client_token": tok, "lease_duration": lease, "renewable": s.renewable}})
			return
		}
		if s.denyAll || !s.tokens[r.Header.Get("X-Vault-Token")] {
			writeJSON(w, 403, map[string]any{"errors": []string{"permission denied"}})
			return
		}
		writeJSON(w, 200, map[string]any{"data": map[string]any{"data": map[string]any{"v": "x"}, "metadata": map[string]any{"version": 1}}})
	})
}

func (s *k8sServer) counts() (logins, renews int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.logins, s.renews
}

func writeTokenFile(t *testing.T, path, jwt string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(jwt+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// k8sAdapter builds a Kubernetes auth adapter whose token file holds jwt.
func k8sAdapter(t *testing.T, srv *httptest.Server, jwt string, opts map[string]any) (*Adapter, string) {
	t.Helper()
	file := filepath.Join(t.TempDir(), "token")
	writeTokenFile(t, file, jwt)
	o := map[string]any{"auth.method": "kubernetes", "token": nil, "auth.kubernetes.role": "scrim", "auth.kubernetes.token-file": file}
	for k, v := range opts {
		o[k] = v
	}
	return newTest(t, srv, o, map[string]string{}), file
}

func mustRead(t *testing.T, a *Adapter) {
	t.Helper()
	sec, err := a.Read(t.Context(), stores.MustParseRef("bao://kv/x"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	sec.Wipe()
}

func TestKubernetesOptions(t *testing.T) {
	o, err := ParseOptions(map[string]any{"address": "http://bao:8200", "auth": map[string]any{"method": "kubernetes", "kubernetes": map[string]any{"role": "scrim"}}})
	if err != nil {
		t.Fatal(err)
	}
	if o.K8sMount != DefaultK8sMount || o.K8sRole != "scrim" || o.K8sTokenFile != DefaultK8sTokenFile {
		t.Errorf("defaults: %+v", o)
	}
	o, err = ParseOptions(map[string]any{"address": "http://bao:8200", "auth.method": "kubernetes", "auth.kubernetes.role": "r",
		"auth.kubernetes.mount": "/k8s/eu/", "auth.kubernetes.token-file": "/var/run/secrets/tokens/bao"})
	if err != nil {
		t.Fatal(err)
	}
	if o.K8sMount != "k8s/eu" || o.K8sTokenFile != "/var/run/secrets/tokens/bao" {
		t.Errorf("decoded %+v", o)
	}
	_, err = ParseOptions(map[string]any{"address": "http://bao:8200", "auth.method": "kubernetes", "token": "env:T", "secret-id": "env:S", "auth.kubernetes.token-file": ""})
	if err == nil {
		t.Fatal("invalid kubernetes options accepted")
	}
	for _, want := range []string{"auth.kubernetes.role is required", "token is not used", "secret-id is not used", "token-file must not be empty"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
}

func TestKubernetesLoginRenewsBeforeExpiry(t *testing.T) {
	jwt := fakeJWT()
	s := newK8sServer(jwt)
	srv := httptest.NewServer(s.handler(t))
	defer srv.Close()
	a, _ := k8sAdapter(t, srv, jwt, nil)
	now := time.Now()
	a.c.Now = func() time.Time { return now }

	mustRead(t, a)
	mustRead(t, a)
	if l, r := s.counts(); l != 1 || r != 0 {
		t.Fatalf("logins, renewals = %d, %d; want 1, 0", l, r)
	}
	if s.seenJWTs[0] != jwt {
		t.Fatalf("login did not present the token file's content (trimmed)")
	}
	now = now.Add(19 * time.Second)
	mustRead(t, a)
	if _, r := s.counts(); r != 0 {
		t.Fatalf("renewed before two thirds of the TTL")
	}
	now = now.Add(2 * time.Second) // 21s of 30s
	mustRead(t, a)
	if l, r := s.counts(); l != 1 || r != 1 {
		t.Fatalf("logins, renewals = %d, %d; want a renewal, not a login", l, r)
	}
	if s.increments[0] != "30s" {
		t.Errorf("renewal asked for %q, want the login TTL", s.increments[0])
	}
	// The renewed lease starts at the renewal: 19s later it is still fresh.
	now = now.Add(19 * time.Second)
	mustRead(t, a)
	if _, r := s.counts(); r != 1 {
		t.Fatalf("renewed again before two thirds of the renewed lease")
	}
	now = now.Add(2 * time.Second)
	s.mu.Lock()
	s.renewCap = 6 // the max TTL is near
	s.mu.Unlock()
	mustRead(t, a)
	if l, r := s.counts(); l != 1 || r != 2 {
		t.Fatalf("logins, renewals = %d, %d; want 1, 2", l, r)
	}
	// A capped renewal is used up, then replaced by a login, not renewed.
	now = now.Add(5 * time.Second)
	mustRead(t, a)
	if l, r := s.counts(); l != 2 || r != 2 {
		t.Fatalf("logins, renewals = %d, %d; want a login after a capped renewal", l, r)
	}
}

func TestKubernetesNonRenewableTokenIsReplaced(t *testing.T) {
	jwt := fakeJWT()
	s := newK8sServer(jwt)
	s.renewable = false
	srv := httptest.NewServer(s.handler(t))
	defer srv.Close()
	a, _ := k8sAdapter(t, srv, jwt, nil)
	now := time.Now()
	a.c.Now = func() time.Time { return now }
	mustRead(t, a)
	now = now.Add(21 * time.Second)
	mustRead(t, a)
	if l, r := s.counts(); l != 2 || r != 0 {
		t.Fatalf("logins, renewals = %d, %d; want 2, 0", l, r)
	}
}

func TestKubernetesRenewalFailureLogsIn(t *testing.T) {
	for _, status := range []int{403, 400, 500} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			jwt := fakeJWT()
			s := newK8sServer(jwt)
			s.renewFail = status
			srv := httptest.NewServer(s.handler(t))
			defer srv.Close()
			a, _ := k8sAdapter(t, srv, jwt, nil)
			now := time.Now()
			a.c.Now = func() time.Time { return now }
			mustRead(t, a)
			now = now.Add(21 * time.Second)
			mustRead(t, a)
			if l, r := s.counts(); l != 2 || r != 1 {
				t.Fatalf("logins, renewals = %d, %d; want a login after the failed renewal", l, r)
			}
		})
	}
}

func TestKubernetesTokenFileReadAtEachLogin(t *testing.T) {
	jwt := fakeJWT()
	s := newK8sServer(jwt)
	srv := httptest.NewServer(s.handler(t))
	defer srv.Close()
	a, file := k8sAdapter(t, srv, jwt, nil)
	mustRead(t, a)

	// The kubelet rotates the projected token; the old one stops working
	// and the store revokes the session.
	rotated := fakeJWT()
	writeTokenFile(t, file, rotated)
	s.mu.Lock()
	s.jwts = map[string]bool{rotated: true}
	clear(s.tokens)
	s.mu.Unlock()

	mustRead(t, a)
	if l, _ := s.counts(); l != 2 {
		t.Fatalf("logins = %d, want a second login after the 403", l)
	}
	if got := s.seenJWTs[len(s.seenJWTs)-1]; got != rotated {
		t.Fatalf("second login did not present the rotated token")
	}
	// A real policy refusal is retried once, then reported.
	s.mu.Lock()
	s.denyAll = true
	s.mu.Unlock()
	if _, err := a.Read(t.Context(), stores.MustParseRef("bao://kv/x")); !errors.Is(err, stores.ErrPermission) {
		t.Fatalf("policy refusal: %v", err)
	}
	if l, _ := s.counts(); l != 3 {
		t.Fatalf("logins = %d, want exactly one retry", l)
	}
}

func TestKubernetesLoginRefusals(t *testing.T) {
	jwt := fakeJWT()
	s := newK8sServer(jwt)
	srv := httptest.NewServer(s.handler(t))
	defer srv.Close()

	cases := map[string]map[string]any{
		"wrong role":    {"auth.kubernetes.role": "other"},
		"missing mount": {"auth.kubernetes.mount": "nowhere"},
	}
	for name, opts := range cases {
		t.Run(name, func(t *testing.T) {
			a, _ := k8sAdapter(t, srv, jwt, opts)
			err := a.Health(t.Context())
			if !errors.Is(err, stores.ErrPermission) || !strings.Contains(err.Error(), "Kubernetes login failed") {
				t.Fatalf("got %v, want a permission error from the Kubernetes login", err)
			}
		})
	}
	t.Run("unknown service account token", func(t *testing.T) {
		a, _ := k8sAdapter(t, srv, fakeJWT(), nil)
		if err := a.Health(t.Context()); !errors.Is(err, stores.ErrPermission) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("missing token file", func(t *testing.T) {
		before := len(s.seenJWTs)
		missing := filepath.Join(t.TempDir(), "absent")
		a, _ := k8sAdapter(t, srv, jwt, map[string]any{"auth.kubernetes.token-file": missing})
		err := a.Health(t.Context())
		if !errors.Is(err, stores.ErrPermission) || !strings.Contains(err.Error(), missing) || !strings.Contains(err.Error(), "auth.kubernetes.token-file") {
			t.Fatalf("got %v, want a permission error naming the token file", err)
		}
		if len(s.seenJWTs) != before {
			t.Fatalf("store contacted without a token")
		}
	})
	t.Run("empty token file", func(t *testing.T) {
		a, file := k8sAdapter(t, srv, jwt, nil)
		writeTokenFile(t, file, "  ")
		if err := a.Health(t.Context()); !errors.Is(err, stores.ErrPermission) || !strings.Contains(err.Error(), "empty") {
			t.Fatalf("got %v", err)
		}
	})
}

// TestKubernetesNoTokenInOutput seeds generated JWTs and tokens, drives every
// failure path, and greps all error output for them.
func TestKubernetesNoTokenInOutput(t *testing.T) {
	jwt := fakeJWT()
	s := newK8sServer(jwt)
	s.echoJWT = true
	srv := httptest.NewServer(s.handler(t))
	defer srv.Close()
	var outputs []string
	record := func(err error) {
		if err != nil {
			outputs = append(outputs, err.Error(), fmt.Sprintf("%v|%+v|%#v|%s|%q", err, err, err, err, err))
			var se *stores.Error
			if errors.As(err, &se) {
				outputs = append(outputs, se.Detail)
			}
		}
	}

	// A good session, renewed, then refused renewal, then revoked.
	a, file := k8sAdapter(t, srv, jwt, nil)
	now := time.Now()
	a.c.Now = func() time.Time { return now }
	record(a.Health(t.Context()))
	now = now.Add(21 * time.Second)
	record(a.Health(t.Context()))
	s.mu.Lock()
	s.renewFail = 403
	s.mu.Unlock()
	now = now.Add(21 * time.Second)
	record(a.Health(t.Context()))
	// The session token is a credential for the redaction set; the JWT,
	// wiped after login, is not held.
	creds := a.Credentials()
	defer func() {
		for _, v := range creds {
			v.Wipe()
		}
	}()
	if len(creds) == 0 {
		t.Fatal("no session token reported as a credential")
	}
	// The store echoes a rejected JWT in its message.
	stale := fakeJWT()
	writeTokenFile(t, file, stale)
	s.mu.Lock()
	clear(s.tokens)
	s.mu.Unlock()
	_, err := a.Read(t.Context(), stores.MustParseRef("bao://kv/x"))
	if !errors.Is(err, stores.ErrPermission) {
		t.Fatalf("read with a rejected JWT: %v", err)
	}
	record(err)
	// Direct calls with explicit tokens.
	_, _, _, err = a.c.LoginKubernetes(t.Context(), stores.OpRead, stores.Ref{}, "kubernetes", "other", secret.FromString(jwt))
	record(err)
	_, _, err = a.c.RenewSelf(t.Context(), stores.OpRead, stores.Ref{}, secret.FromString("hvs.k8s-"+randHex(12)), time.Minute)
	record(err)

	s.mu.Lock()
	seeded := append([]string{jwt, stale}, s.issued...)
	s.mu.Unlock()
	all := strings.Join(outputs, "\n")
	if !strings.Contains(all, "withheld") {
		t.Errorf("the store's echo of the JWT was not withheld: %s", all)
	}
	for _, v := range seeded {
		if strings.Contains(all, v) {
			t.Fatalf("a token or JWT appears in error output")
		}
	}
	for _, v := range creds {
		if v.Equal(secret.FromString(jwt)) || v.Equal(secret.FromString(stale)) {
			t.Errorf("the service account token is held after login")
		}
	}
}

func TestLoginKubernetesLeavesAdapterTokenAlone(t *testing.T) {
	jwt := fakeJWT()
	s := newK8sServer(jwt)
	srv := httptest.NewServer(s.handler(t))
	defer srv.Close()
	a, _ := k8sAdapter(t, srv, jwt, nil)
	mustRead(t, a)
	own := a.c.TokenCopy()
	defer own.Wipe()

	// Another service account logs in through the same client.
	other := fakeJWT()
	s.mu.Lock()
	s.jwts[other] = true
	s.mu.Unlock()
	tok, ttl, renewable, err := a.c.LoginKubernetes(t.Context(), stores.OpRead, stores.Ref{}, "kubernetes", "scrim", secret.FromString(other))
	if err != nil {
		t.Fatal(err)
	}
	defer tok.Wipe()
	if ttl != 30*time.Second || !renewable || tok.IsZero() {
		t.Fatalf("ttl %s renewable %v", ttl, renewable)
	}
	if !a.c.TokenCopy().Equal(own) || tok.Equal(own) {
		t.Fatal("loginKubernetes changed the adapter's own token")
	}
	// A request with an explicit token carries it, and a refusal is not
	// retried with a login.
	resp, err := a.c.Do(t.Context(), request{Op: stores.OpRead, Method: http.MethodGet, Path: "kv/data/x", Token: tok})
	resp.Wipe()
	if err != nil {
		t.Fatalf("request with the other token: %v", err)
	}
	ttl, renewable, err = a.c.RenewSelf(t.Context(), stores.OpRead, stores.Ref{}, tok, time.Minute)
	if err != nil || ttl != 30*time.Second || !renewable {
		t.Fatalf("renewSelf: %s %v %v", ttl, renewable, err)
	}
	s.mu.Lock()
	clear(s.tokens)
	s.mu.Unlock()
	logins, _ := s.counts()
	resp, err = a.c.Do(t.Context(), request{Op: stores.OpRead, Method: http.MethodGet, Path: "kv/data/x", Token: tok})
	resp.Wipe()
	if !errors.Is(err, stores.ErrPermission) {
		t.Fatalf("revoked explicit token: %v", err)
	}
	if l, _ := s.counts(); l != logins {
		t.Fatal("a refused explicit token triggered a login")
	}
}
