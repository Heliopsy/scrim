// SPDX-License-Identifier: AGPL-3.0-only

package infisical

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores"
	"github.com/heliopsy/scrim/internal/stores/internal/satoken"
)

func fakeJWT() string { return "eyJhbGciOiJSUzI1NiJ9." + randID(24) + "." + randID(16) }

func writeToken(t *testing.T, path, jwt string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(jwt+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// k8sInstance is a Kubernetes Auth instance against f whose token file
// holds jwt. It has no credential resolver: none is needed.
func k8sInstance(t *testing.T, f *fake, jwt string, extra map[string]any) (stores.Instance, string) {
	t.Helper()
	file := filepath.Join(t.TempDir(), "token")
	writeToken(t, file, jwt)
	opts := map[string]any{
		"address": f.srv.URL,
		"auth": map[string]any{
			"method":     "kubernetes-auth",
			"kubernetes": map[string]any{"identity-id": f.identityID, "token-file": file},
		},
	}
	for k, v := range extra {
		opts[k] = v
	}
	return stores.Instance{Name: "inf", Kind: Kind, Options: opts}, file
}

func k8sAdapter(t *testing.T, f *fake, jwt string, extra map[string]any) (*Adapter, string) {
	t.Helper()
	inst, file := k8sInstance(t, f, jwt, extra)
	a, err := New(t.Context(), inst)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = a.Close() })
	return a.(*Adapter), file
}

func TestKubernetesAuthOptions(t *testing.T) {
	f := newFake(t)
	inst, _ := k8sInstance(t, f, "x", nil)
	inst.Options["auth"].(map[string]any)["kubernetes"] = map[string]any{"identity-id": " " + f.identityID + " "}
	a, err := New(t.Context(), inst)
	if err != nil {
		t.Fatal(err)
	}
	s := a.(*Adapter).s
	if s.method != methodKubernetesAuth || s.identityID != f.identityID || s.tokenFile != satoken.DefaultPath {
		t.Errorf("decoded method %q identity %q file %q", s.method, s.identityID, s.tokenFile)
	}
	_ = a.Close()

	inst, _ = k8sInstance(t, f, "x", map[string]any{"client-id": "cid", "client-secret": "env:INF_SECRET"})
	inst.Options["auth"].(map[string]any)["kubernetes"] = map[string]any{"token-file": ""}
	_, err = New(t.Context(), inst)
	if err == nil {
		t.Fatal("invalid Kubernetes Auth options accepted")
	}
	for _, want := range []string{"identity-id is required", "client-id is not used", "client-secret is not used", "token-file must not be empty"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
}

func TestKubernetesAuthLoginAndRelogin(t *testing.T) {
	f := newFake(t)
	jwt := fakeJWT()
	f.jwts[jwt] = true
	f.tokenTTL = 60
	a, file := k8sAdapter(t, f, jwt, nil)
	now := time.Now()
	a.c.now = func() time.Time { return now }
	if err := a.Health(t.Context()); err != nil {
		t.Fatal(err)
	}
	if f.seenJWTs[0] != jwt {
		t.Fatal("login did not present the token file's content (trimmed)")
	}
	// The kubelet rotates the token; the next login, before the access
	// token's 60s run out (30s margin), reads the new one.
	rotated := fakeJWT()
	writeToken(t, file, rotated)
	f.mu.Lock()
	f.jwts = map[string]bool{rotated: true}
	f.mu.Unlock()
	now = now.Add(20 * time.Second)
	_ = a.Health(t.Context())
	if f.loginCount() != 1 {
		t.Fatalf("logins = %d, want the token reused while fresh", f.loginCount())
	}
	now = now.Add(11 * time.Second)
	if err := a.Health(t.Context()); err != nil {
		t.Fatalf("Health after rotation: %v", err)
	}
	if f.loginCount() != 2 || f.seenJWTs[len(f.seenJWTs)-1] != rotated {
		t.Fatalf("logins = %d; want a second login with the rotated token", f.loginCount())
	}
	// A revoked access token is replaced once.
	f.expireTokens()
	if _, err := a.Read(t.Context(), stores.MustParseRef("inf://proj/dev/X")); !errors.Is(err, stores.ErrNotFound) {
		t.Fatalf("Read after revocation: %v, want not found", err)
	}
	if f.loginCount() != 3 {
		t.Fatalf("logins = %d, want a login after the refusal", f.loginCount())
	}
}

func TestKubernetesAuthRefusals(t *testing.T) {
	f := newFake(t)
	jwt := fakeJWT()
	f.jwts[jwt] = true
	t.Run("wrong identity", func(t *testing.T) {
		inst, _ := k8sInstance(t, f, jwt, nil)
		inst.Options["auth"].(map[string]any)["kubernetes"].(map[string]any)["identity-id"] = "7f3c1a2e-0000-4000-8000-000000000000"
		a, err := New(t.Context(), inst)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = a.Close() }()
		err = a.Health(t.Context())
		if !errors.Is(err, stores.ErrPermission) || !strings.Contains(err.Error(), "Kubernetes Auth login refused") {
			t.Fatalf("got %v, want a permission error from the login", err)
		}
	})
	t.Run("rejected service account token", func(t *testing.T) {
		a, _ := k8sAdapter(t, f, fakeJWT(), nil)
		if err := a.Health(t.Context()); !errors.Is(err, stores.ErrPermission) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("missing token file", func(t *testing.T) {
		before := len(f.seenJWTs)
		inst, _ := k8sInstance(t, f, jwt, nil)
		missing := filepath.Join(t.TempDir(), "absent")
		inst.Options["auth"].(map[string]any)["kubernetes"].(map[string]any)["token-file"] = missing
		a, err := New(t.Context(), inst)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = a.Close() }()
		_, err = a.Read(t.Context(), stores.MustParseRef("inf://proj/dev/X"))
		if !errors.Is(err, stores.ErrPermission) || !strings.Contains(err.Error(), missing) {
			t.Fatalf("got %v, want a permission error naming the file", err)
		}
		if len(f.seenJWTs) != before {
			t.Fatal("store contacted without a token")
		}
	})
}

// TestKubernetesAuthNoTokenInOutput seeds generated JWTs and access tokens,
// drives the failure paths and greps every error for them.
func TestKubernetesAuthNoTokenInOutput(t *testing.T) {
	f := newFake(t)
	f.echoJWT = true
	jwt := fakeJWT()
	f.jwts[jwt] = true
	a, file := k8sAdapter(t, f, jwt, nil)
	var outputs []string
	record := func(err error) {
		if err != nil {
			outputs = append(outputs, fmt.Sprintf("%v|%+v|%#v|%s|%q", err, err, err, err, err))
		}
	}
	record(a.Health(t.Context()))
	creds := a.Credentials()
	defer func() {
		for _, v := range creds {
			v.Wipe()
		}
	}()
	if len(creds) != 1 || !strings.HasPrefix(plain(t, creds[0]), "tok-") {
		t.Fatalf("credentials: %d, want only the access token", len(creds))
	}
	stale := fakeJWT()
	writeToken(t, file, stale)
	f.expireTokens()
	_, err := a.Read(t.Context(), stores.MustParseRef("inf://proj/dev/X"))
	if !errors.Is(err, stores.ErrPermission) {
		t.Fatalf("read with a rejected JWT: %v", err)
	}
	record(err)

	all := strings.Join(outputs, "\n")
	if !strings.Contains(all, "withheld") {
		t.Errorf("the store's echo of the JWT was not withheld: %s", all)
	}
	f.mu.Lock()
	seeded := append([]string{jwt, stale}, f.issued...)
	f.mu.Unlock()
	for _, v := range seeded {
		if strings.Contains(all, v) {
			t.Fatal("a JWT or access token appears in error output")
		}
	}
	for _, v := range creds {
		if v.Equal(secret.FromString(jwt)) {
			t.Error("the service account token is held after login")
		}
	}
}
