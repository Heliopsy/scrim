// SPDX-License-Identifier: AGPL-3.0-only

package infisical

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores"
	"github.com/heliopsy/scrim/internal/stores/internal/podmantest"
	"github.com/heliopsy/scrim/internal/stores/storetest"
)

// defaultInfisicalVersion is the image tag the integration test runs.
const defaultInfisicalVersion = "v0.167.13"

// admin talks to Infisical with an admin identity token, for test setup
// only. Test credentials are generated per run, so plain strings are fine
// here; adapter code never does this.
type admin struct {
	t     testing.TB
	addr  string
	token string
	org   string
}

func (a *admin) call(method, path string, in any, out any) int {
	a.t.Helper()
	var body io.Reader
	if in != nil {
		b, _ := json.Marshal(in)
		body = bytes.NewReader(b)
	}
	req, _ := http.NewRequestWithContext(a.t.Context(), method, a.addr+path, body)
	req.Header.Set("Content-Type", "application/json")
	if a.token != "" {
		req.Header.Set("Authorization", "Bearer "+a.token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		a.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	if out != nil && resp.StatusCode < 300 {
		if err := json.Unmarshal(b, out); err != nil {
			a.t.Fatalf("%s %s: decode: %v", method, path, err)
		}
	}
	return resp.StatusCode
}

func (a *admin) must(method, path string, in, out any) {
	a.t.Helper()
	if st := a.call(method, path, in, out); st >= 300 {
		a.t.Fatalf("%s %s: HTTP %d", method, path, st)
	}
}

func randB64(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}

// startInfisical plays testdata/pod.yaml with fresh keys and bootstraps the
// instance. It returns the admin client and the backend container name, or
// uses SCRIM_TEST_INFISICAL_ADDR, _TOKEN and _ORG when set (no outage test
// then, since the test does not own that server).
func startInfisical(t *testing.T) (*admin, string) {
	if addr := os.Getenv("SCRIM_TEST_INFISICAL_ADDR"); addr != "" {
		tok, org := os.Getenv("SCRIM_TEST_INFISICAL_TOKEN"), os.Getenv("SCRIM_TEST_INFISICAL_ORG")
		if tok == "" || org == "" {
			t.Fatalf("SCRIM_TEST_INFISICAL_ADDR needs SCRIM_TEST_INFISICAL_TOKEN (admin identity token) and SCRIM_TEST_INFISICAL_ORG")
		}
		return &admin{t: t, addr: strings.TrimRight(addr, "/"), token: tok, org: org}, ""
	}
	podmantest.Require(t)
	tmpl, err := os.ReadFile("testdata/pod.yaml")
	if err != nil {
		t.Fatal(err)
	}
	version := os.Getenv("SCRIM_TEST_INFISICAL_VERSION")
	if version == "" {
		version = defaultInfisicalVersion
	}
	pod := podmantest.Name(t, "inf")
	vars := map[string]string{
		"POD_NAME":          pod,
		"DB_PASSWORD":       randID(16),
		"ENCRYPTION_KEY":    randID(16), // 32 hex characters
		"AUTH_SECRET":       randB64(32),
		"INFISICAL_VERSION": version,
	}
	yaml := os.Expand(string(tmpl), func(k string) string { return vars[k] })
	port := podmantest.FreePort(t)
	start := time.Now()
	podmantest.KubePlay(t, []byte(yaml), fmt.Sprintf("127.0.0.1:%d:8080", port))
	addr := fmt.Sprintf("http://127.0.0.1:%d", port)
	podmantest.WaitHTTP(t, addr+"/api/status", 5*time.Minute, func(s int) bool { return s == 200 })
	t.Logf("Infisical %s ready in %s", version, time.Since(start).Round(time.Second))

	a := &admin{t: t, addr: addr}
	var boot struct {
		Organization struct{ ID string } `json:"organization"`
		Identity     struct {
			Credentials struct{ Token string } `json:"credentials"`
		} `json:"identity"`
	}
	a.must("POST", "/api/v1/admin/bootstrap", map[string]string{
		"email": "admin@scrim.test", "password": randID(16), "organization": "scrim-test",
	}, &boot)
	a.token, a.org = boot.Identity.Credentials.Token, boot.Organization.ID
	return a, pod + "-backend"
}

type project struct{ id, slug string }

func (a *admin) project(name string) project {
	var p struct {
		Project struct{ ID, Slug string } `json:"project"`
	}
	a.must("POST", "/api/v2/workspace", map[string]string{"projectName": name}, &p)
	return project{p.Project.ID, p.Project.Slug}
}

// identity creates a Universal Auth machine identity with no organisation
// access and returns its ID, client ID and client secret.
func (a *admin) identity(name string) (id, clientID, clientSecret string) {
	var idn struct {
		Identity struct{ ID string } `json:"identity"`
	}
	a.must("POST", "/api/v1/identities", map[string]string{"name": name, "organizationId": a.org, "role": "no-access"}, &idn)
	var ua struct {
		IdentityUniversalAuth struct{ ClientID string } `json:"identityUniversalAuth"`
	}
	a.must("POST", "/api/v1/auth/universal-auth/identities/"+idn.Identity.ID, map[string]any{"accessTokenTTL": 3600}, &ua)
	var cs struct{ ClientSecret string }
	a.must("POST", "/api/v1/auth/universal-auth/identities/"+idn.Identity.ID+"/client-secrets", map[string]any{}, &cs)
	return idn.Identity.ID, ua.IdentityUniversalAuth.ClientID, cs.ClientSecret
}

func (a *admin) member(p project, identityID, role string) {
	a.must("POST", "/api/v2/workspace/"+p.id+"/identity-memberships/"+identityID, map[string]string{"role": role}, nil)
}

func TestConformanceInfisical(t *testing.T) {
	adm, backend := startInfisical(t)
	suffix := randID(3)
	main := adm.project("scrim-conformance-" + suffix)
	other := adm.project("scrim-readonly-" + suffix)
	idID, clientID, clientSecret := adm.identity("scrim-" + suffix)
	adm.member(main, idID, "admin")
	adm.member(other, idID, "viewer")

	newInf := func(t testing.TB) *Adapter {
		t.Helper()
		a, err := New(t.Context(), stores.Instance{
			Name: "inf", Kind: Kind,
			Options: map[string]any{
				"address":           adm.addr,
				"client-id":         clientID,
				"client-secret":     config.SecretRef("env:INF"),
				"timeout":           "3s",
				"watch.interval":    "500ms",
				"watch.max-backoff": "2s",
				"expand-references": false,
			},
			Resolve: resolver(map[string]string{"env:INF": clientSecret}),
		})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		return a.(*Adapter)
	}

	var outage func(storetest.TB) func()
	if backend != "" {
		outage = func(t storetest.TB) func() {
			tb := t.(testing.TB)
			podmantest.MustPodman(tb, "pause", backend)
			return func() {
				podmantest.MustPodman(tb, "unpause", backend)
				podmantest.WaitHTTP(tb, adm.addr+"/api/status", time.Minute, func(s int) bool { return s == 200 })
			}
		}
	}

	runConformance(t, func(t storetest.TB) storetest.Harness {
		return storetest.Harness{
			Adapter:         newInf(t.(testing.TB)),
			Prefix:          main.slug + "/dev/conf-" + randID(4),
			SingleField:     Field,
			VersionSelector: true,
			Labels:          true,
			Delete: func(t storetest.TB, ref stores.Ref) {
				l, _ := splitSecret(ref.Path)
				adm.must("DELETE", "/api/v4/secrets/"+l.key, map[string]string{
					"projectId": main.id, "environment": l.env, "secretPath": l.folder,
				}, nil)
			},
			Outage: outage,
			Reject: func(storetest.TB) stores.Ref {
				// A project where the identity is only a viewer.
				return stores.Ref{Scheme: "inf", Path: other.slug + "/dev/REJECTED"}
			},
			WatchTimeout: 15 * time.Second,
		}
	})

	t.Run("ProjectByID", func(t *testing.T) {
		a := newInf(t)
		defer func() { _ = a.Close() }()
		ref := stores.Ref{Scheme: "inf", Path: main.id + "/staging/BY_ID"}
		val := "v-" + randID(12)
		if _, err := a.Write(t.Context(), ref, map[string]secret.Value{Field: secret.FromString(val)}, stores.WriteOptions{}); err != nil {
			t.Fatal(err)
		}
		s, err := a.Read(t.Context(), stores.Ref{Scheme: "inf", Path: main.slug + "/staging/BY_ID"})
		if err != nil {
			t.Fatal(err)
		}
		defer s.Wipe()
		if v, _ := s.Field(Field); plain(t, v) != val {
			t.Errorf("value read by slug differs from the one written by ID")
		}
	})

	t.Run("UnknownEnvironment", func(t *testing.T) {
		a := newInf(t)
		defer func() { _ = a.Close() }()
		_, err := a.Read(t.Context(), stores.Ref{Scheme: "inf", Path: main.slug + "/no-such-env/X"})
		if err == nil {
			t.Fatal("Read in an unknown environment succeeded")
		}
		t.Logf("unknown environment: %v", err)
	})
}
