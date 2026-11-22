// SPDX-License-Identifier: AGPL-3.0-only

package infisical

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"slices"
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
// renovate: datasource=docker depName=docker.io/infisical/infisical
const defaultInfisicalVersion = "v0.167.14"

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

	t.Run("Labels", func(t *testing.T) {
		testLabelsLive(t, adm, main, newInf(t))
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

// testLabelsLive checks the native labels against a real server: tags,
// folders, metadata (plain, forged and encrypted), reminders and imports.
func testLabelsLive(t *testing.T, adm *admin, p project, a *Adapter) {
	defer func() { _ = a.Close() }()
	folder := func(env, path, name string) {
		st := adm.call("POST", "/api/v1/folders", map[string]string{
			"workspaceId": p.id, "projectId": p.id, "environment": env, "path": path, "name": name,
		}, nil)
		if st >= 300 && st != 400 {
			t.Fatalf("create folder %s%s: HTTP %d", path, name, st)
		}
	}
	folder("prod", "/", "db")
	folder("prod", "/db", "Primary")
	folder("prod", "/", "app")
	folder("dev", "/", "shared")

	var tag struct {
		Tag struct{ ID string } `json:"tag"`
	}
	adm.must("POST", "/api/v1/projects/"+p.id+"/tags", map[string]string{"slug": "pci", "color": "#ff0000"}, &tag)

	value, comment, enc := "v-"+randID(12), "c-"+randID(12), "e-"+randID(12)
	body := map[string]any{
		"projectId": p.id, "environment": "prod", "secretPath": "/db/Primary", "type": "shared",
		"secretValue": value, "secretComment": comment, "tagIds": []string{tag.Tag.ID},
		"secretReminderRepeatDays": 30, "secretReminderNote": comment,
		"secretMetadata": []map[string]any{
			{"key": "owner", "value": "payments"},
			{"key": "infisical.environment", "value": "dev"},
			{"key": "pin", "value": enc, "isEncrypted": true},
		},
	}
	encrypted := true
	if st := adm.call("POST", "/api/v4/secrets/DB_PASSWORD", body, nil); st >= 300 {
		t.Logf("create with reminder and encrypted metadata: HTTP %d; retrying without", st)
		encrypted = false
		delete(body, "secretReminderRepeatDays")
		delete(body, "secretReminderNote")
		body["secretMetadata"] = body["secretMetadata"].([]map[string]any)[:2]
		adm.must("POST", "/api/v4/secrets/DB_PASSWORD", body, nil)
	}
	adm.must("POST", "/api/v4/secrets/SHARED_KEY", map[string]any{
		"projectId": p.id, "environment": "dev", "secretPath": "/shared", "type": "shared", "secretValue": "s-" + randID(8),
	}, nil)
	adm.must("POST", "/api/v2/secret-imports", map[string]any{
		"projectId": p.id, "environment": "prod", "path": "/app",
		"import": map[string]string{"environment": "dev", "path": "/shared"},
	}, nil)

	read := func(path string) map[string]string {
		t.Helper()
		s, err := a.Read(t.Context(), stores.Ref{Scheme: "inf", Path: path})
		if err != nil {
			t.Fatalf("Read %s: %v", path, err)
		}
		s.Wipe()
		return s.Meta.Labels
	}
	got := read(p.slug + "/prod/db/Primary/DB_PASSWORD")
	for _, k := range slices.Sorted(maps.Keys(got)) {
		t.Logf("label %s = %q", k, got[k])
	}
	want := map[string]string{
		"infisical.project": p.slug, "infisical.project.id": p.id, "infisical.project.slug": p.slug,
		"infisical.org.id": adm.org, "infisical.environment": "prod", "infisical.environment.name": "Production",
		"infisical.folder": "/db/Primary", "infisical.folder.db": "true", "infisical.folder.db.Primary": "true",
		"infisical.key": "DB_PASSWORD", "infisical.path": "/db/Primary/DB_PASSWORD", "infisical.type": "shared",
		"infisical.version": "1", "infisical.tag": "pci", "infisical.tag.pci": "true",
		"infisical.meta.owner": "payments", "infisical.meta.infisical.environment": "dev", "owner": "payments",
		"infisical.rotation": "false", "infisical.imported": "false",
	}
	if encrypted {
		want["infisical.encrypted-meta"] = "pin"
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("label %s = %q, want %q", k, got[k], v)
		}
	}
	for _, k := range []string{"infisical.created", "infisical.updated", "infisical.project.name", "infisical.environment.id"} {
		if got[k] == "" {
			t.Errorf("label %s missing", k)
		}
	}
	ms, err := a.List(t.Context(), stores.Ref{Scheme: "inf", Path: p.slug + "/prod/db"})
	if err != nil || len(ms) != 1 {
		t.Fatalf("List: %v (%d secrets)", err, len(ms))
	}
	if encrypted {
		// Reminders come with listings only.
		want["infisical.reminder"] = "true"
		want["infisical.reminder.days"] = "30"
	}
	for k, v := range want {
		if ms[0].Labels[k] != v {
			t.Errorf("List: label %s = %q, want %q", k, ms[0].Labels[k], v)
		}
	}
	byID := read(p.id + "/prod/db/Primary/DB_PASSWORD")
	if byID["infisical.project.slug"] != p.slug || byID["infisical.project.name"] == "" {
		t.Errorf("by ID: project labels %q / %q", byID["infisical.project.slug"], byID["infisical.project.name"])
	}
	for where, l := range map[string]map[string]string{"Read": got, "List": ms[0].Labels, "by ID": byID} {
		for k, v := range l {
			for _, needle := range []string{value, comment, enc} {
				if strings.Contains(k+"="+v, needle) {
					t.Errorf("%s: label %s holds a value, comment or encrypted metadata", where, k)
				}
			}
		}
	}

	imp := read(p.slug + "/prod/app/SHARED_KEY")
	for k, v := range map[string]string{
		"infisical.environment": "prod", "infisical.folder": "/app", "infisical.imported": "true",
		"infisical.import.environment": "dev", "infisical.import.path": "/shared",
	} {
		if imp[k] != v {
			t.Errorf("imported: label %s = %q, want %q", k, imp[k], v)
		}
	}

	// ReadMetadata: the same metadata as Read, from a request Infisical
	// answers without the value.
	for _, path := range []string{
		p.slug + "/prod/db/Primary/DB_PASSWORD", p.id + "/prod/db/Primary/DB_PASSWORD",
		p.slug + "/prod/db/Primary/DB_PASSWORD?version=1", p.slug + "/prod/app/SHARED_KEY",
	} {
		ref := stores.Ref{Scheme: "inf"}
		ref.Path, ref.Selectors, _ = strings.Cut(path, "?")
		s, err := a.Read(t.Context(), ref)
		if err != nil {
			t.Fatalf("Read %s: %v", path, err)
		}
		s.Wipe()
		m, err := a.ReadMetadata(t.Context(), ref)
		if err != nil {
			t.Fatalf("ReadMetadata %s: %v", path, err)
		}
		if !reflect.DeepEqual(m, s.Meta) {
			t.Errorf("%s: ReadMetadata differs from Read\n got %#v\nwant %#v", path, m, s.Meta)
		}
	}
	if _, err := a.ReadMetadata(t.Context(), stores.Ref{Scheme: "inf", Path: p.slug + "/prod/db/Primary/MISSING"}); !errors.Is(err, stores.ErrNotFound) {
		t.Errorf("ReadMetadata of a missing secret: %v", err)
	}
	var hidden struct {
		Secret struct {
			Value  string `json:"secretValue"`
			Hidden *bool  `json:"secretValueHidden"`
			Tags   []struct {
				Slug string `json:"slug"`
			} `json:"tags"`
		} `json:"secret"`
	}
	adm.must("GET", "/api/v4/secrets/DB_PASSWORD?"+url.Values{
		"projectId": {p.id}, "environment": {"prod"}, "secretPath": {"/db/Primary"}, "type": {"shared"},
		"viewSecretValue": {"false"}, "expandSecretReferences": {"false"},
	}.Encode(), nil, &hidden)
	if hidden.Secret.Value == value || hidden.Secret.Hidden == nil || !*hidden.Secret.Hidden || len(hidden.Secret.Tags) != 1 {
		t.Errorf("Infisical does not answer viewSecretValue=false with a hidden value and the tags (hidden %v, %d tags)",
			hidden.Secret.Hidden, len(hidden.Secret.Tags))
	}
}
