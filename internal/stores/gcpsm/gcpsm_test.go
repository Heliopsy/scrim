// SPDX-License-Identifier: AGPL-3.0-only

package gcpsm

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores"
)

func ref(path string) stores.Ref { return stores.Ref{Scheme: "gsm", Path: path} }

// saKeyJSON returns a service account key file for the fake's token
// endpoint and registers the key with the fake.
func saKeyJSON(t *testing.T, f *fake) string {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.saKey = k
	f.mu.Unlock()
	b, _ := json.Marshal(map[string]string{
		"type":           "service_account",
		"project_id":     f.project,
		"private_key_id": randHex(8),
		"private_key":    string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})),
		"client_email":   f.saEmail,
		"client_id":      "1234567890",
		"token_uri":      f.srv.URL + "/token",
	})
	return string(b)
}

func instance(f *fake, opts map[string]any, refs map[string]string) stores.Instance {
	if _, ok := opts["endpoint"]; !ok {
		opts["endpoint"] = f.srv.URL
	}
	return stores.Instance{Name: "gsm", Kind: Kind, Options: opts, Resolve: resolver(refs)}
}

func readValue(t *testing.T, a *Adapter, r stores.Ref) string {
	t.Helper()
	s, err := a.Read(t.Context(), r)
	if err != nil {
		t.Fatalf("Read %s: %v", r, err)
	}
	defer s.Wipe()
	v, _ := s.Field(Field)
	return plain(t, v)
}

func TestAuthServiceAccountKeyByReference(t *testing.T) {
	f := newFake(t)
	key := saKeyJSON(t, f)
	f.put("", "app--token", []byte("v1-"+randHex(4)))
	a, err := newAdapter(instance(f, map[string]any{"project": f.project, "auth.method": "credentials", "credentials": "file:/run/sa.json"},
		map[string]string{"file:/run/sa.json": key}), nil, "")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = a.Close() }()
	if f.jwtSeen != 0 {
		t.Fatalf("New contacted the token endpoint")
	}
	readValue(t, a, ref("app/token"))
	if f.jwtSeen != 1 {
		t.Errorf("token endpoint saw %d JWT grants, want 1", f.jwtSeen)
	}
	// The private key and the access token are held for the redaction set.
	creds := a.Credentials()
	var gotKey, gotTok bool
	for _, c := range creds {
		s := plain(t, c)
		gotKey = gotKey || strings.Contains(s, "PRIVATE KEY")
		gotTok = gotTok || s == f.issued[len(f.issued)-1]
		c.Wipe()
	}
	if !gotKey || !gotTok {
		t.Errorf("Credentials: private key %v, access token %v; want both", gotKey, gotTok)
	}
}

func TestAuthADCFromEnvironment(t *testing.T) {
	f := newFake(t)
	key := saKeyJSON(t, f)
	file := filepath.Join(t.TempDir(), "adc.json")
	if err := os.WriteFile(file, []byte(key), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", file)
	f.put("", "adc", []byte("x"))
	// No project option: it comes from the credentials.
	a, err := newAdapter(instance(f, map[string]any{}, nil), nil, "")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = a.Close() }()
	if got := readValue(t, a, ref("adc")); got != "x" {
		t.Errorf("read %q", got)
	}
	if f.jwtSeen != 1 {
		t.Errorf("JWT grants %d, want 1", f.jwtSeen)
	}
	if got := a.WriteLabels(ref("n"))["gcpsm.project"]; got != f.project {
		t.Errorf("write labels name project %q, want the credentials' %q", got, f.project)
	}
}

func TestAuthWorkloadIdentityFederation(t *testing.T) {
	f := newFake(t)
	dir := t.TempDir()
	subject := "eyJ.federated." + randHex(8)
	if err := os.WriteFile(filepath.Join(dir, "token"), []byte(subject), 0o600); err != nil {
		t.Fatal(err)
	}
	f.stsAud = "//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/providers/k8s"
	f.stsToken = subject
	cfg, _ := json.Marshal(map[string]any{
		"type":               "external_account",
		"audience":           f.stsAud,
		"subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
		"token_url":          f.srv.URL + "/sts/v1/token",
		"credential_source":  map[string]any{"file": filepath.Join(dir, "token")},
	})
	file := filepath.Join(dir, "wif.json")
	if err := os.WriteFile(file, cfg, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", file)
	f.put("", "wif", []byte("y"))
	a, err := newAdapter(instance(f, map[string]any{"project": f.project}, nil), nil, "")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = a.Close() }()
	readValue(t, a, ref("wif"))
	if f.stsSeen != 1 {
		t.Errorf("STS exchanges %d, want 1", f.stsSeen)
	}
	// Without a project option or a project in the credentials, the
	// adapter says what to set.
	b, err := newAdapter(instance(f, map[string]any{}, nil), nil, "")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = b.Close() }()
	_, err = b.Read(t.Context(), ref("wif"))
	if !errors.Is(err, stores.ErrInvalidRef) || !strings.Contains(err.Error(), "option project") {
		t.Errorf("read without a project: %v", err)
	}
}

func TestAuthMetadataServer(t *testing.T) {
	f := newFake(t)
	f.meta = true
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "")
	t.Setenv("HOME", t.TempDir()) // no gcloud application default file
	t.Setenv("GCE_METADATA_HOST", f.host())
	f.put("", "gke", []byte("z"))
	a, err := newAdapter(instance(f, map[string]any{"project": f.project}, nil), nil, "")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = a.Close() }()
	readValue(t, a, ref("gke"))
	if f.metaSeen != 1 {
		t.Errorf("metadata token requests %d, want 1", f.metaSeen)
	}
}

func TestAuthImpersonation(t *testing.T) {
	f := newFake(t)
	key := saKeyJSON(t, f)
	target := "reader@scrim-test.iam.gserviceaccount.com"
	f.put("", "imp", []byte("w"))
	inst := instance(f, map[string]any{
		"project": f.project, "auth.method": "credentials", "credentials": "env:SA",
		"auth.impersonate-service-account": target,
	}, map[string]string{"env:SA": key})
	a, err := newAdapter(inst, nil, f.srv.URL+"/iam")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = a.Close() }()
	_, err = a.Read(t.Context(), ref("imp"))
	if !errors.Is(err, stores.ErrPermission) || !strings.Contains(err.Error(), "impersonate") {
		t.Fatalf("impersonation not allowed: %v, want permission denied naming impersonation", err)
	}
	f.mu.Lock()
	f.impAllow[target] = true
	f.mu.Unlock()
	b, err := newAdapter(inst, nil, f.srv.URL+"/iam")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = b.Close() }()
	readValue(t, b, ref("imp"))
	if f.impSeen != 2 {
		t.Errorf("generateAccessToken calls %d, want 2", f.impSeen)
	}
}

func TestAuthRefused(t *testing.T) {
	f := newFake(t)
	f.put("", "x", []byte("v"))
	a, err := newAdapter(instance(f, map[string]any{"project": f.project, "auth.method": "access-token", "token": "env:T"},
		map[string]string{"env:T": "ya29.not-issued"}), nil, "")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = a.Close() }()
	_, err = a.Read(t.Context(), ref("x"))
	if !errors.Is(err, stores.ErrPermission) || strings.Contains(err.Error(), "ya29") {
		t.Errorf("refused token: %v", err)
	}
	if err := a.Health(t.Context()); !errors.Is(err, stores.ErrPermission) {
		t.Errorf("Health with a refused token: %v", err)
	}
	// A bad service account key is refused by the token endpoint.
	key := saKeyJSON(t, f)
	f.mu.Lock()
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	f.saKey = other
	f.mu.Unlock()
	b, _ := newAdapter(instance(f, map[string]any{"project": f.project, "auth.method": "credentials", "credentials": "env:SA"},
		map[string]string{"env:SA": key}), nil, "")
	defer func() { _ = b.Close() }()
	if _, err := b.Read(t.Context(), ref("x")); !errors.Is(err, stores.ErrPermission) || strings.Contains(err.Error(), "PRIVATE") {
		t.Errorf("wrong key: %v", err)
	}
}

func TestOptions(t *testing.T) {
	f := newFake(t)
	for name, tc := range map[string]struct {
		opts map[string]any
		want string
	}{
		"unknown":       {map[string]any{"projet": "x"}, "did you mean project"},
		"bad method":    {map[string]any{"auth.method": "magic"}, "unsupported method"},
		"creds missing": {map[string]any{"auth.method": "credentials"}, "option credentials is required"},
		"adc and token": {map[string]any{"token": "env:T"}, "not used with auth.method adc"},
		"format":        {map[string]any{"format": "yaml"}, "option format"},
		"separator":     {map[string]any{"path-separator": "."}, "option path-separator"},
		"location":      {map[string]any{"location": "global"}, "option location"},
		"replicas":      {map[string]any{"location": "us-east1", "replication.locations": []any{"us-east4"}}, "does not apply to regional"},
		"endpoint":      {map[string]any{"endpoint": "http://example.com"}, "option endpoint"},
		"delegates":     {map[string]any{"auth.delegates": []any{"a@b.c"}}, "needs auth.impersonate-service-account"},
		"project":       {map[string]any{"project": "Not A Project"}, "option project"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := newAdapter(instance(f, tc.opts, map[string]string{}), nil, "")
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("got %v, want an error containing %q", err, tc.want)
			}
		})
	}
	a, err := newAdapter(instance(f, map[string]any{"location": "europe-west1", "endpoint": ""}, nil), nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if got := a.s.endpoint.String(); got != "https://secretmanager.europe-west1.rep.googleapis.com" {
		t.Errorf("regional endpoint %s", got)
	}
	if a.Capabilities().Has(stores.CapWrite) == false {
		t.Errorf("write not declared")
	}
	ro, _ := newAdapter(instance(f, map[string]any{"read-only": true}, nil), nil, "")
	if ro.Capabilities().Has(stores.CapWrite) {
		t.Errorf("read-only store declares write")
	}
}

func TestPaths(t *testing.T) {
	f := newFake(t)
	a := adapterFor(t, f, nil)
	ctx := t.Context()
	for _, p := range []string{"bad.name", "a-/b", "a/-b", "a--b/c", "x/" + strings.Repeat("y", 300)} {
		_, err := a.Write(ctx, ref(p), map[string]secret.Value{Field: secret.FromString("v")}, stores.WriteOptions{})
		if !errors.Is(err, stores.ErrInvalidRef) {
			t.Errorf("Write %s: %v, want ErrInvalidRef", p, err)
		}
	}
	// Names that do not map back to a path are left out of listings.
	f.put("", "odd---name", []byte("1"))
	f.put("", "-lead", []byte("1"))
	f.put("", "plain_name", []byte("1"))
	f.put("", "dir--leaf", []byte("1"))
	ms, err := a.List(ctx, ref("*"))
	if err != nil {
		t.Fatal(err)
	}
	var paths []string
	for _, m := range ms {
		paths = append(paths, m.Ref.Path)
	}
	if strings.Join(paths, ",") != "dir/leaf,plain_name" {
		t.Errorf("listed %v", paths)
	}
	// A glob matches by name prefix.
	ms, _ = a.List(ctx, ref("pla*"))
	if len(ms) != 1 || ms[0].Ref.Path != "plain_name" {
		t.Errorf("glob listed %v", ms)
	}
}

func TestVersions(t *testing.T) {
	f := newFake(t)
	a := adapterFor(t, f, nil)
	ctx := t.Context()
	v1, v2 := "one-"+randHex(4), "two-"+randHex(4)
	f.put("", "rot", []byte(v1))
	f.put("", "rot", []byte(v2))
	f.edit("", "rot", func(s *fakeSecret) { s.aliases = map[string]int{"stable": 1, "canary": 2} })
	for sel, want := range map[string]string{"version=1": v1, "version=2": v2, "version=latest": v2, "version=stable": v1} {
		r := ref("rot")
		r.Selectors = sel
		if got := readValue(t, a, r); got != want {
			t.Errorf("%s read the wrong version", sel)
		}
	}
	r := ref("rot")
	r.Selectors = "version=stable"
	s, err := a.Read(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	s.Wipe()
	if s.Meta.Version != "1" || s.Meta.Labels["gcpsm.version-alias"] != "stable" || s.Meta.Labels["gcpsm.version-alias.stable"] != "true" ||
		s.Meta.Labels["gcpsm.alias"] != "canary,stable" {
		t.Errorf("alias read: version %q labels %v", s.Meta.Version, s.Meta.Labels)
	}
	// A disabled version has no value to read.
	f.edit("", "rot", func(s *fakeSecret) { s.versions[1].state = "DISABLED" })
	if _, err := a.Read(ctx, ref("rot")); !errors.Is(err, stores.ErrNotFound) {
		t.Errorf("read of a disabled latest version: %v", err)
	}
	if _, err := a.ReadMetadata(ctx, ref("rot")); !errors.Is(err, stores.ErrNotFound) {
		t.Errorf("metadata of a disabled latest version: %v", err)
	}
	ms, _ := a.List(ctx, ref("rot"))
	if len(ms) != 0 {
		t.Errorf("a secret whose latest version is disabled is listed")
	}
	for _, sel := range []string{"version=0", "version=1.5", "version=-a", "stage=x"} {
		r := ref("rot")
		r.Selectors = sel
		if _, err := a.Read(ctx, r); !errors.Is(err, stores.ErrInvalidRef) {
			t.Errorf("selector %s: %v", sel, err)
		}
	}
}

func TestPayloadIntegrity(t *testing.T) {
	f := newFake(t)
	a := adapterFor(t, f, nil)
	v := "crc-" + randHex(6)
	f.put("", "c", []byte(v))
	f.corrupt = true
	_, err := a.Read(t.Context(), ref("c"))
	if !errors.Is(err, stores.ErrUnavailable) || !strings.Contains(err.Error(), "CRC32C") || strings.Contains(fmt.Sprintf("%+v", err), v) {
		t.Errorf("corrupted payload: %v", err)
	}
	f.corrupt = false
	// Binary payloads round-trip byte for byte in raw format.
	bin := []byte{0, 1, 2, 0xff, 0xfe, '\n'}
	if _, err := a.Write(t.Context(), ref("bin"), map[string]secret.Value{Field: secret.New(bin)}, stores.WriteOptions{}); err != nil {
		t.Fatal(err)
	}
	if got := readValue(t, a, ref("bin")); got != string(bin) {
		t.Errorf("binary payload changed")
	}
	// Oversized payloads are refused before anything is sent.
	big := secret.New(make([]byte, maxPayload+1))
	n := len(f.ids())
	if _, err := a.Write(t.Context(), ref("big"), map[string]secret.Value{Field: big}, stores.WriteOptions{}); !errors.Is(err, stores.ErrUnsupported) {
		t.Errorf("oversized write: %v", err)
	}
	if len(f.ids()) != n {
		t.Errorf("an oversized write created a secret")
	}
}

func TestJSONFormat(t *testing.T) {
	f := newFake(t)
	a := adapterFor(t, f, map[string]any{"format": "json"})
	ctx := t.Context()
	f.put("", "db", []byte(`{"user":"app","password":"pé-`+"x"+`","port":5432,"opt":null}`))
	s, err := a.Read(ctx, ref("db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Wipe()
	if strings.Join(s.Meta.Fields, ",") != "password,port,user" {
		t.Errorf("fields %v", s.Meta.Fields)
	}
	if p, _ := s.Field("password"); plain(t, p) != "pé-x" {
		t.Errorf("password decoded wrong")
	}
	if p, _ := s.Field("port"); plain(t, p) != "5432" {
		t.Errorf("number field kept as %q", plain(t, p))
	}
	f.put("", "notjson", []byte("plain text"))
	if _, err := a.Read(ctx, ref("notjson")); !errors.Is(err, stores.ErrUnsupported) || strings.Contains(err.Error(), "plain text") {
		t.Errorf("non-JSON payload: %v", err)
	}
	if _, err := a.Write(ctx, ref("bad"), map[string]secret.Value{"k": secret.New([]byte{0xff})}, stores.WriteOptions{}); !errors.Is(err, stores.ErrUnsupported) {
		t.Errorf("invalid UTF-8 in JSON format: %v", err)
	}
}

func TestWriteCleansUpRefusedCreate(t *testing.T) {
	f := newFake(t)
	a := adapterFor(t, f, nil)
	// Creation is allowed, the version is refused: no empty secret stays.
	f.mu.Lock()
	f.denyVers = "half"
	f.mu.Unlock()
	if _, err := a.Write(t.Context(), ref("half"), map[string]secret.Value{Field: secret.FromString("v")}, stores.WriteOptions{}); !errors.Is(err, stores.ErrPermission) {
		t.Fatalf("refused write: %v", err)
	}
	if ids := f.ids(); len(ids) != 0 {
		t.Errorf("refused write left secrets %v", ids)
	}
}

func TestHealth(t *testing.T) {
	f := newFake(t)
	a := adapterFor(t, f, nil)
	if err := a.Health(t.Context()); err != nil {
		t.Fatal(err)
	}
	// An identity that may not list secrets is still healthy.
	b := adapterFor(t, f, map[string]any{"project": "other-project-1"})
	if err := b.Health(t.Context()); err != nil {
		t.Errorf("Health with list refused: %v", err)
	}
	f.setDown(true)
	defer f.setDown(false)
	if err := a.Health(t.Context()); !errors.Is(err, stores.ErrUnavailable) {
		t.Errorf("Health during an outage: %v", err)
	}
}

func TestWatchReportsLabelChanges(t *testing.T) {
	f := newFake(t)
	a := adapterFor(t, f, map[string]any{"watch.interval": "30ms"})
	f.put("", "w--one", []byte("v"))
	ch, err := a.Watch(t.Context(), ref("w"))
	if err != nil {
		t.Fatal(err)
	}
	f.edit("", "w--one", func(s *fakeSecret) { s.annotations = map[string]string{"scrim.hosts": "api.example.test"} })
	select {
	case c := <-ch:
		if c.Ref.Path != "w/one" || c.Kind != stores.Changed {
			t.Errorf("change %v", c)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no change reported for an annotation update")
	}
}

// TestStaticTokenReadPerCall: a configured access token is copied out of its
// secret value for each call, not kept as one string by a static token
// source; once the value is wiped there is no token left to send.
func TestStaticTokenReadPerCall(t *testing.T) {
	v := secret.FromString(" ya29.static-token \n")
	ts := valueTokenSource{v}
	tok, err := ts.Token()
	if err != nil || tok.AccessToken != "ya29.static-token" || tok.TokenType != "Bearer" {
		t.Fatalf("token %v %v", tok, err)
	}
	v.Wipe()
	if tok, err := ts.Token(); err == nil || tok != nil {
		t.Fatalf("token after wipe: %v %v", tok, err)
	}
}
