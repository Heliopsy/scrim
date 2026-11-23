// SPDX-License-Identifier: AGPL-3.0-only

package azkv

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"maps"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/heliopsy/scrim/internal/policy"
	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores"
)

func ref(p string) stores.Ref { return stores.Ref{Scheme: "kv", Path: p} }

func plain(t *testing.T, v secret.Value) string {
	t.Helper()
	var s string
	_ = v.Expose(func(b []byte) error { s = string(b); return nil })
	return s
}

func strp(s string) *string { return &s }

func TestReadMetadataEqualsReadWithoutValue(t *testing.T) {
	f := newFake(t)
	a := f.adapter(t, "kv", nil)
	val := "v-" + randHex(8)
	f.seed("apps--pay--db", val, map[string]string{"team": "pay", "scrim.hosts": "db.example.test"}, strp("text/plain"))

	s, err := a.Read(t.Context(), ref("apps/pay/db"))
	if err != nil {
		t.Fatal(err)
	}
	s.Wipe()
	f.mu.Lock()
	served, reqs := f.valuesServed, len(f.requests)
	f.mu.Unlock()

	m, err := a.ReadMetadata(t.Context(), ref("apps/pay/db"))
	if err != nil {
		t.Fatal(err)
	}
	if !maps.Equal(m.Labels, s.Meta.Labels) {
		t.Errorf("metadata labels differ from Read's:\n got %v\nwant %v", m.Labels, s.Meta.Labels)
	}
	if m.Version == "" || m.Version != s.Meta.Version {
		t.Errorf("metadata version %q, Read version %q", m.Version, s.Meta.Version)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.valuesServed != served {
		t.Errorf("ReadMetadata made the vault serve a value")
	}
	for _, r := range f.requests[reqs:] {
		if !strings.HasSuffix(r, "/versions") {
			t.Errorf("ReadMetadata sent %s; only the versions listing returns no value", r)
		}
	}
	if fmt.Sprint(m) != "" && strings.Contains(fmt.Sprintf("%+v", m), val) {
		t.Errorf("metadata holds the value")
	}
}

func TestReadMetadataMissingAndDisabled(t *testing.T) {
	f := newFake(t)
	a := f.adapter(t, "kv", nil)
	if _, err := a.ReadMetadata(t.Context(), ref("nope")); !errors.Is(err, stores.ErrNotFound) {
		t.Errorf("missing secret: %v, want not found", err)
	}
	v := f.seed("off", "x"+randHex(4), nil, nil)
	f.mu.Lock()
	v.enabled = false
	f.mu.Unlock()
	if _, err := a.Read(t.Context(), ref("off")); !errors.Is(err, stores.ErrNotFound) {
		t.Errorf("Read of a disabled secret: %v, want not found", err)
	}
	if _, err := a.ReadMetadata(t.Context(), ref("off")); !errors.Is(err, stores.ErrNotFound) {
		t.Errorf("ReadMetadata of a disabled secret: %v, want not found", err)
	}
}

func TestReadMetadataSameSecondLeavesVersionOut(t *testing.T) {
	f := newFake(t)
	a := f.adapter(t, "kv", nil)
	v1 := f.seed("twice", "a"+randHex(4), nil, nil)
	v2 := f.seed("twice", "b"+randHex(4), nil, nil)
	f.mu.Lock()
	v2.created, v2.updated = v1.created, v1.updated
	f.mu.Unlock()
	m, err := a.ReadMetadata(t.Context(), ref("twice"))
	if err != nil {
		t.Fatal(err)
	}
	if m.Version != "" || m.Labels["azkv.version"] != "" {
		t.Errorf("ambiguous current version reported as %q / %q", m.Version, m.Labels["azkv.version"])
	}
	pinned := ref("twice")
	pinned.Selectors = "version=" + v1.id
	if m, err := a.ReadMetadata(t.Context(), pinned); err != nil || m.Version != v1.id {
		t.Errorf("pinned ReadMetadata: %v, version %q", err, m.Version)
	}
}

func TestNativeLabelsAndForgery(t *testing.T) {
	f := newFake(t)
	a := f.adapter(t, "kv", nil)
	val := "v-" + randHex(8)
	f.seed("agents--github", val, map[string]string{
		"azkv.enabled": "false", "AZKV.Name": "other", "azkv.meta.team": "forged", "team": "pay",
	}, strp("text/plain"))
	s, err := a.Read(t.Context(), ref("agents/github"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Wipe()
	l := s.Meta.Labels
	want := map[string]string{
		"azkv.vault":               "127",
		"azkv.vault-host":          "127.0.0.1",
		"azkv.name":                "agents--github",
		"azkv.version":             s.Meta.Version,
		"azkv.enabled":             "true",
		"azkv.content-type":        "text/plain",
		"azkv.managed":             "false",
		"azkv.recovery-level":      "Recoverable+Purgeable",
		"azkv.recoverable-days":    "90",
		"team":                     "pay",
		"azkv.meta.team":           "pay",
		"azkv.meta.azkv.enabled":   "false",
		"azkv.meta.azkv.name":      "other",
		"azkv.meta.azkv.meta.team": "forged",
	}
	for k, v := range want {
		if l[k] != v {
			t.Errorf("label %s = %q, want %q", k, l[k], v)
		}
	}
	for _, k := range []string{"azkv.enabled", "AZKV.Name"} {
		if _, ok := l[strings.ToLower(k)]; ok && l[strings.ToLower(k)] != want[strings.ToLower(k)] {
			t.Errorf("tag %s forged a native label", k)
		}
	}
	if _, ok := l["AZKV.Name"]; ok {
		t.Errorf("a reserved tag was copied as is")
	}
	if l["azkv.created"] == "" || l["azkv.updated"] == "" {
		t.Errorf("times missing: %v", l)
	}
	for k, v := range l {
		if strings.Contains(k, val) || strings.Contains(v, val) {
			t.Errorf("label %s holds the value", k)
		}
	}
}

func TestWriteLabelsFromReference(t *testing.T) {
	f := newFake(t)
	a := f.adapter(t, "kv", map[string]any{"format": formatJSON})
	l := a.WriteLabels(ref("agents/new"))
	if l["azkv.name"] != "agents--new" || l["azkv.vault-host"] != "127.0.0.1" || l["azkv.content-type"] != jsonContentType {
		t.Errorf("write labels: %v", l)
	}
	if a.WriteLabels(ref("bad_name")) != nil {
		t.Errorf("a reference that maps to no name got labels")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.requests) != 0 {
		t.Errorf("WriteLabels contacted the vault: %v", f.requests)
	}
}

func TestWriteKeepsTagsAndContentType(t *testing.T) {
	f := newFake(t)
	a := f.adapter(t, "kv", nil)
	f.seed("kept", "a"+randHex(4), map[string]string{"scrim.hosts": "api.example.test"}, strp("text/plain"))
	write := func(labels map[string]string) {
		t.Helper()
		if _, err := a.Write(t.Context(), ref("kept"), map[string]secret.Value{Field: secret.FromString("n" + randHex(4))}, stores.WriteOptions{Labels: labels}); err != nil {
			t.Fatal(err)
		}
	}
	last := func() *fakeVersion {
		f.mu.Lock()
		defer f.mu.Unlock()
		vs := f.secrets["kept"]
		return vs[len(vs)-1]
	}
	write(nil)
	if v := last(); v.tags["scrim.hosts"] != "api.example.test" || v.contentType == nil || *v.contentType != "text/plain" {
		t.Errorf("a write without labels dropped the tags or content type: %v %v", v.tags, v.contentType)
	}
	write(map[string]string{"azkv.enabled": "false"})
	if v := last(); v.tags["scrim.hosts"] != "api.example.test" || v.tags["azkv.enabled"] != "" {
		t.Errorf("a write of only derived labels changed the tags: %v", v.tags)
	}
	write(map[string]string{"team": "x", "azkv.name": "y"})
	if v := last(); len(v.tags) != 1 || v.tags["team"] != "x" {
		t.Errorf("tags after a labelled write: %v", v.tags)
	}
}

func TestWriteSoftDeletedNameConflicts(t *testing.T) {
	f := newFake(t)
	a := f.adapter(t, "kv", nil)
	f.seed("gone", "a"+randHex(4), nil, nil)
	f.remove("gone")
	_, err := a.Write(t.Context(), ref("gone"), map[string]secret.Value{Field: secret.FromString("b" + randHex(4))}, stores.WriteOptions{})
	if !errors.Is(err, stores.ErrConflict) || !strings.Contains(err.Error(), "soft-deleted") {
		t.Errorf("write to a soft-deleted name: %v, want a conflict naming soft delete", err)
	}
}

func TestEchoedValueWithheld(t *testing.T) {
	f := newFake(t)
	a := f.adapter(t, "kv", nil)
	f.mu.Lock()
	f.denyWrite, f.echoValue = "deny", true
	f.mu.Unlock()
	val := "secret-" + randHex(8)
	_, err := a.Write(t.Context(), ref("deny/x"), map[string]secret.Value{Field: secret.FromString(val)}, stores.WriteOptions{})
	if !errors.Is(err, stores.ErrPermission) {
		t.Fatalf("got %v, want permission denied", err)
	}
	if strings.Contains(fmt.Sprintf("%v %+v", err, err), val) {
		t.Errorf("error repeats the value the vault echoed")
	}
}

func TestPathMapping(t *testing.T) {
	f := newFake(t)
	a := f.adapter(t, "kv", nil)
	for _, p := range []string{"a--b/c", "a-/b", "under_score", "a/-b"} {
		_, err := a.Write(t.Context(), ref(p), map[string]secret.Value{Field: secret.FromString("x" + randHex(4))}, stores.WriteOptions{})
		if !errors.Is(err, stores.ErrInvalidRef) {
			t.Errorf("Write %s: %v, want invalid reference", p, err)
		}
	}
	f.seed("odd---name", "x"+randHex(4), nil, nil)
	f.seed("plain-name", "x"+randHex(4), nil, nil)
	ms, err := a.List(t.Context(), ref("*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(ms) != 1 || ms[0].Ref.Path != "plain-name" {
		t.Errorf("listing: %v; a name that maps to no path must be skipped", ms)
	}
}

func TestListPagesAndGlob(t *testing.T) {
	f := newFake(t)
	f.pageSize = 2
	a := f.adapter(t, "kv", nil)
	for i := range 5 {
		f.seed(fmt.Sprintf("APP-%d", i), "x"+randHex(4), nil, nil)
	}
	f.seed("OTHER", "x"+randHex(4), nil, nil)
	ms, err := a.List(t.Context(), ref("APP-*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(ms) != 5 {
		t.Errorf("glob listing over pages returned %d entries, want 5", len(ms))
	}
}

func TestJSONFormatRefusesNonObject(t *testing.T) {
	f := newFake(t)
	a := f.adapter(t, "kv", map[string]any{"format": formatJSON})
	val := "not json " + randHex(6)
	f.seed("text", val, nil, nil)
	_, err := a.Read(t.Context(), ref("text"))
	if !errors.Is(err, stores.ErrUnsupported) {
		t.Fatalf("got %v, want unsupported", err)
	}
	if strings.Contains(fmt.Sprintf("%v %+v", err, err), val) {
		t.Errorf("error holds the value")
	}
}

func TestWatchSameSecondRotation(t *testing.T) {
	f := newFake(t)
	a := f.adapter(t, "kv", nil)
	// The first version was updated in a second that is still current on
	// the vault's clock (a little ahead, so the test has time), and the
	// rotation lands in the same second: the listing looks the same.
	v := f.seed("rot", "a"+randHex(4), nil, nil)
	f.mu.Lock()
	same := time.Now().Unix() + 5
	v.created, v.updated = same, same
	f.mu.Unlock()
	ch, err := a.Watch(t.Context(), ref("rot"))
	if err != nil {
		t.Fatal(err)
	}
	nv := f.seed("rot", "b"+randHex(4), nil, nil)
	f.mu.Lock()
	nv.created, nv.updated = same, same
	f.mu.Unlock()
	select {
	case c := <-ch:
		if c.Ref.Path != "rot" || c.Kind != stores.Changed {
			t.Errorf("change %v", c)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("no change reported for a rotation within the same second")
	}
}

func TestCredentialsHeld(t *testing.T) {
	f := newFake(t)
	a := f.adapter(t, "kv", nil)
	if err := a.Health(t.Context()); err != nil {
		t.Fatal(err)
	}
	creds := a.Credentials()
	got := map[string]bool{}
	for _, c := range creds {
		got[plain(t, c)] = true
		c.Wipe()
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if !got[f.clientSecret] || !got[f.issued[len(f.issued)-1]] {
		t.Errorf("Credentials holds %d values; want the client secret and the access token", len(creds))
	}
}

func TestOptions(t *testing.T) {
	f := newFake(t)
	cases := map[string]map[string]any{
		"missing vault-url":       {"vault-url": nil},
		"http vault-url":          {"vault-url": "http://vault.example.test"},
		"vault-url with path":     {"vault-url": "https://v.vault.azure.net/secrets"},
		"unused secret":           {"auth": map[string]any{"method": "default"}},
		"missing secret":          {"client-secret": nil},
		"bad separator":           {"path-separator": "__"},
		"bad format":              {"format": "yaml"},
		"unknown option":          {"vault-ulr": "x"},
		"bad cloud":               {"cloud": "moon"},
		"unknown method":          {"auth": map[string]any{"method": "password"}},
		"token with access-token": {"auth": map[string]any{"method": "access-token"}},
	}
	for name, extra := range cases {
		opts := f.baseOptions()
		for k, v := range extra {
			if v == nil {
				delete(opts, k)
			} else {
				opts[k] = v
			}
		}
		if _, err := New(t.Context(), stores.Instance{Name: "kv", Kind: Kind, Options: opts, Resolve: literal}); err == nil {
			t.Errorf("%s: accepted", name)
		} else if strings.Contains(err.Error(), f.clientSecret) {
			t.Errorf("%s: error holds the client secret", name)
		}
	}
	a := f.adapter(t, "kv", map[string]any{"read-only": true})
	if a.Capabilities().Has(stores.CapWrite) {
		t.Errorf("read-only store declares write")
	}
}

func TestChallengeForOtherResourceRefused(t *testing.T) {
	f := newFake(t)
	f.challengeHeader = `Bearer authorization="https://login.microsoftonline.com/` + f.tenant + `", resource="https://attacker.example"`
	a := f.adapter(t, "kv", nil)
	err := a.Health(t.Context())
	if !errors.Is(err, stores.ErrPermission) || !strings.Contains(err.Error(), "attacker.example") {
		t.Fatalf("got %v, want a refusal naming the resource", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.tokenReqs != 0 {
		t.Errorf("a token was requested for a resource the vault is not part of")
	}
}

func TestChallengeScopeAndTenant(t *testing.T) {
	f := newFake(t)
	f.challengeHeader = `Bearer authorization_uri="https://login.microsoftonline.com/` + f.tenant + `/oauth2/authorize", scope="https://127.0.0.1/.default"`
	a := f.adapter(t, "kv", nil)
	if err := a.Health(t.Context()); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.scopes) == 0 || !strings.Contains(f.scopes[0], "https://127.0.0.1/.default") {
		t.Errorf("token scopes %v", f.scopes)
	}
}

func TestVerifyResource(t *testing.T) {
	for _, c := range []struct {
		host, scope string
		ok          bool
	}{
		{"myvault.vault.azure.net", "https://vault.azure.net/.default", true},
		{"myvault.vault.azure.cn", "https://vault.azure.cn/.default", true},
		{"myvault.vault.azure.net", "https://vault.azure.net", true},
		{"myvault.vault.azure.net", "https://evil.net/.default", false},
		{"myvault.vault.azure.net", "https://ault.azure.net/.default", false},
		{"vault.azure.net.evil.com", "https://vault.azure.net/.default", false},
		{"127.0.0.1", "https://127.0.0.1/.default", true},
		{"10.0.0.1", "https://0.0.1/.default", false},
		{"myvault.vault.azure.net", "not a url", false},
	} {
		err := verifyResource(c.host, c.scope)
		if (err == nil) != c.ok {
			t.Errorf("verifyResource(%s, %s) = %v, want ok=%v", c.host, c.scope, err, c.ok)
		}
	}
}

func TestParseBearer(t *testing.T) {
	p, ok := parseBearer(`Bearer authorization="https://login.microsoftonline.com/t1", resource="https://vault.azure.net", error="insufficient_claims", claims="e30="`)
	if !ok || p["authorization"] != "https://login.microsoftonline.com/t1" || p["resource"] != "https://vault.azure.net" || p["claims"] != "e30=" {
		t.Errorf("parsed %v", p)
	}
	if _, ok := parseBearer(`PoP nonce="x"`); ok {
		t.Errorf("a non-Bearer challenge parsed")
	}
}

func TestAuthWorkloadIdentity(t *testing.T) {
	f := newFake(t)
	assertion := "eyJhbGciOiJSUzI1NiJ9." + randHex(16) + ".sig"
	f.assertions[assertion] = true
	file := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(file, []byte(assertion), 0o600); err != nil {
		t.Fatal(err)
	}
	a := f.adapter(t, "kv", map[string]any{
		"auth":          map[string]any{"method": "workload-identity", "token-file": file},
		"client-secret": nil,
	})
	if err := a.Health(t.Context()); err != nil {
		t.Fatalf("Health with workload identity: %v", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.seenAssert) == 0 || f.seenAssert[0] != assertion {
		t.Errorf("Entra saw assertions %v, want the token file's content", f.seenAssert)
	}
}

func TestAuthWorkloadIdentityRefused(t *testing.T) {
	f := newFake(t)
	file := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(file, []byte("unknown-assertion"), 0o600); err != nil {
		t.Fatal(err)
	}
	a := f.adapter(t, "kv", map[string]any{
		"auth":          map[string]any{"method": "workload-identity", "token-file": file},
		"client-secret": nil,
	})
	if err := a.Health(t.Context()); !errors.Is(err, stores.ErrPermission) {
		t.Errorf("Health with a refused assertion: %v, want permission denied", err)
	}
}

func TestAuthClientSecretWrong(t *testing.T) {
	f := newFake(t)
	wrong := "wrong-" + randHex(8)
	a := f.adapter(t, "kv", map[string]any{"client-secret": wrong})
	err := a.Health(t.Context())
	if !errors.Is(err, stores.ErrPermission) {
		t.Errorf("Health with a wrong client secret: %v, want permission denied", err)
	}
	if err != nil && strings.Contains(fmt.Sprintf("%v %+v", err, err), wrong) {
		t.Errorf("error holds the client secret")
	}
}

func TestAuthManagedIdentityAppService(t *testing.T) {
	f := newFake(t)
	t.Setenv("IDENTITY_ENDPOINT", f.srv.URL+"/msi/token")
	t.Setenv("IDENTITY_HEADER", f.miHeader)
	a := f.adapter(t, "kv", map[string]any{
		"auth": map[string]any{"method": "managed-identity"}, "tenant-id": nil, "client-id": nil, "client-secret": nil,
	})
	if err := a.Health(t.Context()); err != nil {
		t.Fatalf("Health with managed identity: %v", err)
	}
}

func TestAuthAccessToken(t *testing.T) {
	f := newFake(t)
	f.mu.Lock()
	tok := f.issue()
	f.mu.Unlock()
	a := f.adapter(t, "kv", map[string]any{
		"auth": map[string]any{"method": "access-token"}, "token": tok,
		"tenant-id": nil, "client-id": nil, "client-secret": nil,
	})
	if err := a.Health(t.Context()); err != nil {
		t.Fatalf("Health with an access token: %v", err)
	}
	b := f.adapter(t, "kv2", map[string]any{
		"auth": map[string]any{"method": "access-token"}, "token": "expired-" + randHex(4),
		"tenant-id": nil, "client-id": nil, "client-secret": nil,
	})
	if err := b.Health(t.Context()); !errors.Is(err, stores.ErrPermission) {
		t.Errorf("Health with a refused access token: %v, want permission denied", err)
	}
}

func TestAuthClientCertificate(t *testing.T) {
	f := newFake(t)
	f.certAssertions = true
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "scrim-test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	pemData := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})) +
		string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
	a := f.adapter(t, "kv", map[string]any{
		"auth": map[string]any{"method": "client-certificate"}, "certificate": pemData, "client-secret": nil,
	})
	if err := a.Health(t.Context()); err != nil {
		t.Fatalf("Health with a client certificate: %v", err)
	}
	bad := f.adapter(t, "kv2", map[string]any{
		"auth": map[string]any{"method": "client-certificate"}, "certificate": "not a certificate", "client-secret": nil,
	})
	if err := bad.Health(t.Context()); !errors.Is(err, stores.ErrPermission) || strings.Contains(err.Error(), "not a certificate") {
		t.Errorf("Health with an unusable certificate: %v", err)
	}
}

func TestLabelsDocsPolicyExamples(t *testing.T) {
	data, err := os.ReadFile("../../../docs/stores/azure.md")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile("(?s)<!-- policy-example -->\n```yaml\n(.*?)```").FindSubmatch(data)
	if m == nil {
		t.Fatal("docs/stores/azure.md has no policy example block")
	}
	for _, b := range regexp.MustCompile("(?s)```cel\n(.*?)```").FindAllSubmatch(data, -1) {
		for _, line := range strings.Split(string(b[1]), "\n") {
			expr, _, _ := strings.Cut(line, "  //")
			if expr = strings.TrimSpace(expr); expr == "" {
				continue
			}
			if _, err := policy.Compile(policy.Config{Rules: []policy.RuleSpec{{Name: "doc", Decision: "ask", When: expr}}}); err != nil {
				t.Errorf("%s: %v", expr, err)
			}
		}
	}
	cfg, err := policy.Parse(m[1], false)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	rs, err := policy.Compile(cfg)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	f := newFake(t)
	a := f.adapter(t, "kv", nil)
	f.seed("pay--db", "v"+randHex(4), map[string]string{"team": "payments"}, nil)
	f.seed("plain", "v"+randHex(4), nil, nil)
	f.seed("forged", "v"+randHex(4), map[string]string{"azkv.meta.team": "billing", "azkv.managed": "true"}, nil)
	cert := f.seed("cert", "v"+randHex(4), nil, nil)
	f.mu.Lock()
	cert.managed = true
	f.mu.Unlock()
	for path, want := range map[string]policy.Effect{"pay/db": policy.Ask, "plain": policy.Allow, "forged": policy.Allow, "cert": policy.Deny} {
		md, err := a.ReadMetadata(t.Context(), ref(path))
		if err != nil {
			t.Fatal(err)
		}
		r := ref(path)
		res := rs.Evaluate(policy.Request{
			Agent: policy.Agent{ID: "codex", Kind: "session"}, Action: policy.ActionRead,
			Ref: r, Store: "kv", SecretLabels: stores.ComposeLabels("kv", Kind, r, md.Labels, nil),
		})
		if res.Effect != want {
			t.Errorf("read %s = %s, want %s", path, res.Effect, want)
		}
	}
}
