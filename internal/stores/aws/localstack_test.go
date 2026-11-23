// SPDX-License-Identifier: AGPL-3.0-only

package aws

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores"
	"github.com/heliopsy/scrim/internal/stores/internal/podmantest"
	"github.com/heliopsy/scrim/internal/stores/storetest"
)

// defaultLocalStackImage is the emulator the integration tests run.
// LocalStack images after 4.14 refuse to start without a license token, so
// this stays on the last community release (renovate.json caps it).
// renovate: datasource=docker depName=docker.io/localstack/localstack
const defaultLocalStackImage = "docker.io/localstack/localstack:4.14.0"

// localstack is one emulator for a test.
type localstack struct {
	endpoint  string
	container *podmantest.Container
}

// startLocalStack starts LocalStack in rootless podman, or uses
// SCRIM_TEST_LOCALSTACK_ENDPOINT when set (no outage cases then, since the
// test does not own that emulator).
func startLocalStack(t *testing.T) *localstack {
	t.Helper()
	if e := os.Getenv("SCRIM_TEST_LOCALSTACK_ENDPOINT"); e != "" {
		return &localstack{endpoint: strings.TrimRight(e, "/")}
	}
	podmantest.Require(t)
	image := os.Getenv("SCRIM_TEST_LOCALSTACK_IMAGE")
	if image == "" {
		image = defaultLocalStackImage
	}
	start := time.Now()
	c := podmantest.Run(t, "localstack", image, 4566, map[string]string{
		"SERVICES":             "secretsmanager,ssm,sts,kms",
		"LOCALSTACK_TELEMETRY": "0",
		"DISABLE_EVENTS":       "1",
	})
	ls := &localstack{endpoint: fmt.Sprintf("http://127.0.0.1:%d", c.Port), container: c}
	podmantest.WaitHTTP(t, ls.endpoint+"/_localstack/health", 3*time.Minute, func(s int) bool { return s == 200 })
	t.Logf("LocalStack %s ready in %s", image, time.Since(start).Round(time.Second))
	return ls
}

func resolver(m map[string]string) func(context.Context, config.SecretRef) (secret.Value, error) {
	return func(_ context.Context, ref config.SecretRef) (secret.Value, error) {
		v, ok := m[string(ref)]
		if !ok {
			return secret.Value{}, errors.New("no such reference")
		}
		return secret.FromString(v), nil
	}
}

// adapter builds an adapter of kind against the emulator with static test
// keys given by reference.
func (ls *localstack) adapter(t testing.TB, kind, name string, extra map[string]any) stores.Adapter {
	t.Helper()
	opts := map[string]any{
		"endpoint":          ls.endpoint,
		"region":            "us-east-1",
		"access-key-id":     "test:id",
		"secret-access-key": "test:key",
		"timeout":           "3s",
		"max-attempts":      1,
		"watch.interval":    "300ms",
		"watch.max-backoff": "1s",
	}
	maps.Copy(opts, extra)
	for k, v := range opts {
		if v == nil {
			delete(opts, k)
		}
	}
	a, err := stores.DefaultRegistry.Open(t.Context(), stores.Instance{
		Name: name, Kind: kind, Options: opts,
		Resolve: resolver(map[string]string{"test:id": "test", "test:key": "test"}),
	})
	if err != nil {
		t.Fatalf("open %s: %v", kind, err)
	}
	t.Cleanup(func() { _ = a.Close() })
	return a
}

func randHex(t testing.TB, n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

// call sends one API call outside the adapter's own operations, for test
// setup (deletes, staging labels, parameter labels).
func call(t testing.TB, a stores.Adapter, op string, in map[string]any) map[string]any {
	t.Helper()
	var c *client
	switch x := a.(type) {
	case *SecretsManager:
		c = x.c
	case *ParameterStore:
		c = x.c
	}
	body, err := jsonBody(in, "", nil, false)
	if err != nil {
		t.Fatal(err)
	}
	b, err := c.call(t.Context(), op, body, false)
	if err != nil {
		t.Fatalf("%s: %v", op, err)
	}
	var out map[string]any
	_ = json.Unmarshal(b, &out)
	return out
}

func plain(t testing.TB, v secret.Value) string {
	t.Helper()
	var s string
	_ = v.Expose(func(b []byte) error { s = string(b); return nil })
	return s
}

func readField(t testing.TB, a stores.Adapter, ref stores.Ref, field string) (string, stores.Metadata) {
	t.Helper()
	s, err := a.Read(t.Context(), ref)
	if err != nil {
		t.Fatalf("Read %s: %v", ref, err)
	}
	defer s.Wipe()
	v, ok := s.Field(field)
	if !ok {
		t.Fatalf("Read %s: no field %s (have %v)", ref, field, s.Meta.Fields)
	}
	return plain(t, v), s.Meta
}

func outage(ls *localstack, t *testing.T) func(storetest.TB) func() {
	if ls.container == nil {
		return nil
	}
	return func(storetest.TB) func() {
		ls.container.Pause(t)
		return func() { ls.container.Unpause(t) }
	}
}

func TestLocalStack(t *testing.T) {
	ls := startLocalStack(t)

	t.Run("ConformanceSecretsManager", func(t *testing.T) {
		storetest.Run(t, func(tb storetest.TB) storetest.Harness {
			a := ls.adapter(t, KindSecretsManager, "awssm", nil)
			return storetest.Harness{
				Adapter:         a,
				VersionSelector: true,
				Labels:          true,
				WatchTimeout:    15 * time.Second,
				Outage:          outage(ls, t),
				Delete: func(tb storetest.TB, ref stores.Ref) {
					call(t, a, "DeleteSecret", map[string]any{"SecretId": ref.Path, "ForceDeleteWithoutRecovery": true})
				},
			}
		})
	})

	t.Run("ConformanceParameterStore", func(t *testing.T) {
		storetest.Run(t, func(tb storetest.TB) storetest.Harness {
			a := ls.adapter(t, KindParameterStore, "ssm", nil)
			return storetest.Harness{
				Adapter:         a,
				SingleField:     Field,
				VersionSelector: true,
				Labels:          true,
				WatchTimeout:    15 * time.Second,
				Outage:          outage(ls, t),
				Delete: func(tb storetest.TB, ref stores.Ref) {
					call(t, a, "DeleteParameter", map[string]any{"Name": "/" + ref.Path})
				},
			}
		})
	})

	t.Run("SecretsManagerStages", func(t *testing.T) { testStages(t, ls) })
	t.Run("SecretsManagerFormats", func(t *testing.T) { testFormats(t, ls) })
	t.Run("SecretsManagerLabels", func(t *testing.T) { testSMLabels(t, ls) })
	t.Run("ParameterStoreSelectors", func(t *testing.T) { testSSMSelectors(t, ls) })
	t.Run("ParameterStoreTypes", func(t *testing.T) { testSSMTypes(t, ls) })
	t.Run("ParameterStoreLabels", func(t *testing.T) { testSSMLabels(t, ls) })
	t.Run("DefaultChain", func(t *testing.T) { testDefaultChain(t, ls) })
	t.Run("AssumeRole", func(t *testing.T) { testAssumeRole(t, ls) })
}

// testStages: AWSCURRENT, AWSPREVIOUS and a custom staging label select
// the versions Secrets Manager says they label, and an unknown stage is
// not found rather than the current version.
func testStages(t *testing.T, ls *localstack) {
	a := ls.adapter(t, KindSecretsManager, "awssm", nil)
	ctx := t.Context()
	ref := stores.Ref{Scheme: "awssm", Path: "stages/" + randHex(t, 4)}
	v1, v2 := "one_"+randHex(t, 8), "two_"+randHex(t, 8)
	m1, err := a.Write(ctx, ref, map[string]secret.Value{"token": secret.FromString(v1)}, stores.WriteOptions{})
	if err != nil {
		t.Fatal(err)
	}
	m2, err := a.Write(ctx, ref, map[string]secret.Value{"token": secret.FromString(v2)}, stores.WriteOptions{})
	if err != nil {
		t.Fatal(err)
	}
	sel := func(s string) stores.Ref { r := ref.WithField("token"); r.Selectors = s; return r }
	if got, m := readField(t, a, sel(""), "token"); got != v2 || m.Version != m2.Version {
		t.Errorf("current: wrong value or version %q, want %q", m.Version, m2.Version)
	}
	got, m := readField(t, a, sel("stage=AWSPREVIOUS"), "token")
	if got != v1 || m.Version != m1.Version {
		t.Errorf("AWSPREVIOUS: wrong value or version %q, want %q", m.Version, m1.Version)
	}
	if m.Labels["awssm.stage.AWSPREVIOUS"] != "true" || m.Labels["awssm.stage.AWSCURRENT"] != "" {
		t.Errorf("AWSPREVIOUS labels: %v", m.Labels)
	}
	if got, _ := readField(t, a, sel("version="+m1.Version), "token"); got != v1 {
		t.Errorf("version selector returned another value")
	}
	call(t, a, "UpdateSecretVersionStage", map[string]any{"SecretId": ref.Path, "VersionStage": "canary", "MoveToVersionId": m1.Version})
	if got, m := readField(t, a, sel("stage=canary"), "token"); got != v1 || m.Labels["awssm.stage.canary"] != "true" {
		t.Errorf("custom stage: wrong value or labels %v", m.Labels)
	}
	if got, _ := readField(t, a, sel("stage=AWSCURRENT&version="+m2.Version), "token"); got != v2 {
		t.Errorf("stage and version together returned another value")
	}
	for _, s := range []string{"stage=nope", "stage=AWSPREVIOUS&version=" + m2.Version} {
		if _, err := a.Read(ctx, sel(s)); !errors.Is(err, stores.ErrNotFound) {
			t.Errorf("Read ?%s: %v, want not found", s, err)
		}
	}
}

// testFormats: a plain string, a JSON object with non-string members, a
// binary secret and a value that is itself JSON round-trip as fields.
func testFormats(t *testing.T, ls *localstack) {
	a := ls.adapter(t, KindSecretsManager, "awssm", nil)
	ctx := t.Context()
	base := "formats/" + randHex(t, 4)

	// Seeded out of band: a JSON object with a number and a nested object.
	tok := "tok_" + randHex(t, 8)
	call(t, a, "CreateSecret", map[string]any{"Name": base + "/json", "ClientRequestToken": newToken(),
		"SecretString": fmt.Sprintf(`{"token":%q,"port":5432,"nested":{"a":"b"},"none":null}`, tok)})
	s, err := a.Read(ctx, stores.Ref{Scheme: "awssm", Path: base + "/json"})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"nested", "port", "token"}; !reflect.DeepEqual(s.Meta.Fields, want) {
		t.Errorf("fields %v, want %v", s.Meta.Fields, want)
	}
	for f, want := range map[string]string{"token": tok, "port": "5432", "nested": `{"a":"b"}`} {
		if v, _ := s.Field(f); plain(t, v) != want {
			t.Errorf("field %s = %q, want %q", f, plain(t, v), want)
		}
	}
	s.Wipe()

	// Binary, seeded out of band and written through the adapter.
	bin := []byte{0, 1, 2, 0xff, 0xfe, 'x'}
	call(t, a, "CreateSecret", map[string]any{"Name": base + "/bin", "ClientRequestToken": newToken(), "SecretBinary": bin})
	if got, _ := readField(t, a, stores.Ref{Scheme: "awssm", Path: base + "/bin"}, Field); got != string(bin) {
		t.Errorf("binary secret did not round-trip")
	}
	ref := stores.Ref{Scheme: "awssm", Path: base + "/bin-written"}
	bin2 := append([]byte{0xc3, 0x28}, randHex(t, 4)...)
	if _, err := a.Write(ctx, ref, map[string]secret.Value{Field: secret.New(bin2)}, stores.WriteOptions{}); err != nil {
		t.Fatal(err)
	}
	if got, _ := readField(t, a, ref, Field); got != string(bin2) {
		t.Errorf("binary write did not round-trip")
	}

	// A single value that is a JSON object stays one value.
	ref = stores.Ref{Scheme: "awssm", Path: base + "/json-value"}
	j := `{"looks":"like fields","n":` + "1" + `}`
	if _, err := a.Write(ctx, ref, map[string]secret.Value{Field: secret.FromString(j)}, stores.WriteOptions{}); err != nil {
		t.Fatal(err)
	}
	if got, _ := readField(t, a, ref, Field); got != j {
		t.Errorf("a JSON value came back as %q", got)
	}

	// A plain value is stored as a plain SecretString, readable by any
	// AWS client as it is.
	ref = stores.Ref{Scheme: "awssm", Path: base + "/plain"}
	p := "plain_" + randHex(t, 8)
	if _, err := a.Write(ctx, ref, map[string]secret.Value{Field: secret.FromString(p)}, stores.WriteOptions{}); err != nil {
		t.Fatal(err)
	}
	out := call(t, a, "GetSecretValue", map[string]any{"SecretId": ref.Path})
	if out["SecretString"] != p {
		t.Errorf("plain value stored as something else")
	}

	// create-secrets off: a missing secret is not created.
	off := ls.adapter(t, KindSecretsManager, "awssm-nocreate", map[string]any{"create-secrets": false})
	_, err = off.Write(ctx, stores.Ref{Scheme: "awssm-nocreate", Path: base + "/never"}, map[string]secret.Value{Field: secret.FromString(p)}, stores.WriteOptions{})
	if !errors.Is(err, stores.ErrNotFound) || strings.Contains(err.Error(), p) {
		t.Errorf("write with create-secrets off: %v, want not found without the value", err)
	}
}

// testSMLabels: native labels, tags as meta, scrim.* tags decoded, the
// labels of ReadMetadata equal Read's, and a tag cannot forge a native
// label.
func testSMLabels(t *testing.T, ls *localstack) {
	a := ls.adapter(t, KindSecretsManager, "awssm", nil)
	ctx := t.Context()
	ref := stores.Ref{Scheme: "awssm", Path: "labels/" + randHex(t, 4)}
	call(t, a, "CreateSecret", map[string]any{"Name": ref.Path, "ClientRequestToken": newToken(), "SecretString": "v_" + randHex(t, 8),
		"Tags": []map[string]string{{"Key": "team", "Value": "payments"}, {"Key": "awssm.name", "Value": "forged"}}})
	if _, err := a.Write(ctx, ref, map[string]secret.Value{Field: secret.FromString("v_" + randHex(t, 8))},
		stores.WriteOptions{Labels: map[string]string{"scrim.hosts": "a.example.test,b.example.test", "awssm.region": "forged"}}); err != nil {
		t.Fatal(err)
	}
	s, err := a.Read(ctx, ref)
	if err != nil {
		t.Fatal(err)
	}
	s.Wipe()
	l := s.Meta.Labels
	want := map[string]string{
		"awssm.name":                ref.Path,
		"awssm.region":              "us-east-1",
		"awssm.account":             "000000000000",
		"awssm.stage":               "AWSCURRENT",
		"awssm.stage.AWSCURRENT":    "true",
		"awssm.meta.team":           "payments",
		"awssm.meta.awssm.name":     "forged",
		"scrim.hosts":               "a.example.test,b.example.test",
		"awssm.meta.scrim.hosts":    "a.example.test=2Cb.example.test",
		"awssm.meta.awssm.region":   "",
		"awssm.meta.awssm.rotation": "",
	}
	for k, v := range want {
		if l[k] != v {
			t.Errorf("label %s = %q, want %q", k, l[k], v)
		}
	}
	if !strings.HasPrefix(l["awssm.arn"], "arn:aws:secretsmanager:us-east-1:000000000000:secret:"+ref.Path) {
		t.Errorf("awssm.arn = %q", l["awssm.arn"])
	}
	m, err := a.(stores.MetadataReader).ReadMetadata(ctx, ref)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(m.Labels, l) || m.Version != s.Meta.Version {
		t.Errorf("ReadMetadata labels or version differ from Read's:\n%v\n%v", m.Labels, l)
	}
	if _, err := a.(stores.MetadataReader).ReadMetadata(ctx, stores.Ref{Scheme: "awssm", Path: "labels/missing-" + randHex(t, 4)}); !errors.Is(err, stores.ErrNotFound) {
		t.Errorf("ReadMetadata of a missing secret: %v", err)
	}
	wl := a.(stores.WriteLabeler).WriteLabels(stores.Ref{Scheme: "awssm", Path: "inbox/new"})
	if wl["awssm.name"] != "inbox/new" || wl["awssm.region"] != "us-east-1" {
		t.Errorf("write labels: %v", wl)
	}
}

// testSSMSelectors: ?version=, ?label=, the native :n and :label suffixes,
// and a label that does not exist.
func testSSMSelectors(t *testing.T, ls *localstack) {
	a := ls.adapter(t, KindParameterStore, "ssm", nil)
	ctx := t.Context()
	ref := stores.Ref{Scheme: "ssm", Path: "sel/" + randHex(t, 4) + "/db"}
	v1, v2 := "one_"+randHex(t, 8), "two_"+randHex(t, 8)
	m1, err := a.Write(ctx, ref, map[string]secret.Value{Field: secret.FromString(v1)}, stores.WriteOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Write(ctx, ref, map[string]secret.Value{Field: secret.FromString(v2)}, stores.WriteOptions{}); err != nil {
		t.Fatal(err)
	}
	call(t, a, "LabelParameterVersion", map[string]any{"Name": "/" + ref.Path, "ParameterVersion": 1, "Labels": []string{"stable"}})
	cases := map[string]string{"": v2, "?version=" + m1.Version: v1, "?label=stable": v1, ":1": v1, ":stable": v1, ":2": v2}
	for sel, want := range cases {
		r, err := stores.ParseRef("ssm://" + ref.Path + sel)
		if err != nil {
			t.Fatal(err)
		}
		if got, _ := readField(t, a, r, Field); got != want {
			t.Errorf("Read %s returned the other version", r)
		}
	}
	for _, sel := range []string{"?label=missing", ":missing", ":99"} {
		r, _ := stores.ParseRef("ssm://" + ref.Path + sel)
		if _, err := a.Read(ctx, r); !errors.Is(err, stores.ErrNotFound) {
			t.Errorf("Read %s: %v, want not found", r, err)
		}
	}
	for _, s := range []string{"ssm://" + ref.Path + "?stage=AWSCURRENT", "ssm://" + ref.Path + ":1?version=1", "ssm://" + ref.Path + "?label=1abc"} {
		if _, err := a.Read(ctx, stores.MustParseRef(s)); !errors.Is(err, stores.ErrInvalidRef) {
			t.Errorf("Read %s: %v, want invalid reference", s, err)
		}
	}
}

// testSSMTypes: String and StringList parameters read as their text, a
// SecureString is decrypted, and parameter-type String writes plain
// parameters.
func testSSMTypes(t *testing.T, ls *localstack) {
	a := ls.adapter(t, KindParameterStore, "ssm", nil)
	ctx := t.Context()
	base := "types/" + randHex(t, 4)
	for typ, val := range map[string]string{"String": "s_" + randHex(t, 6), "StringList": "a,b," + randHex(t, 6), "SecureString": "sec_" + randHex(t, 6)} {
		name := base + "/" + strings.ToLower(typ)
		call(t, a, "PutParameter", map[string]any{"Name": "/" + name, "Type": typ, "Value": val})
		got, m := readField(t, a, stores.Ref{Scheme: "ssm", Path: name}, Field)
		if got != val {
			t.Errorf("%s did not read back as written", typ)
		}
		if m.Labels["ssm.type"] != typ || m.Labels["ssm.name"] != "/"+name || m.Labels["ssm.path"] != "/"+base {
			t.Errorf("%s labels: %v", typ, m.Labels)
		}
	}
	plainType := ls.adapter(t, KindParameterStore, "ssm-plain", map[string]any{"parameter-type": "String", "tier": "Standard"})
	ref := stores.Ref{Scheme: "ssm-plain", Path: base + "/written"}
	if _, err := plainType.Write(ctx, ref, map[string]secret.Value{Field: secret.FromString("w_" + randHex(t, 6))}, stores.WriteOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, m := readField(t, plainType, ref, Field); m.Labels["ssm.type"] != "String" {
		t.Errorf("parameter-type String wrote %q", m.Labels["ssm.type"])
	}
	// An update keeps the parameter's type.
	if _, err := a.Write(ctx, stores.Ref{Scheme: "ssm", Path: ref.Path}, map[string]secret.Value{Field: secret.FromString("w2_" + randHex(t, 6))}, stores.WriteOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, m := readField(t, a, stores.Ref{Scheme: "ssm", Path: ref.Path}, Field); m.Labels["ssm.type"] != "String" {
		t.Errorf("an update changed the type to %q", m.Labels["ssm.type"])
	}
	_, err := a.Write(ctx, stores.Ref{Scheme: "ssm", Path: base + "/two"}, map[string]secret.Value{"a": secret.FromString("x"), "b": secret.FromString("y")}, stores.WriteOptions{})
	if !errors.Is(err, stores.ErrUnsupported) {
		t.Errorf("multi-field write: %v, want unsupported", err)
	}
}

// testSSMLabels: native labels, tags, ReadMetadata equal to Read's, write
// labels.
func testSSMLabels(t *testing.T, ls *localstack) {
	a := ls.adapter(t, KindParameterStore, "ssm", nil)
	ctx := t.Context()
	ref := stores.Ref{Scheme: "ssm", Path: "labels/" + randHex(t, 4) + "/key"}
	if _, err := a.Write(ctx, ref, map[string]secret.Value{Field: secret.FromString("v_" + randHex(t, 8))},
		stores.WriteOptions{Labels: map[string]string{"scrim.hosts": "a.example.test,b.example.test", "team": "core", "ssm.type": "forged"}}); err != nil {
		t.Fatal(err)
	}
	s, err := a.Read(ctx, ref)
	if err != nil {
		t.Fatal(err)
	}
	s.Wipe()
	l := s.Meta.Labels
	for k, v := range map[string]string{
		"ssm.type": "SecureString", "ssm.tier": "Standard", "ssm.region": "us-east-1",
		"ssm.meta.team": "core", "scrim.hosts": "a.example.test,b.example.test", "ssm.meta.ssm.type": "",
	} {
		if l[k] != v {
			t.Errorf("label %s = %q, want %q", k, l[k], v)
		}
	}
	// LocalStack leaves ARN out of DescribeParameters; AWS sends it.
	if l["ssm.arn"] != "" && l["ssm.account"] != "000000000000" {
		t.Errorf("ssm.account = %q for ARN %q", l["ssm.account"], l["ssm.arn"])
	}
	m, err := a.(stores.MetadataReader).ReadMetadata(ctx, ref)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(m.Labels, l) || m.Version != s.Meta.Version {
		t.Errorf("ReadMetadata labels or version differ from Read's:\n%v\n%v", m.Labels, l)
	}
	if _, err := a.(stores.MetadataReader).ReadMetadata(ctx, stores.Ref{Scheme: "ssm", Path: "labels/missing-" + randHex(t, 4)}); !errors.Is(err, stores.ErrNotFound) {
		t.Errorf("ReadMetadata of a missing parameter: %v", err)
	}
	wl := a.(stores.WriteLabeler).WriteLabels(stores.Ref{Scheme: "ssm", Path: "inbox/new"})
	if wl["ssm.name"] != "/inbox/new" || wl["ssm.path"] != "/inbox" || wl["ssm.type"] != "SecureString" {
		t.Errorf("write labels: %v", wl)
	}
}

// testDefaultChain: with no keys in configuration the adapter finds
// credentials through the SDK's default chain (here the environment), and
// never reads the user's own AWS files.
func testDefaultChain(t *testing.T, ls *localstack) {
	dir := t.TempDir()
	t.Setenv("AWS_CONFIG_FILE", dir+"/config")
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", dir+"/credentials")
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	t.Setenv("AWS_ACCESS_KEY_ID", "test")
	key := "envkey" + randHex(t, 8)
	t.Setenv("AWS_SECRET_ACCESS_KEY", key)
	t.Setenv("AWS_SESSION_TOKEN", "")
	t.Setenv("AWS_REGION", "us-east-1")
	a := ls.adapter(t, KindSecretsManager, "awssm-env", map[string]any{"access-key-id": nil, "secret-access-key": nil, "region": nil})
	if err := a.Health(t.Context()); err != nil {
		t.Fatalf("Health with environment credentials: %v", err)
	}
	found := false
	for _, v := range a.(stores.CredentialHolder).Credentials() {
		found = found || plain(t, v) == key
		v.Wipe()
	}
	if !found {
		t.Errorf("the secret key from the environment is not handed to the redaction set")
	}

	// No credentials anywhere: a permission error that names no key.
	t.Setenv("AWS_ACCESS_KEY_ID", "")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "")
	t.Setenv("AWS_WEB_IDENTITY_TOKEN_FILE", "")
	t.Setenv("AWS_CONTAINER_CREDENTIALS_FULL_URI", "")
	t.Setenv("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "")
	none := ls.adapter(t, KindSecretsManager, "awssm-none", map[string]any{"access-key-id": nil, "secret-access-key": nil})
	err := none.Health(t.Context())
	if !errors.Is(err, stores.ErrPermission) {
		t.Errorf("Health without credentials: %v, want permission denied", err)
	}
}

// testAssumeRole: the adapter assumes the configured role through STS and
// signs with the session credentials, which go to the redaction set.
func testAssumeRole(t *testing.T, ls *localstack) {
	a := ls.adapter(t, KindParameterStore, "ssm-role", map[string]any{
		"assume-role.arn":          "arn:aws:iam::000000000000:role/scrim-test",
		"assume-role.session-name": "scrim-test",
		"assume-role.external-id":  "ext-" + randHex(t, 4),
		"assume-role.sts-endpoint": ls.endpoint,
	})
	ref := stores.Ref{Scheme: "ssm-role", Path: "role/" + randHex(t, 4)}
	val := "r_" + randHex(t, 8)
	if _, err := a.Write(t.Context(), ref, map[string]secret.Value{Field: secret.FromString(val)}, stores.WriteOptions{}); err != nil {
		t.Fatalf("Write with an assumed role: %v", err)
	}
	if got, _ := readField(t, a, ref, Field); got != val {
		t.Errorf("Read with an assumed role returned another value")
	}
	creds := a.(stores.CredentialHolder).Credentials()
	// The static keys (two) plus the session's secret key and token.
	if len(creds) < 4 {
		t.Errorf("Credentials returned %d values, want the session key and token too", len(creds))
	}
	for _, v := range creds {
		v.Wipe()
	}
}
