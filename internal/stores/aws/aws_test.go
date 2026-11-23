// SPDX-License-Identifier: AGPL-3.0-only

package aws

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores"
)

// fake answers every call with status and body, and counts calls.
func fake(t *testing.T, status int, body func(target string, req []byte) string) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		b, _ := io.ReadAll(r.Body)
		if !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 Credential=test/") {
			t.Errorf("request not signed with the configured key: %q", r.Header.Get("Authorization"))
		}
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body(r.Header.Get("X-Amz-Target"), b))
	}))
	t.Cleanup(srv.Close)
	return srv, &n
}

func open(t *testing.T, kind, endpoint string, extra map[string]any) stores.Adapter {
	t.Helper()
	ls := &localstack{endpoint: endpoint}
	return ls.adapter(t, kind, kind, extra)
}

// TestValidationMessageNeverKept: AWS validation messages quote request
// fields; a write's error keeps the code only, so the value never reaches
// an error, whatever AWS echoes.
func TestValidationMessageNeverKept(t *testing.T) {
	for _, kind := range []string{KindSecretsManager, KindParameterStore} {
		t.Run(kind, func(t *testing.T) {
			srv, _ := fake(t, 400, func(target string, req []byte) string {
				if strings.HasSuffix(target, ".DescribeParameters") || strings.HasSuffix(target, ".DescribeSecret") {
					return `{}`
				}
				// Echo the whole request, as a validation message may.
				return fmt.Sprintf(`{"__type":"ValidationException","message":%q}`, "1 validation error detected: Value '"+string(req)+"' failed")
			})
			a := open(t, kind, srv.URL, nil)
			val := "leak_" + randHex(t, 12)
			_, err := a.Write(t.Context(), stores.Ref{Scheme: kind, Path: "app/key"}, map[string]secret.Value{Field: secret.FromString(val)}, stores.WriteOptions{})
			if !errors.Is(err, stores.ErrUnsupported) {
				t.Fatalf("Write: %v, want unsupported", err)
			}
			if text := chain(err); strings.Contains(text, val) {
				t.Fatalf("error carries the value: %s", text)
			}
			if !strings.Contains(err.Error(), "ValidationException") {
				t.Errorf("error %q does not name the AWS error code", err)
			}
		})
	}
}

func chain(err error) string {
	var b strings.Builder
	var walk func(error)
	walk = func(e error) {
		if e == nil {
			return
		}
		fmt.Fprintf(&b, "%v|%+v|%#v\n", e, e, e)
		switch u := e.(type) {
		case interface{ Unwrap() []error }:
			for _, x := range u.Unwrap() {
				walk(x)
			}
		case interface{ Unwrap() error }:
			walk(u.Unwrap())
		}
	}
	walk(err)
	return b.String()
}

// TestReadErrorKeepsMessage: a read carries no value, so AWS's message
// stays in the error for the operator (who is denied what).
func TestReadErrorKeepsMessage(t *testing.T) {
	srv, _ := fake(t, 400, func(string, []byte) string {
		return `{"__type":"com.amazonaws.secretsmanager#AccessDeniedException","message":"User arn:aws:iam::1:user/x is not authorized"}`
	})
	a := open(t, KindSecretsManager, srv.URL, nil)
	_, err := a.Read(t.Context(), stores.Ref{Scheme: KindSecretsManager, Path: "app/key"})
	if !errors.Is(err, stores.ErrPermission) || !strings.Contains(err.Error(), "not authorized") || !strings.Contains(err.Error(), "app/key") {
		t.Fatalf("Read: %v", err)
	}
	if err := a.Health(t.Context()); err != nil {
		t.Errorf("Health with valid credentials but no ListSecrets permission: %v", err)
	}
}

// TestRetries: throttling and 5xx are retried up to max-attempts, other
// errors are not.
func TestRetries(t *testing.T) {
	srv, n := fake(t, 400, func(string, []byte) string { return `{"__type":"ThrottlingException","message":"slow down"}` })
	a := open(t, KindParameterStore, srv.URL, map[string]any{"max-attempts": 3})
	_, err := a.Read(t.Context(), stores.Ref{Scheme: KindParameterStore, Path: "a/b"})
	if !errors.Is(err, stores.ErrUnavailable) || n.Load() != 3 {
		t.Errorf("throttled read: %v after %d calls, want unavailable after 3", err, n.Load())
	}
	srv2, n2 := fake(t, 400, func(string, []byte) string { return `{"__type":"ParameterNotFound"}` })
	a2 := open(t, KindParameterStore, srv2.URL, map[string]any{"max-attempts": 3})
	if _, err := a2.Read(t.Context(), stores.Ref{Scheme: KindParameterStore, Path: "a/b"}); !errors.Is(err, stores.ErrNotFound) || n2.Load() != 1 {
		t.Errorf("missing parameter: %v after %d calls, want not found after 1", err, n2.Load())
	}
}

func TestClassify(t *testing.T) {
	cases := []struct {
		code   string
		status int
		want   error
		retry  bool
	}{
		{"ResourceNotFoundException", 400, stores.ErrNotFound, false},
		{"ParameterVersionNotFound", 400, stores.ErrNotFound, false},
		{"AccessDeniedException", 400, stores.ErrPermission, false},
		{"UnrecognizedClientException", 400, stores.ErrPermission, false},
		{"ExpiredTokenException", 400, stores.ErrPermission, false},
		{"DecryptionFailure", 400, stores.ErrPermission, false},
		{"ResourceExistsException", 400, stores.ErrConflict, false},
		{"ParameterAlreadyExists", 400, stores.ErrConflict, false},
		{"ThrottlingException", 400, stores.ErrUnavailable, true},
		{"InternalServiceError", 500, stores.ErrUnavailable, true},
		{"", 503, stores.ErrUnavailable, true},
		{"", 403, stores.ErrPermission, false},
		{"ValidationException", 400, stores.ErrInvalidRef, false},
	}
	for _, c := range cases {
		got, retry := classify(c.code, c.status)
		if got != c.want || retry != c.retry {
			t.Errorf("classify(%q, %d) = %v, %v; want %v, %v", c.code, c.status, got, retry, c.want, c.retry)
		}
	}
}

func TestOptions(t *testing.T) {
	sm, ps := KindSecretsManager, KindParameterStore
	bad := []struct {
		kind string
		opts map[string]any
	}{
		{sm, map[string]any{"region": "Europe"}},
		{sm, map[string]any{"endpoint": "localhost:4566"}},
		{sm, map[string]any{"endpoint": "https://x.example/path"}},
		{sm, map[string]any{"endpoint": "https://x.example", "fips": true}},
		{sm, map[string]any{"access-key-id": "env:A"}},
		{sm, map[string]any{"access-key-id": "env:A", "secret-access-key": "env:B", "profile": "p"}},
		{sm, map[string]any{"assume-role.arn": "role/x"}},
		{sm, map[string]any{"assume-role.external-id": "x"}},
		{sm, map[string]any{"assume-role.arn": "arn:aws:iam::123456789012:role/r", "assume-role.duration": "1m"}},
		{sm, map[string]any{"assume-role.arn": "arn:aws:iam::123456789012:role/r", "assume-role.session-name": "a b"}},
		{sm, map[string]any{"timeout": "0s"}},
		{sm, map[string]any{"max-attempts": 0}},
		{sm, map[string]any{"regoin": "eu-west-1"}},
		{sm, map[string]any{"parameter-type": "String"}},
		{ps, map[string]any{"parameter-type": "StringList"}},
		{ps, map[string]any{"tier": "Gold"}},
		{ps, map[string]any{"parameter-type": "String", "kms-key-id": "alias/x"}},
		{ps, map[string]any{"create-secrets": true}},
	}
	for _, c := range bad {
		_, err := stores.DefaultRegistry.Open(t.Context(), stores.Instance{Name: "x", Kind: c.kind, Options: c.opts, Resolve: resolver(nil)})
		if !errors.Is(err, stores.ErrInvalidRef) {
			t.Errorf("%s %v: %v, want a configuration error", c.kind, c.opts, err)
		}
	}
	good := map[string]any{
		"region": "eu-west-1", "profile": "scrim", "assume-role": map[string]any{
			"arn": "arn:aws:iam::123456789012:role/scrim", "external-id": "x", "duration": "1h", "session-name": "scrim-eu",
		},
		"timeout": "5s", "max-attempts": 5, "watch": map[string]any{"interval": "1m"}, "kms-key-id": "alias/scrim",
	}
	for _, kind := range []string{KindSecretsManager, KindParameterStore} {
		a, err := stores.DefaultRegistry.Open(t.Context(), stores.Instance{Name: "x", Kind: kind, Options: good})
		if err != nil {
			t.Errorf("%s: %v", kind, err)
			continue
		}
		_ = a.Close()
	}
}

func TestSelectorsRefusedBeforeCalling(t *testing.T) {
	srv, n := fake(t, 500, func(string, []byte) string { return `{}` })
	sm := open(t, KindSecretsManager, srv.URL, nil)
	ps := open(t, KindParameterStore, srv.URL, nil)
	for _, c := range []struct {
		a   stores.Adapter
		ref string
	}{
		{sm, "awssm://app/key?label=x"},
		{sm, "awssm://bad name"},
		{ps, "ssm://app/key?stage=AWSCURRENT"},
		{ps, "ssm://app/key?version=0"},
		{ps, "ssm://app/key?version=1&label=x"},
		{ps, "ssm://app/key:1?label=x"},
		{ps, "ssm://app/bad name"},
	} {
		if _, err := c.a.Read(t.Context(), stores.MustParseRef(c.ref)); !errors.Is(err, stores.ErrInvalidRef) {
			t.Errorf("Read %s: %v, want invalid reference", c.ref, err)
		}
	}
	if _, err := ps.Write(t.Context(), stores.MustParseRef("ssm://aws/x"), map[string]secret.Value{Field: secret.FromString("v")}, stores.WriteOptions{}); !errors.Is(err, stores.ErrInvalidRef) {
		t.Errorf("write under the reserved aws prefix: %v", err)
	}
	if n.Load() != 0 {
		t.Errorf("%d calls reached AWS for references that do not parse", n.Load())
	}
}

func TestTagValues(t *testing.T) {
	for _, v := range []string{"a.example,b.example", "plain value", "x=y", "=2C", "日本,é", "", "50%"} {
		enc := encodeTagValue(v)
		if strings.ContainsFunc(enc, func(r rune) bool { return !tagChar(r) }) {
			t.Errorf("encoded %q = %q holds characters AWS refuses", v, enc)
		}
		if got := decodeTagValue(enc); got != v {
			t.Errorf("round trip of %q: %q", v, got)
		}
	}
	if got := decodeTagValue("a=b=zz="); got != "a=b=zz=" {
		t.Errorf("hand-written = mangled: %q", got)
	}
	tags, bad := writeTags(KindSecretsManager, map[string]string{"scrim.hosts": "a,b", "awssm.name": "x", "store.path": "y", "aws:x": "z", "team": "t"})
	if bad != "" || len(tags) != 2 || tags[0].Key != "scrim.hosts" || tags[0].Value != "a=2Cb" || tags[1].Key != "team" {
		t.Errorf("writeTags: %v %q", tags, bad)
	}
	if _, bad := writeTags(KindSecretsManager, map[string]string{"a,b": "x"}); bad != "a,b" {
		t.Errorf("a key AWS refuses was accepted")
	}
}

func TestTagsCannotForge(t *testing.T) {
	l := map[string]string{}
	stores.SetNative(l, KindSecretsManager, "name", "real")
	tagLabels(l, KindSecretsManager, []tag{{"awssm.name", "forged"}, {"scrim.hosts", "h=2Ci"}, {"env", "prod"}})
	if l["awssm.name"] != "real" || l["awssm.meta.awssm.name"] != "forged" || l["scrim.hosts"] != "h,i" || l["awssm.meta.env"] != "prod" {
		t.Errorf("labels: %v", l)
	}
	if _, ok := l["env"]; ok {
		t.Errorf("a tag set a label outside the meta namespace")
	}
}

func TestEncodeSecret(t *testing.T) {
	cases := []struct {
		fields map[string]secret.Value
		want   string
		binary bool
	}{
		{map[string]secret.Value{Field: secret.FromString("plain")}, "plain", false},
		{map[string]secret.Value{Field: secret.FromString(`{"a":"b"}`)}, `{"value":"{\"a\":\"b\"}"}`, false},
		{map[string]secret.Value{Field: secret.FromString(`["x"]`)}, `["x"]`, false},
		{map[string]secret.Value{"user": secret.FromString("u"), "pass": secret.FromString("p\"q")}, `{"pass":"p\"q","user":"u"}`, false},
		{map[string]secret.Value{Field: secret.New([]byte{0xff, 0})}, "\xff\x00", true},
	}
	for _, c := range cases {
		got, bin, err := encodeSecret(c.fields)
		if err != nil || string(got) != c.want || bin != c.binary {
			t.Errorf("encodeSecret(%v) = %q, %v, %v; want %q, %v", c.fields, got, bin, err, c.want, c.binary)
		}
	}
	if _, _, err := encodeSecret(map[string]secret.Value{"a": secret.New([]byte{0xff}), "b": secret.FromString("x")}); err == nil {
		t.Errorf("non-UTF-8 field in a JSON secret accepted")
	}
}

func TestDefaultEndpoint(t *testing.T) {
	for _, c := range []struct {
		svc, region string
		fips        bool
		want        string
	}{
		{"secretsmanager", "eu-west-1", false, "https://secretsmanager.eu-west-1.amazonaws.com"},
		{"ssm", "us-gov-west-1", true, "https://ssm-fips.us-gov-west-1.amazonaws.com"},
		{"ssm", "cn-north-1", false, "https://ssm.cn-north-1.amazonaws.com.cn"},
	} {
		if got := defaultEndpoint(c.svc, c.region, c.fips); got != c.want {
			t.Errorf("defaultEndpoint(%s, %s, %v) = %s", c.svc, c.region, c.fips, got)
		}
	}
}

func TestListPrefix(t *testing.T) {
	for in, want := range map[string][2]string{"app": {"app/", ""}, "app/*": {"app/", "glob"}, "app/db-*": {"app/db-", "glob"}} {
		got, glob := listPrefix(in)
		if got != want[0] || glob != (want[1] == "glob") {
			t.Errorf("listPrefix(%q) = %q, %v", in, got, glob)
		}
	}
	f, match := listFilter("app/db-*")
	if f["Key"] != "Name" || f["Option"] != "BeginsWith" || match != "/app/db-" {
		t.Errorf("glob filter %v %q", f, match)
	}
	f, match = listFilter("app")
	if f["Key"] != "Path" || f["Option"] != "Recursive" || match != "/app/" {
		t.Errorf("path filter %v %q", f, match)
	}
}
