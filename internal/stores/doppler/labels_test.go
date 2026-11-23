// SPDX-License-Identifier: AGPL-3.0-only

package doppler

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/heliopsy/scrim/internal/policy"
	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores"
)

// TestLabels pins the native labels of a secret in a branch config, and
// that Read, List, ReadMetadata and WriteLabels agree on the ones they share.
func TestLabels(t *testing.T) {
	f, toks := newFake(t)
	v, note := "lab-"+randID(8), "note-"+randID(8)
	f.put("billing/dev_feature", "payments/stripe.key", v, func(s *fakeSecret) {
		s.note, s.visibility, s.valueType = note, "restricted", "string"
	})
	a := newAdapter(t, f.srv.URL, toks[tokSA], nil)
	r := ref("billing/dev_feature/payments/stripe.key")

	// Before any call, WriteLabels knows only the reference.
	pre := a.WriteLabels(r)
	for k, want := range map[string]string{"doppler.project": "billing", "doppler.config": "dev_feature", "doppler.secret": "payments/stripe.key", "doppler.managed": "false"} {
		if pre[k] != want {
			t.Errorf("WriteLabels before any call: %s = %q, want %q", k, pre[k], want)
		}
	}
	if _, ok := pre["doppler.environment"]; ok {
		t.Errorf("WriteLabels guessed the environment without asking Doppler")
	}

	s, err := a.Read(t.Context(), r)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	defer s.Wipe()
	want := map[string]string{
		"doppler.workplace":           "2faa85f6610102d983522",
		"doppler.workplace.name":      "Doppler University",
		"doppler.project":             "billing",
		"doppler.config":              "dev_feature",
		"doppler.environment":         "dev",
		"doppler.config.root":         "false",
		"doppler.config.locked":       "false",
		"doppler.secret":              "payments/stripe.key",
		"doppler.managed":             "false",
		"doppler.visibility":          "restricted",
		"doppler.computed-visibility": "restricted",
		"doppler.value-type":          "string",
	}
	for k, w := range want {
		if s.Meta.Labels[k] != w {
			t.Errorf("Read: %s = %q, want %q", k, s.Meta.Labels[k], w)
		}
	}
	for k := range s.Meta.Labels {
		if _, ok := want[k]; !ok && k != "doppler.config.inheritable" {
			t.Errorf("Read: unexpected label %s", k)
		}
	}
	noValue(t, "labels", s.Meta.Labels, v, note)

	readOnly := []string{"doppler.visibility", "doppler.computed-visibility", "doppler.value-type"}
	same := func(what string, got map[string]string) {
		t.Helper()
		for k, w := range want {
			if slices.Contains(readOnly, k) {
				if _, ok := got[k]; ok {
					t.Errorf("%s: %s is only known with the value, but is set", what, k)
				}
				continue
			}
			if got[k] != w {
				t.Errorf("%s: %s = %q, want %q", what, k, got[k], w)
			}
		}
	}
	m, err := a.ReadMetadata(t.Context(), r)
	if err != nil {
		t.Fatalf("ReadMetadata: %v", err)
	}
	same("ReadMetadata", m.Labels)
	ms, err := a.List(t.Context(), ref("billing/dev_feature/payments"))
	if err != nil || len(ms) != 1 {
		t.Fatalf("List: %v %v", ms, err)
	}
	same("List", ms[0].Labels)
	// Once the config is known, WriteLabels has its details too.
	same("WriteLabels", a.WriteLabels(r))
	if a.WriteLabels(ref("billing/dev_feature")) != nil {
		t.Errorf("WriteLabels of a config, not a secret, returned labels")
	}
}

// TestLabelsWithoutConfigAccess: a token that may read secrets but not
// describe its config gets the labels its reference gives, and the refused
// lookup is not repeated on every read.
func TestLabelsWithoutConfigAccess(t *testing.T) {
	f, toks := newFake(t)
	f.hiddenConfigs["billing/dev"] = true
	f.put("billing/dev", "A", "a-"+randID(6), nil)
	f.put("billing/dev", "B", "b-"+randID(6), nil)
	a := newAdapter(t, f.srv.URL, toks[tokSA], nil)
	for _, n := range []string{"A", "B", "A"} {
		s, err := a.Read(t.Context(), ref("billing/dev/"+n))
		if err != nil {
			t.Fatalf("Read: %v", err)
		}
		if s.Meta.Labels["doppler.config"] != "dev" {
			t.Errorf("labels %v", s.Meta.Labels)
		}
		if _, ok := s.Meta.Labels["doppler.environment"]; ok {
			t.Errorf("environment label without config access")
		}
		s.Wipe()
	}
	if n := f.count("GET /v3/configs/config"); n != 1 {
		t.Errorf("config details asked %d times, want once", n)
	}
	if n := f.count("GET /v3/me"); n != 1 {
		t.Errorf("workplace asked %d times, want once", n)
	}
}

// TestReadMetadataWithoutValues: the metadata lookup never makes a request
// that returns a value, and fails where a read fails.
func TestReadMetadataWithoutValues(t *testing.T) {
	f, toks := newFake(t)
	f.put("billing/dev", "KEY", "m-"+randID(8), nil)
	a := newAdapter(t, f.srv.URL, toks[tokSA], nil)
	before := f.values()
	if _, err := a.ReadMetadata(t.Context(), ref("billing/dev/KEY")); err != nil {
		t.Fatalf("ReadMetadata: %v", err)
	}
	if _, err := a.ReadMetadata(t.Context(), ref("billing/dev/MISSING")); !errors.Is(err, stores.ErrNotFound) {
		t.Errorf("ReadMetadata of a missing secret: %v", err)
	}
	if f.values() != before {
		t.Errorf("ReadMetadata fetched a value")
	}
	if n := f.count("GET /v3/configs/config/secret"); n != 0 {
		t.Errorf("ReadMetadata read the secret %d times", n)
	}
	// Set.Metadata uses it, so exists is reported without a read.
	set := stores.NewSet()
	if err := set.Add(a); err != nil {
		t.Fatal(err)
	}
	_, exists, err := set.Metadata(t.Context(), ref("billing/dev/KEY"))
	if err != nil || !exists {
		t.Errorf("Set.Metadata: exists=%v err=%v", exists, err)
	}
	f.setDown(true)
	if _, err := a.ReadMetadata(t.Context(), ref("billing/dev/KEY")); !errors.Is(err, stores.ErrUnavailable) {
		t.Errorf("ReadMetadata during an outage: %v", err)
	}
	st := newAdapter(t, f.srv.URL, toks[tokServiceRO], nil)
	f.setDown(false)
	if _, err := st.ReadMetadata(t.Context(), ref("billing/dev/KEY")); !errors.Is(err, stores.ErrPermission) {
		t.Errorf("ReadMetadata outside the token's config: %v", err)
	}
}

// TestWriteResponseValuesWiped: the write response echoes every value of the
// config; none of them reaches the returned metadata.
func TestWriteResponseValuesWiped(t *testing.T) {
	f, toks := newFake(t)
	other := "o-" + randID(8)
	f.put("billing/dev", "OTHER", other, nil)
	a := newAdapter(t, f.srv.URL, toks[tokSA], nil)
	v := "n-" + randID(8)
	m, err := a.Write(t.Context(), ref("billing/dev/NEW"), map[string]secret.Value{Field: secret.FromString(v)}, stores.WriteOptions{})
	if err != nil {
		t.Fatal(err)
	}
	noValue(t, "write metadata", m, v, other)
	if m.Ref.Path != "billing/dev/NEW" || m.Labels["doppler.secret"] != "NEW" {
		t.Errorf("metadata %+v", m)
	}
}

// TestFakeMatchesFixtures checks the fake answers with the fields of the
// recorded responses in testdata, so the conformance run exercises the
// documented shapes.
func TestFakeMatchesFixtures(t *testing.T) {
	f, toks := newFake(t)
	f.put("billing/dev", "DATABASE", "${USER}@aws.dynamodb.com:9876", nil)
	f.put("billing/dev", "USER", "brian", nil)
	get := func(path string, q url.Values) map[string]any {
		t.Helper()
		req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, f.srv.URL+path+"?"+q.Encode(), nil)
		req.Header.Set("Authorization", "Bearer "+toks[tokSA])
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		b, _ := io.ReadAll(resp.Body)
		var out map[string]any
		if err := json.Unmarshal(b, &out); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		return out
	}
	fixture := func(name string) map[string]any {
		t.Helper()
		b, err := os.ReadFile(filepath.Join("testdata", name))
		if err != nil {
			t.Fatal(err)
		}
		var out map[string]any
		if err := json.Unmarshal(b, &out); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		return out
	}
	cfg := url.Values{"project": {"billing"}, "config": {"dev"}}
	sec := url.Values{"project": {"billing"}, "config": {"dev"}, "name": {"DATABASE"}}
	missing := url.Values{"project": {"billing"}, "config": {"dev"}, "name": {"NOPE"}}
	for _, tc := range []struct {
		fixture, path string
		q             url.Values
	}{
		{"me.json", "/v3/me", nil},
		{"config.json", "/v3/configs/config", cfg},
		{"secret-get-cli.json", "/v3/configs/config/secret", sec},
		{"names.json", "/v3/configs/config/secrets/names", cfg},
		{"error.json", "/v3/configs/config/secret", missing},
	} {
		want, got := keys("", fixture(tc.fixture)), keys("", get(tc.path, tc.q))
		for _, k := range want {
			if k == ".success" && tc.fixture == "secret-get-cli.json" {
				continue // the CLI's envelope field, not in the reference
			}
			if !slices.Contains(got, k) {
				t.Errorf("%s: the fake's answer lacks %s", tc.fixture, k)
			}
		}
	}
	dl := get("/v3/configs/config/secrets/download", url.Values{"project": {"billing"}, "config": {"dev"}, "format": {"json"}})
	if dl["DATABASE"] != "brian@aws.dynamodb.com:9876" {
		t.Errorf("download does not hold computed values as download.json does")
	}
}

// keys lists the object keys of v, dotted, recursing into objects.
func keys(prefix string, v map[string]any) []string {
	var out []string
	for k, x := range v {
		out = append(out, prefix+"."+k)
		if m, ok := x.(map[string]any); ok {
			out = append(out, keys(prefix+"."+k, m)...)
		}
	}
	return out
}

// The example rules in docs/stores/doppler.md compile and decide as the page
// says, on labels the adapter produced.
func TestLabelsDocsPolicyExamples(t *testing.T) {
	data, err := os.ReadFile("../../../docs/stores/doppler.md")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile("(?s)<!-- policy-example -->\n```yaml\n(.*?)```").FindSubmatch(data)
	if m == nil {
		t.Fatal("docs/stores/doppler.md has no policy example block")
	}
	for _, b := range regexp.MustCompile("(?s)```cel\n(.*?)```").FindAllSubmatch(data, -1) {
		for line := range strings.SplitSeq(string(b[1]), "\n") {
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
	f, toks := newFake(t)
	f.hiddenConfigs["billing/dev_feature"] = true
	f.put("billing/dev", "API_KEY", "v-"+randID(8), nil)
	f.put("billing/prd", "API_KEY", "v-"+randID(8), nil)
	f.put("billing/dev_feature", "API_KEY", "v-"+randID(8), nil)
	a := newAdapter(t, f.srv.URL, toks[tokSA], nil)
	decide := func(op policy.Action, path string, labels map[string]string) policy.Effect {
		return rs.Evaluate(policy.Request{
			Agent: policy.Agent{ID: "codex", Kind: "session"}, Action: op,
			Ref: ref(path), Store: "dop", SecretLabels: labels,
		}).Effect
	}
	for path, want := range map[string]policy.Effect{
		"billing/dev/API_KEY":         policy.Allow,
		"billing/prd/API_KEY":         policy.Ask,
		"billing/dev_feature/API_KEY": policy.Ask, // no environment label
	} {
		s, err := a.Read(t.Context(), ref(path))
		if err != nil {
			t.Fatalf("Read %s: %v", path, err)
		}
		s.Wipe()
		if got := decide(policy.ActionRead, path, s.Meta.Labels); got != want {
			t.Errorf("read %s = %s, want %s", path, got, want)
		}
	}
	for path, want := range map[string]policy.Effect{"billing/prd/NEW": policy.Ask, "billing/dev/NEW": policy.Allow} {
		if got := decide(policy.ActionWrite, path, a.WriteLabels(ref(path))); got != want {
			t.Errorf("write %s = %s, want %s", path, got, want)
		}
	}
}
