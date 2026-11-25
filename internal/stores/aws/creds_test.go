// SPDX-License-Identifier: AGPL-3.0-only

package aws

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	sdkaws "github.com/aws/aws-sdk-go-v2/aws"

	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores"
)

// TestStaticKeysAreNotCached: configured access keys are copied out of
// their secret values for each signature, not kept by the SDK's credentials
// cache: once the values are wiped, the provider has nothing left to give.
func TestStaticKeysAreNotCached(t *testing.T) {
	srv, n := fake(t, 200, func(string, []byte) string { return `{"SecretList":[]}` })
	a := open(t, KindSecretsManager, srv.URL, nil).(*SecretsManager)
	if _, err := a.List(t.Context(), stores.Ref{Scheme: KindSecretsManager, Path: "app/"}); err != nil {
		t.Fatal(err)
	}
	if n.Load() == 0 {
		t.Fatal("no request reached the fake")
	}
	c := a.c
	if _, cached := c.creds.inner.(*sdkaws.CredentialsCache); cached {
		t.Fatal("static keys go through the SDK's credentials cache")
	}
	c.mu.Lock()
	for _, v := range c.static {
		v.Wipe()
	}
	c.mu.Unlock()
	cr, _ := c.creds.inner.Retrieve(t.Context())
	if cr.SecretAccessKey != "" || cr.AccessKeyID != "" {
		t.Fatal("the provider still returns the keys after their values were wiped")
	}
}

// TestRecorderKeepsValuesNotStrings: the recorder copies the secret parts of
// each new set of credentials into secret values, wipes the previous set,
// and hands out copies.
func TestRecorderKeepsValuesNotStrings(t *testing.T) {
	r := &recorder{}
	exp := time.Now().Add(time.Hour)
	r.record(sdkaws.Credentials{AccessKeyID: "AKIDONE", SecretAccessKey: "first-secret-key", SessionToken: "first-session", CanExpire: true, Expires: exp})
	first := r.secrets
	if len(first) != 2 {
		t.Fatalf("recorded %d values", len(first))
	}
	// The same credentials again keep the same values.
	r.record(sdkaws.Credentials{AccessKeyID: "AKIDONE", SecretAccessKey: "first-secret-key", SessionToken: "first-session", CanExpire: true, Expires: exp})
	if first[0].Wiped() || &r.secrets[0] != &first[0] {
		t.Fatal("unchanged credentials replaced the recorded values")
	}
	r.record(sdkaws.Credentials{AccessKeyID: "AKIDTWO", SecretAccessKey: "second-secret-key", SessionToken: "second-session", CanExpire: true, Expires: exp.Add(time.Hour)})
	if !first[0].Wiped() || !first[1].Wiped() {
		t.Error("replaced credentials were not wiped")
	}
	c := &client{creds: r}
	got := c.credentials()
	want := []string{"second-secret-key", "second-session"}
	if len(got) != len(want) {
		t.Fatalf("credentials: %d values", len(got))
	}
	for i, v := range got {
		if !v.Equal(secret.FromString(want[i])) {
			t.Errorf("value %d differs", i)
		}
		v.Wipe()
	}
	if r.secrets[0].Wiped() {
		t.Error("wiping a handed-out copy wiped the recorded value")
	}
	r.wipe()
	if len(c.credentials()) != 0 {
		t.Error("credentials after wipe")
	}
}

// TestAssumeRoleWithStaticKeys: with static keys and a role to assume, STS
// is called with the keys straight from their values (no cache in between),
// and the store with the role's credentials.
func TestAssumeRoleWithStaticKeys(t *testing.T) {
	var stsAuth, smAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.Form.Get("Action") == "AssumeRole" {
			stsAuth = r.Header.Get("Authorization")
			w.Header().Set("Content-Type", "text/xml")
			_, _ = io.WriteString(w, `<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><AssumeRoleResult>`+
				`<Credentials><AccessKeyId>ASIAROLE</AccessKeyId><SecretAccessKey>role-secret</SecretAccessKey>`+
				`<SessionToken>role-session</SessionToken><Expiration>`+time.Now().Add(time.Hour).UTC().Format(time.RFC3339)+`</Expiration></Credentials>`+
				`<AssumedRoleUser><Arn>arn:aws:sts::123456789012:assumed-role/r/s</Arn><AssumedRoleId>AROA:s</AssumedRoleId></AssumedRoleUser>`+
				`</AssumeRoleResult></AssumeRoleResponse>`)
			return
		}
		smAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		_, _ = io.WriteString(w, `{"SecretList":[]}`)
	}))
	defer srv.Close()
	a := open(t, KindSecretsManager, srv.URL, map[string]any{
		optRoleARN: "arn:aws:iam::123456789012:role/r", optSTSEndpoint: srv.URL,
	}).(*SecretsManager)
	if _, err := a.List(t.Context(), stores.Ref{Scheme: KindSecretsManager, Path: "app/"}); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(stsAuth, "AWS4-HMAC-SHA256 Credential=test/") {
		t.Errorf("AssumeRole signed with %q", stsAuth)
	}
	if !strings.HasPrefix(smAuth, "AWS4-HMAC-SHA256 Credential=ASIAROLE/") {
		t.Errorf("store call signed with %q", smAuth)
	}
}
