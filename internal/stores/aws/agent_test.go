// SPDX-License-Identifier: AGPL-3.0-only

package aws

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores"
)

// fakeAWS is STS (AssumeRoleWithWebIdentity, unsigned form requests) and
// Secrets Manager / SSM (signed JSON) on one endpoint. Each assumed role
// gets generated keys; reads are allowed by role.
type fakeAWS struct {
	t   *testing.T
	jwt string

	mu      sync.Mutex
	assumes []url.Values
	// keyRole maps an issued key ID to its role ARN and session token.
	keyRole map[string][2]string
	secrets map[string]string // last secret key issued, for leak checks
	// readable maps role ARN to the secret or parameter it may read.
	readable map[string]string
	reads    int
}

func (f *fakeAWS) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	b, _ := io.ReadAll(r.Body)
	if target := r.Header.Get("X-Amz-Target"); target == "" {
		q, _ := url.ParseQuery(string(b))
		f.assumes = append(f.assumes, q)
		if r.Header.Get("Authorization") != "" {
			f.t.Error("AssumeRoleWithWebIdentity was signed")
		}
		if q.Get("Action") != "AssumeRoleWithWebIdentity" || q.Get("WebIdentityToken") != f.jwt || strings.Contains(q.Get("RoleArn"), "denied") {
			w.WriteHeader(http.StatusForbidden)
			// Echo the token, as an error message might.
			_, _ = fmt.Fprintf(w, `<ErrorResponse><Error><Type>Sender</Type><Code>AccessDenied</Code><Message>Not authorized for %s</Message></Error></ErrorResponse>`, q.Get("WebIdentityToken"))
			return
		}
		id, key, sess := "tmpkey-"+randHex(f.t, 6), randHex(f.t, 20), randHex(f.t, 32)
		f.keyRole[id] = [2]string{q.Get("RoleArn"), sess}
		f.secrets[id] = key
		arn := strings.Replace(strings.Replace(q.Get("RoleArn"), ":iam::", ":sts::", 1), ":role/", ":assumed-role/", 1) + "/" + q.Get("RoleSessionName")
		_, _ = fmt.Fprintf(w, `<AssumeRoleWithWebIdentityResponse><AssumeRoleWithWebIdentityResult><Credentials>`+
			`<AccessKeyId>%s</AccessKeyId><SecretAccessKey>%s</SecretAccessKey><SessionToken>%s</SessionToken><Expiration>%s</Expiration>`+
			`</Credentials><AssumedRoleUser><Arn>%s</Arn><AssumedRoleId>AROA:x</AssumedRoleId></AssumedRoleUser></AssumeRoleWithWebIdentityResult></AssumeRoleWithWebIdentityResponse>`,
			id, key, sess, time.Now().Add(time.Hour).UTC().Format(time.RFC3339), arn)
		return
	}
	// A signed service call: find the role by the key in the signature.
	auth := r.Header.Get("Authorization")
	_, rest, _ := strings.Cut(auth, "Credential=")
	id, _, _ := strings.Cut(rest, "/")
	role, ok := f.keyRole[id]
	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	if !ok || r.Header.Get("X-Amz-Security-Token") != role[1] {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"__type":"UnrecognizedClientException","message":"bad token"}`)
		return
	}
	var in struct{ SecretId, Name string }
	_ = json.Unmarshal(b, &in)
	name := strings.TrimPrefix(in.SecretId+in.Name, "/")
	if f.readable[role[0]] != name {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = fmt.Fprintf(w, `{"__type":"AccessDeniedException","message":"User: %s is not authorized to perform this action"}`, role[0])
		return
	}
	f.reads++
	if strings.HasSuffix(r.Header.Get("X-Amz-Target"), "GetParameter") {
		_, _ = io.WriteString(w, `{"Parameter":{"Name":"`+in.Name+`","Value":"pv-`+randHex(f.t, 8)+`","Version":1}}`)
		return
	}
	_, _ = io.WriteString(w, `{"Name":"`+in.SecretId+`","SecretString":"sv-`+randHex(f.t, 8)+`","VersionId":"v1"}`)
}

func federated(key, session, roleARN, jwt string, mints *int) stores.AgentCredential {
	return stores.AgentCredential{Agent: "claude-laptop/" + session, Federation: &stores.Federation{
		Method: stores.FederationAWS, Params: map[string]string{"role-arn": roleARN, "audience": "sts.amazonaws.com", "duration": "15m"},
		Audience: "sts.amazonaws.com", SessionName: "claude-laptop." + session, Key: key, Session: session,
		Token: func() (secret.Value, error) { *mints++; return secret.FromString(jwt), nil },
	}}
}

// TestAgentWebIdentity: the agent's identity token is exchanged for its
// own role (role ARN, session name, duration and token as given; the call
// unsigned), the read is signed with that role's keys and session token,
// the role is cached per agent and dropped with its session, the role's
// own permissions decide, and no token or key reaches an error.
func TestAgentWebIdentity(t *testing.T) {
	jwt := "eyJ" + randHex(t, 40) + "." + randHex(t, 40) + "." + randHex(t, 40)
	f := &fakeAWS{t: t, jwt: jwt, keyRole: map[string][2]string{}, secrets: map[string]string{}, readable: map[string]string{
		"arn:aws:iam::000000000000:role/agent-claude-laptop": "prod/db",
	}}
	srv := httptest.NewServer(f)
	defer srv.Close()
	ctx := t.Context()
	const role = "arn:aws:iam::000000000000:role/agent-claude-laptop"
	var errs []error
	for _, kind := range []string{KindSecretsManager, KindParameterStore} {
		a := open(t, kind, srv.URL, nil)
		acc := a.(stores.AgentAccess)
		if m := a.(stores.AgentFederation).FederationMethods(); len(m) != 1 || m[0] != stores.FederationAWS {
			t.Fatalf("%s methods %v", kind, m)
		}
		mints := 0
		cred := federated(kind+"-k1", "s1", role, jwt, &mints)
		path := "prod/db"
		if err := acc.AgentCan(ctx, cred, stores.OpRead, stores.Ref{Scheme: kind, Path: path}); err != nil {
			t.Fatalf("%s: allowed read: %v", kind, err)
		}
		f.mu.Lock()
		q := f.assumes[len(f.assumes)-1]
		n := len(f.assumes)
		f.mu.Unlock()
		if q.Get("RoleArn") != role || q.Get("RoleSessionName") != "claude-laptop.s1" || q.Get("DurationSeconds") != "900" || q.Get("Version") != "2011-06-15" {
			t.Fatalf("%s: assume request %v", kind, q)
		}
		// Cached: no second exchange or mint.
		err := acc.AgentCan(ctx, cred, stores.OpRead, stores.Ref{Scheme: kind, Path: "prod/payments"})
		if !errors.Is(err, stores.ErrPermission) {
			t.Fatalf("%s: read outside the role: %v", kind, err)
		}
		errs = append(errs, err)
		f.mu.Lock()
		if len(f.assumes) != n || mints != 1 {
			t.Fatalf("%s: %d assumes, %d mints; want the role cached", kind, len(f.assumes)-n+1, mints)
		}
		f.mu.Unlock()
		// The session ends: its role goes.
		a.(stores.SessionForgetter).ForgetSession("s1")
		if err := acc.AgentCan(ctx, cred, stores.OpRead, stores.Ref{Scheme: kind, Path: path}); err != nil || mints != 2 {
			t.Fatalf("%s: after ForgetSession: %v, %d mints", kind, err, mints)
		}
		// A role whose trust refuses the agent.
		err = acc.AgentCan(ctx, federated(kind+"-k2", "s2", "arn:aws:iam::000000000000:role/denied", jwt, &mints), stores.OpRead, stores.Ref{Scheme: kind, Path: path})
		if !errors.Is(err, stores.ErrPermission) || !strings.Contains(err.Error(), "AccessDenied") {
			t.Fatalf("%s: refused exchange: %v", kind, err)
		}
		errs = append(errs, err)
		// A token STS does not accept.
		err = acc.AgentCan(ctx, federated(kind+"-k3", "s3", role, jwt+"x", &mints), stores.OpRead, stores.Ref{Scheme: kind, Path: path})
		if !errors.Is(err, stores.ErrPermission) {
			t.Fatalf("%s: bad token: %v", kind, err)
		}
		errs = append(errs, err)
		if err := acc.AgentCan(ctx, cred, stores.OpWrite, stores.Ref{Scheme: kind, Path: path}); !errors.Is(err, stores.ErrUnsupported) {
			t.Fatalf("%s: write check: %v", kind, err)
		}
		static := stores.AgentCredential{Agent: "laptop", Token: secret.FromString("tok")}
		if err := acc.AgentCan(ctx, static, stores.OpRead, stores.Ref{Scheme: kind, Path: path}); !errors.Is(err, stores.ErrUnsupported) {
			t.Fatalf("%s: static token: %v", kind, err)
		}
		if err := a.Close(); err != nil {
			t.Fatal(err)
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.reads != 4 {
		t.Fatalf("%d reads with the agent's role, want 4", f.reads)
	}
	for _, err := range errs {
		msg := chain(err)
		if strings.Contains(msg, jwt[:30]) || strings.Contains(msg, jwt[len(jwt)-30:]) {
			t.Fatalf("the identity token reached an error: %s", msg)
		}
		for id, key := range f.secrets {
			if strings.Contains(msg, key) || strings.Contains(msg, f.keyRole[id][1]) {
				t.Fatalf("an assumed role's key reached an error: %s", msg)
			}
		}
	}
}

func TestQueryEscape(t *testing.T) {
	got := string(appendQueryEscape(nil, []byte("a/b+c=d e~._-")))
	if got != "a%2Fb%2Bc%3Dd%20e~._-" {
		t.Fatal(got)
	}
}
