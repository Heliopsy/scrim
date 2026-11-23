// SPDX-License-Identifier: AGPL-3.0-only

package aws

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	sdkaws "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/heliopsy/scrim/internal/agentstore"
	"github.com/heliopsy/scrim/internal/identity"
	"github.com/heliopsy/scrim/internal/identity/issuer"
	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores"
)

// TestLocalStackAgentWebIdentity is 12.2b's AWS verification: scrim's own
// issuer signs an identity token for agent claude-laptop, the awssm store
// trades it for the role agent-claude-laptop (identity.store-login
// aws-web-identity through agentstore, as the daemon wires it) and reads
// the secret as that role. The audit evidence is what CloudTrail records
// as userIdentity.arn: GetCallerIdentity with the role's keys answers
// arn:aws:sts::000000000000:assumed-role/agent-claude-laptop/<session
// name>, the session name being the agent's.
//
// LocalStack community neither verifies the web identity token nor
// enforces IAM, so the refusals (a role that does not trust the agent, a
// role without access to the secret) are covered by TestAgentWebIdentity
// against a fake only.
func TestLocalStackAgentWebIdentity(t *testing.T) {
	ls := startLocalStack(t)
	ctx := t.Context()
	a := ls.adapter(t, KindSecretsManager, "awssm", nil)
	name := "scrim-agent/" + randHex(t, 6)
	if _, err := a.Write(ctx, stores.Ref{Scheme: "awssm", Path: name}, map[string]secret.Value{Field: secret.FromString("v-" + randHex(t, 12))}, stores.WriteOptions{}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	iss, err := issuer.New(issuer.Options{URL: "https://scrim-idp.example.test", KeyDir: filepath.Join(t.TempDir(), "issuer")})
	if err != nil {
		t.Fatal(err)
	}
	defer iss.Close()
	c, err := agentstore.New(agentstore.Options{
		Login:  map[string]string{"awssm": "aws-web-identity role-arn:arn:aws:iam::000000000000:role/agent-{agent}"},
		Lookup: func(stores.Ref) (stores.Adapter, error) { return a, nil }, Issuer: iss, RequireIssuer: true,
		Adapter: func(string) (stores.Adapter, bool) { return a, true },
	})
	if err != nil {
		t.Fatal(err)
	}
	id := identity.Identity{Agent: "claude-laptop", Source: identity.SourceSession, SessionID: "s" + randHex(t, 4),
		ExpiresAt: time.Now().Add(time.Hour), Scopes: identity.AgentScopes}
	src, err := c.Check(ctx, id, nil, stores.OpRead, stores.Ref{Scheme: "awssm", Path: name})
	if err != nil || src != agentstore.SourceFederated {
		t.Fatalf("agent read through its own role: %s %v", src, err)
	}

	// The audit trail: who AWS says made the call with the agent's keys.
	sm := a.(*SecretsManager)
	jwt, _, err := iss.Mint(id, "sts.amazonaws.com")
	if err != nil {
		t.Fatal(err)
	}
	session := agentstore.SessionName(id)
	cr, err := sm.c.assumeWithWebIdentity(ctx, "arn:aws:iam::000000000000:role/agent-claude-laptop", session, 15*time.Minute, jwt)
	jwt.Wipe()
	if err != nil {
		t.Fatal(err)
	}
	defer cr.wipe()
	client := sts.New(sts.Options{Region: "us-east-1", BaseEndpoint: sdkaws.String(ls.endpoint), Credentials: cr.provider()})
	out, err := client.GetCallerIdentity(context.WithoutCancel(ctx), &sts.GetCallerIdentityInput{})
	if err != nil {
		t.Fatalf("GetCallerIdentity as the agent: %v", err)
	}
	want := "arn:aws:sts::000000000000:assumed-role/agent-claude-laptop/" + session
	got := sdkaws.ToString(out.Arn)
	t.Logf("CloudTrail userIdentity.arn for the agent's calls: %s (AssumeRoleWithWebIdentity returned %s)", got, cr.arn)
	if got != want || cr.arn != want || !strings.HasPrefix(session, "claude-laptop.") {
		t.Fatalf("caller %q (assumed %q), want %q", got, cr.arn, want)
	}
}
