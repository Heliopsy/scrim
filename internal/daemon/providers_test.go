// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/heliopsy/scrim/internal/config"
	pb "github.com/heliopsy/scrim/internal/dataplane/dataplanev1"
	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores"
	"github.com/heliopsy/scrim/internal/stores/refresh"
)

func TestProviderRoutes(t *testing.T) {
	cfg := buildConfig(t, `proxy:
  chain:
    url: http://127.0.0.1:8787
providers:
  bedrock:
    kind: bedrock
    region: us-east-1
    access-key-id: bao://kv/aws#access_key_id
    secret-access-key: bao://kv/aws#secret_access_key
    session-token: bao://kv/aws#session_token
  bedrock-2:
    kind: bedrock
    region: us-east-1
    api-key: bao://kv/aws#bedrock_api_key
  claude-aws:
    kind: anthropic-aws
    region: eu-west-1
    access-key-id: bao://kv/aws#access_key_id
    secret-access-key: bao://kv/aws#secret_access_key
  mantle:
    kind: bedrock-mantle
    region: us-west-2
    api-key: bao://kv/aws#bedrock_api_key
  azure:
    kind: foundry
    resource: my-res
    api-key: bao://kv/azure#key
  local:
    kind: foundry
    upstream: http://127.0.0.1:9999/
    api-key: bao://kv/azure#key
`)
	byName := map[string]*pb.Route{}
	for _, r := range routes(cfg) {
		byName[r.GetName()] = r
	}
	b := byName["bedrock"]
	if b.GetProvider() != "bedrock" || b.GetUpstream() != "https://bedrock-runtime.us-east-1.amazonaws.com" ||
		b.GetPathPrefix() != "/bedrock" || !slices.Equal(b.GetHosts(), []string{"bedrock-runtime.us-east-1.amazonaws.com"}) {
		t.Errorf("bedrock route: %v", b)
	}
	if b.GetChain() != nil || byName["claude-aws"].GetChain() != nil {
		t.Error("a provider route is chained: the chain would receive its credentials")
	}
	if byName["anthropic"].GetChain() == nil {
		t.Error("the built-in routes lost the chain")
	}
	s := b.GetAuth().GetAwsSigv4()
	if s.GetRegion() != "us-east-1" || s.GetService() != "bedrock" || s.GetAccessKeyIdRef() != "bao://kv/aws#access_key_id" ||
		s.GetSecretAccessKeyRef() != "bao://kv/aws#secret_access_key" || s.GetSessionTokenRef() != "bao://kv/aws#session_token" {
		t.Errorf("bedrock auth: %v", s)
	}
	if h := byName["bedrock-2"]; len(h.GetHosts()) != 0 || h.GetAuth().GetHeader().GetName() != "authorization" ||
		h.GetAuth().GetHeader().GetPrefix() != "Bearer " {
		t.Errorf("a second route for a claimed host keeps it, or the API key is not a bearer token: %v", h)
	}
	if a := byName["claude-aws"]; a.GetProvider() != "anthropic" || a.GetUpstream() != "https://aws-external-anthropic.eu-west-1.api.aws" ||
		a.GetAuth().GetAwsSigv4().GetService() != "aws-external-anthropic" {
		t.Errorf("claude platform on aws: %v", a)
	}
	if m := byName["mantle"]; m.GetUpstream() != "https://bedrock-mantle.us-west-2.api.aws" || m.GetProvider() != "anthropic" {
		t.Errorf("mantle: %v", m)
	}
	if f := byName["azure"]; f.GetUpstream() != "https://my-res.services.ai.azure.com" || f.GetAuth().GetHeader().GetName() != "api-key" ||
		f.GetAuth().GetHeader().GetPrefix() != "" || f.GetAuth().GetHeader().GetValueRef() != "bao://kv/azure#key" {
		t.Errorf("foundry: %v", f)
	}
	if !slices.Contains(bypass(cfg), "127.0.0.1:9999") {
		t.Errorf("a loopback provider upstream is not bypassed: %v", bypass(cfg))
	}
	got := ProviderRoutes(cfg)
	if got[ProviderBedrock] != "/bedrock" || got[ProviderAnthropicAWS] != "/claude-aws" || got[ProviderFoundry] != "/azure" {
		t.Errorf("ProviderRoutes = %v", got)
	}
}

func TestProviderValidation(t *testing.T) {
	keys := "    access-key-id: bao://kv/aws#id\n    secret-access-key: bao://kv/aws#secret\n"
	for _, c := range []struct{ body, want string }{
		{"kind: vertex\n" + keys, "must be one of"},
		{"kind: bedrock\n" + keys, "region: required"},
		{"kind: bedrock\n    region: us-east-1\n", "needs credentials"},
		{"kind: bedrock\n    region: us-east-1\n    access-key-id: bao://kv/aws#id\n", "go together"},
		{"kind: bedrock\n    region: us-east-1\n    api-key: AKIALITERALKEY\n", "must be a store reference"},
		{"kind: bedrock\n    region: us-east-1\n    api-key: bao://kv/a#k\n" + keys, "not both"},
		{"kind: bedrock\n    region: bedrock-runtime.us-east-1.amazonaws.com\n" + keys, "not an AWS region"},
		{"kind: foundry\n    api-key: bao://kv/a#k\n", "resource: required"},
		{"kind: foundry\n    resource: https://x.services.ai.azure.com\n    api-key: bao://kv/a#k\n", "resource name alone"},
		{"kind: foundry\n    resource: xy\n" + keys, "foundry takes api-key"},
		{"kind: bedrock\n    region: us-east-1\n    upstream: https://h/path\n" + keys, "origin without a path"},
		{"kind: bedrock\n    region: us-east-1\n    bogus: 1\n" + keys, "unknown field bogus"},
	} {
		err := buildErr(t, "providers:\n  p:\n    "+c.body)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%q: got %v, want %q", c.body, err, c.want)
		}
		if err != nil && strings.Contains(err.Error(), "AKIALITERALKEY") {
			t.Errorf("an error repeats the literal value: %v", err)
		}
	}
	if err := buildErr(t, "providers:\n  anthropic:\n    kind: foundry\n    resource: x\n    api-key: bao://kv/a#k\n"); err == nil ||
		!strings.Contains(err.Error(), "built-in route") {
		t.Errorf("a provider may take a built-in route's name: %v", err)
	}
}

func buildErr(t *testing.T, body string) error {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte("apiVersion: "+config.APIVersion+"\nkind: Config\n"+body), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := config.Build(config.Options{Registry: config.Default, ConfigPaths: []string{p}, Environ: []string{}})
	return err
}

func TestProviderCredentialsTravelInTheSnapshot(t *testing.T) {
	cfg := buildConfig(t, "providers:\n  azure:\n    kind: foundry\n    resource: res\n    api-key: e2e://tools/cloud-key\n")
	v := seed(t, "key-")
	// The file store reports the default field explicitly; a retained value
	// of the same secret is never the one signed with.
	src := &fakeValues{store: "e2e", vals: []fakeValue{
		{refresh.Source{Ref: stores.MustParseRef("e2e://tools/cloud-key#value"), Retained: true}, secret.FromString(seed(t, "old-"))},
		{refresh.Source{Ref: stores.MustParseRef("e2e://tools/cloud-key#value")}, secret.FromString(v)},
	}}
	b := &SnapshotBuilder{Config: func() *config.Config { return cfg }, Values: []ValueSource{src}}
	b.SetKeys(testRing(t))
	snap, err := b.Build(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	var ref string
	for _, r := range snap.GetRoutes() {
		if r.GetName() == "azure" {
			ref = r.GetAuth().GetHeader().GetValueRef()
		}
	}
	if ref != "e2e://tools/cloud-key#value" {
		t.Errorf("the route names %q, not the stored value's reference", ref)
	}
	found := false
	for _, e := range snap.GetValues() {
		found = found || (e.GetRef() == ref && string(e.GetValue()) == v)
	}
	if !found {
		t.Errorf("the route's reference %q matches no current value in the snapshot", ref)
	}
}
