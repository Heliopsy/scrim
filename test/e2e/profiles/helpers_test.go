// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package profiles

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/heliopsy/scrim/internal/leak"
	fp "github.com/heliopsy/scrim/internal/testing/fakeprovider"
	"github.com/heliopsy/scrim/test/e2e/harness"
)

// TestCredentialHelpers runs kubectl and aws with their profiles' helper
// variants (tasks 10a.9): kubectl's kubeconfig user is scrim's exec
// credential plugin and aws's config has scrim's credential_process, so
// neither tool has a credential in a file. git and docker use scrim's
// helpers by default and are covered in TestProfiles.
func TestCredentialHelpers(t *testing.T) {
	e := setupWith(t, `tool-profiles:
  kubectl: {params: {helper: scrim}}
  aws: {params: {helper: scrim}}
`)
	path := func(names ...string) string { return harness.PathWith(t, names...) }

	t.Run("kubectl exec plugin", func(t *testing.T) {
		harness.LookPath(t, "kubectl")
		before := e.fake.count("k8s.scrim.test")
		r := e.sh(t, "", `set -e
kubectl get --raw /api/v1/namespaces/default/pods
kubectl config view --raw`, path("kubectl"))
		must(t, r, "kubectl")
		contains(t, r, `"name":"scrim-e2e"`)
		contains(t, r, "- credential-helper")
		contains(t, r, "SCRIM_K8S")
		if strings.Contains(r.Stdout, "token: ") {
			t.Error("the kubeconfig holds a token although the exec plugin supplies it")
		}
		if e.fake.count("k8s.scrim.test") == before {
			t.Error("the API server received no request with the real token")
		}
	})

	t.Run("aws credential_process", func(t *testing.T) {
		harness.LookPath(t, "aws")
		r := e.sh(t, "", `set -e
aws configure export-credentials --format env
cat "$AWS_SHARED_CREDENTIALS_FILE"`, path("aws"), "AWS_ACCESS_KEY_ID="+e.seeds["aws-id"].Value())
		must(t, r, "aws configure export-credentials")
		contains(t, r, "AWS_ACCESS_KEY_ID=SCRIM_AWS_ID")
		contains(t, r, "AWS_SECRET_ACCESS_KEY=SCRIM_AWS_SECRET")
		if strings.Contains(r.Stdout, "aws_secret_access_key") {
			t.Error("the credentials file holds keys although credential_process supplies them")
		}
	})
}

// TestProjectFileValues is the fixture of tasks 10a.11: a key in the
// project's .env that no store holds is redacted from the agent's first
// request, and a value written into .env while the agent runs is redacted
// from the requests after the rescan.
func TestProjectFileValues(t *testing.T) {
	bin := harness.Require(t)
	harness.LookPath(t, "curl")
	key, later := leak.Generate(leak.KindAPIKey), leak.Generate(leak.KindAPIKey)
	fake := fp.New(fp.Options{})
	provider := httptest.NewServer(fake)
	defer provider.Close()
	// The store holds an unrelated value; the .env key is in no store.
	d := harness.Start(t, bin, harness.Options{Upstream: provider.URL, Secrets: map[string]string{"other": leak.Generate(leak.KindAPIKey).Value()},
		Extra: "run:\n  scan-interval: 200ms\n"})

	work := t.TempDir()
	if err := os.WriteFile(filepath.Join(work, ".env"), []byte("OPENAI_API_KEY="+key.Value()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ask := `curl -sS --fail-with-body "$ANTHROPIC_BASE_URL/v1/messages" -H 'content-type: application/json' ` +
		`-H 'x-api-key: fake-provider-key' -H 'anthropic-version: 2023-06-01' ` +
		`-d "{\"model\":\"m\",\"max_tokens\":8,\"messages\":[{\"role\":\"user\",\"content\":\"the key is $1\"}]}" >/dev/null`
	script := `set -e
ask() { ` + ask + `; }
. ./.env
ask "$OPENAI_API_KEY"
printf 'LATER_API_TOKEN=%s\n' "$LATER" >> .env
sleep 2
. ./.env
ask "$LATER_API_TOKEN"`
	r := d.Run(t, work, []string{"LATER=" + later.Value()}, "sh", "-c", script)
	if r.Code != 0 {
		t.Fatalf("agent: exit %d\n%s", r.Code, r.Output())
	}
	if !strings.Contains(r.Stderr, "secret values in project files are redacted") {
		t.Errorf("scrim run did not say it redacts the project values:\n%s", r.Stderr)
	}
	ex := fake.Exchanges()
	if len(ex) != 2 {
		t.Fatalf("the provider received %d requests, want 2", len(ex))
	}
	checker := leak.NewChecker([]leak.Seed{key, later})
	for i, x := range ex {
		if f := checker.Check(x.Capture); len(f) > 0 {
			t.Errorf("request %d holds a project value: %d findings", i+1, len(f))
		}
		if !strings.Contains(string(x.Body), "scrim:project-env-") {
			t.Errorf("request %d does not carry a placeholder where the value was", i+1)
		}
	}
	for _, out := range []string{r.Output(), d.Log.String()} {
		if f := checker.Check(leak.Capture{Body: []byte(out)}); len(f) > 0 {
			t.Error("scrim's output or log holds a project value")
		}
	}
}
