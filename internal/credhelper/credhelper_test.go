// SPDX-License-Identifier: AGPL-3.0-only

package credhelper

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func run(t *testing.T, environ []string, stdin string, args ...string) (string, string, int) {
	t.Helper()
	var out, errb bytes.Buffer
	code := Main(args, environ, strings.NewReader(stdin), &out, &errb)
	return out.String(), errb.String(), code
}

func TestGit(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "git-credentials")
	if err := os.WriteFile(file, []byte("https://x-access-token:SCRIM_GITHUB@github.com\nhttps://bot:SCRIM_GITEA@git.example.com:3000\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, _, code := run(t, nil, "protocol=https\nhost=github.com\n\n", "git", "--file", file, "get")
	if code != 0 || out != "username=x-access-token\npassword=SCRIM_GITHUB\n" {
		t.Fatalf("get github.com: %d %q", code, out)
	}
	out, _, _ = run(t, nil, "protocol=https\nhost=git.example.com:3000\n\n", "git", "--file", file, "get")
	if out != "username=bot\npassword=SCRIM_GITEA\n" {
		t.Fatalf("get with port: %q", out)
	}
	if out, _, code := run(t, nil, "protocol=https\nhost=gitlab.com\n\n", "git", "--file", file, "get"); code != 0 || out != "" {
		t.Fatalf("unknown host: %d %q", code, out)
	}
	before, _ := os.ReadFile(file)
	for _, action := range []string{"store", "erase"} {
		if out, _, code := run(t, nil, "protocol=https\nhost=github.com\nusername=u\npassword=real-value-123\n\n", "git", "--file", file, action); code != 0 || out != "" {
			t.Fatalf("%s: %d %q", action, code, out)
		}
	}
	if after, _ := os.ReadFile(file); !bytes.Equal(before, after) {
		t.Fatal("store or erase changed the credential file")
	}
}

func TestDocker(t *testing.T) {
	dir := t.TempDir()
	auth := base64.StdEncoding.EncodeToString([]byte("scrim:SCRIM_REGISTRY"))
	cfg := `{"auths":{"registry.example.com":{"auth":"` + auth + `"},"https://index.docker.io/v1/":{"auth":"` + auth + `"}},"credHelpers":{"registry.example.com":"scrim"}}`
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	env := []string{"DOCKER_CONFIG=" + dir}
	out, _, code := run(t, env, "registry.example.com\n", "docker", "get")
	var c dockerCred
	if code != 0 || json.Unmarshal([]byte(out), &c) != nil || c.Username != "scrim" || c.Secret != "SCRIM_REGISTRY" || c.ServerURL != "registry.example.com" {
		t.Fatalf("get: %d %q", code, out)
	}
	if out, _, _ := run(t, env, "docker.io", "docker", "get"); !strings.Contains(out, "SCRIM_REGISTRY") {
		t.Fatalf("Docker Hub get: %q", out)
	}
	if out, _, code := run(t, env, "other.example.com", "docker", "get"); code != 1 || strings.TrimSpace(out) != dockerNotFound {
		t.Fatalf("unknown registry: %d %q", code, out)
	}
	if out, _, code := run(t, env, "", "docker", "list"); code != 0 || !strings.Contains(out, `"registry.example.com":"scrim"`) {
		t.Fatalf("list: %d %q", code, out)
	}
	// store succeeds only for the placeholder it returns.
	if _, _, code := run(t, env, `{"ServerURL":"registry.example.com","Username":"scrim","Secret":"SCRIM_REGISTRY"}`, "docker", "store"); code != 0 {
		t.Fatalf("store of the placeholder: %d", code)
	}
	real := "real-registry-password-0d1e2f"
	out, errOut, code := run(t, env, `{"ServerURL":"registry.example.com","Username":"me","Secret":"`+real+`"}`, "docker", "store")
	if code == 0 || !strings.Contains(errOut, "does not store credentials") || strings.Contains(out+errOut, real) {
		t.Fatalf("store of another credential: %d %q %q", code, out, errOut)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "config.json")); string(b) != cfg {
		t.Fatal("store changed the config")
	}
	// Without DOCKER_CONFIG it knows nothing, not even ~/.docker/config.json.
	if out, _, code := run(t, []string{"HOME=" + dir}, "registry.example.com", "docker", "get"); code != 1 || strings.Contains(out, "SCRIM") {
		t.Fatalf("get outside a session: %d %q", code, out)
	}
}

func TestAWSAndKubectl(t *testing.T) {
	out, _, code := run(t, nil, "", "aws", "--access-key-id", "SCRIM_AWS_ID", "--secret-access-key", "SCRIM_AWS_SECRET")
	var a map[string]any
	if code != 0 || json.Unmarshal([]byte(out), &a) != nil || a["Version"] != float64(1) || a["AccessKeyId"] != "SCRIM_AWS_ID" ||
		a["SecretAccessKey"] != "SCRIM_AWS_SECRET" || a["SessionToken"] != nil {
		t.Fatalf("aws: %d %q", code, out)
	}
	if _, _, code := run(t, nil, "", "aws", "--access-key-id", "x"); code == 0 {
		t.Fatal("aws without a secret key succeeded")
	}
	env := []string{`KUBERNETES_EXEC_INFO={"apiVersion":"client.authentication.k8s.io/v1beta1","kind":"ExecCredential"}`}
	out, _, code = run(t, env, "", "kubectl", "--token", "SCRIM_K8S")
	var k struct {
		APIVersion string `json:"apiVersion"`
		Kind       string `json:"kind"`
		Status     struct {
			Token string `json:"token"`
		} `json:"status"`
	}
	if code != 0 || json.Unmarshal([]byte(out), &k) != nil || k.Kind != "ExecCredential" || k.Status.Token != "SCRIM_K8S" ||
		k.APIVersion != "client.authentication.k8s.io/v1beta1" {
		t.Fatalf("kubectl: %d %q", code, out)
	}
	if _, _, code := run(t, nil, "", "nope"); code == 0 {
		t.Fatal("an unknown helper succeeded")
	}
}
