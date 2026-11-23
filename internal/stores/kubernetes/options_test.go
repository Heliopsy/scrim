// SPDX-License-Identifier: AGPL-3.0-only

package kubernetes

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/heliopsy/scrim/internal/stores"
)

func TestParseOptions(t *testing.T) {
	abs := filepath.Join(t.TempDir(), "kubeconfig")
	cases := []struct {
		name string
		raw  map[string]any
		want []string // substrings of the error; none means valid
	}{
		{"in-cluster one namespace", map[string]any{"namespace": "prod"}, nil},
		{"in-cluster namespaces", map[string]any{"namespaces": []any{"a", "b"}}, nil},
		{"namespaces from env", map[string]any{"namespaces": "a, b"}, nil},
		{"kubeconfig with context", map[string]any{"auth": map[string]any{"method": "kubeconfig", "kubeconfig": abs, "context": "kind-x"}, "namespace": "a"}, nil},
		{"writable", map[string]any{"namespace": "a", "writable": "true", "timeout": "3s"}, nil},
		{"no namespace", map[string]any{}, []string{"option namespace or namespaces is required"}},
		{"both namespace forms", map[string]any{"namespace": "a", "namespaces": []any{"b"}}, []string{"not both"}},
		{"bad namespace", map[string]any{"namespaces": []any{"Prod"}}, []string{`namespace "Prod" is not a valid`}},
		{"duplicate namespace", map[string]any{"namespaces": []any{"a", "a"}}, []string{"twice"}},
		{"kubeconfig without context", map[string]any{"auth": map[string]any{"method": "kubeconfig", "kubeconfig": abs}, "namespace": "a"},
			[]string{"option auth.context is required", "never uses a kubeconfig's current context"}},
		{"kubeconfig without path", map[string]any{"auth": map[string]any{"method": "kubeconfig", "context": "c"}, "namespace": "a"},
			[]string{"option auth.kubeconfig is required"}},
		{"relative kubeconfig", map[string]any{"auth": map[string]any{"method": "kubeconfig", "kubeconfig": "kube/config", "context": "c"}, "namespace": "a"},
			[]string{"must be an absolute path"}},
		{"kubeconfig keys with in-cluster", map[string]any{"auth": map[string]any{"kubeconfig": abs, "context": "c"}, "namespace": "a"},
			[]string{"option auth.kubeconfig is only used", "option auth.context is only used"}},
		{"unknown method", map[string]any{"auth": map[string]any{"method": "token"}, "namespace": "a"}, []string{"must be in-cluster or kubeconfig"}},
		{"typo", map[string]any{"namespace": "a", "writeable": true}, []string{"unknown option writeable", "did you mean writable"}},
		{"bad timeout", map[string]any{"namespace": "a", "timeout": "0s"}, []string{"timeout must be positive"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := ParseOptions("k8s", c.raw)
			if len(c.want) == 0 {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("accepted, want error with %q", c.want)
			}
			for _, w := range c.want {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("error %q does not contain %q", err, w)
				}
			}
		})
	}
}

func TestDefaults(t *testing.T) {
	c, err := ParseOptions("k8s", map[string]any{"namespace": "a"})
	if err != nil {
		t.Fatal(err)
	}
	if c.AuthMethod != AuthInCluster || c.Writable || c.Timeout != DefaultTimeout {
		t.Errorf("defaults: %+v", c)
	}
}

// kubeconfig with two clusters; current-context points at the wrong one.
const twoContexts = `apiVersion: v1
kind: Config
current-context: wrong
clusters:
- name: right
  cluster: {server: "https://right.example.test:6443"}
- name: wrong
  cluster: {server: "https://wrong.example.test:6443"}
users:
- name: u
  user: {token: not-a-real-token}
contexts:
- name: right
  context: {cluster: right, user: u}
- name: wrong
  context: {cluster: wrong, user: u}
`

func TestKubeconfigExplicitContextOnly(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config")
	if err := os.WriteFile(path, []byte(twoContexts), 0o600); err != nil {
		t.Fatal(err)
	}
	// An ambient KUBECONFIG pointing elsewhere must not matter.
	other := filepath.Join(dir, "other")
	if err := os.WriteFile(other, []byte(strings.ReplaceAll(twoContexts, "right.example", "ambient.example")), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KUBECONFIG", other)
	t.Setenv("HOME", dir)

	rc, err := Config{AuthMethod: AuthKubeconfig, Kubeconfig: path, Context: "right"}.restConfig()
	if err != nil {
		t.Fatal(err)
	}
	if rc.Host != "https://right.example.test:6443" {
		t.Errorf("host %q, want the named context's cluster", rc.Host)
	}
	_, err = Config{AuthMethod: AuthKubeconfig, Kubeconfig: path, Context: "missing"}.restConfig()
	if err == nil || !strings.Contains(err.Error(), `has no context "missing"`) {
		t.Errorf("missing context: %v", err)
	}
	if strings.Contains(err.Error(), "not-a-real-token") {
		t.Errorf("error carries the kubeconfig's credential")
	}
	_, err = Config{AuthMethod: AuthKubeconfig, Kubeconfig: filepath.Join(dir, "absent"), Context: "right"}.restConfig()
	if err == nil {
		t.Errorf("a missing kubeconfig file was accepted")
	}
}

func TestBrokenKubeconfigNoLeak(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	const cred = "kc_cred_6f1d2a9b"
	if err := os.WriteFile(path, []byte("users: [{name: u, user: {token: "+cred+"}}\n  bad: [indent"), 0o600); err != nil {
		t.Fatal(err)
	}
	a := New("k8s", Config{AuthMethod: AuthKubeconfig, Kubeconfig: path, Context: "x", Namespace: "a", Timeout: DefaultTimeout})
	err := a.Health(context.Background())
	if !errors.Is(err, stores.ErrUnavailable) {
		t.Fatalf("Health with a broken kubeconfig: %v, want ErrUnavailable", err)
	}
	if strings.Contains(err.Error(), cred) || !strings.Contains(err.Error(), path) {
		t.Errorf("error %q must name the file and not quote it", err)
	}
}

func TestInClusterOutsideAPod(t *testing.T) {
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	t.Setenv("KUBERNETES_SERVICE_PORT", "")
	a := New("k8s", Config{AuthMethod: AuthInCluster, Namespace: "a", Timeout: DefaultTimeout})
	err := a.Health(context.Background())
	if !errors.Is(err, stores.ErrUnavailable) || !strings.Contains(err.Error(), "not running in a Kubernetes pod") {
		t.Errorf("in-cluster outside a pod: %v", err)
	}
}
