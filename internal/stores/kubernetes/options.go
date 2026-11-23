// SPDX-License-Identifier: AGPL-3.0-only

package kubernetes

import (
	"fmt"
	"path/filepath"
	"slices"
	"time"

	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/heliopsy/scrim/internal/stores/internal/options"
)

// Authentication methods (option auth.method).
const (
	// AuthInCluster uses the pod's service account, as every in-cluster
	// client does.
	AuthInCluster = "in-cluster"
	// AuthKubeconfig uses one context of one kubeconfig file, both named in
	// the configuration.
	AuthKubeconfig = "kubeconfig"
)

// DefaultTimeout bounds every request except watches.
const DefaultTimeout = 10 * time.Second

// Option keys.
const (
	optAuthMethod = "auth.method"
	optKubeconfig = "auth.kubeconfig"
	optContext    = "auth.context"
	optNamespace  = "namespace"
	optNamespaces = "namespaces"
	optWritable   = "writable"
	optTimeout    = "timeout"
)

// Config is the Kubernetes source's configuration.
type Config struct {
	// AuthMethod is AuthInCluster (the default) or AuthKubeconfig.
	AuthMethod string
	// Kubeconfig is the absolute path of the kubeconfig file, and Context
	// the context in it. Both are required with AuthKubeconfig and refused
	// otherwise. Neither KUBECONFIG nor ~/.kube/config nor the file's
	// current-context is ever used.
	Kubeconfig string
	Context    string
	// Namespace confines the instance to one namespace; references are
	// then `<instance>://<name>`. Exactly one of Namespace and Namespaces
	// is set.
	Namespace string
	// Namespaces is the namespaces the instance may use; references are
	// then `<instance>://<namespace>/<name>`.
	Namespaces []string
	// Writable allows writes. Off by default: the source is read-only.
	Writable bool
	// Timeout bounds every request except watches.
	Timeout time.Duration
}

// namespaced reports whether references carry no namespace segment.
func (c Config) namespaced() bool { return c.Namespace != "" }

// allowed reports whether ns is one of the configured namespaces.
func (c Config) allowed(ns string) bool {
	if c.namespaced() {
		return ns == c.Namespace
	}
	return slices.Contains(c.Namespaces, ns)
}

// all is every configured namespace.
func (c Config) all() []string {
	if c.namespaced() {
		return []string{c.Namespace}
	}
	return c.Namespaces
}

// ParseOptions decodes and validates instance options strictly. Every
// problem is reported, each naming its key.
func ParseOptions(store string, raw map[string]any) (Config, error) {
	d := options.New(store, raw)
	c := Config{
		AuthMethod: d.String(optAuthMethod, AuthInCluster),
		Kubeconfig: d.String(optKubeconfig, ""),
		Context:    d.String(optContext, ""),
		Namespace:  d.String(optNamespace, ""),
		Namespaces: d.Strings(optNamespaces),
		Writable:   d.Bool(optWritable, false),
		Timeout:    d.Duration(optTimeout, DefaultTimeout),
	}
	switch c.AuthMethod {
	case AuthInCluster:
		for _, k := range []struct{ key, val string }{{optKubeconfig, c.Kubeconfig}, {optContext, c.Context}} {
			if k.val != "" {
				d.Errorf("option %s is only used with %s %s; remove it", k.key, optAuthMethod, AuthKubeconfig)
			}
		}
	case AuthKubeconfig:
		switch {
		case c.Kubeconfig == "":
			d.Errorf("option %s is required with %s %s", optKubeconfig, optAuthMethod, AuthKubeconfig)
		case !filepath.IsAbs(c.Kubeconfig):
			d.Errorf("option %s must be an absolute path", optKubeconfig)
		}
		if c.Context == "" {
			d.Errorf("option %s is required with %s %s: scrim never uses a kubeconfig's current context",
				optContext, optAuthMethod, AuthKubeconfig)
		}
	default:
		d.Errorf("option %s must be %s or %s", optAuthMethod, AuthInCluster, AuthKubeconfig)
	}
	switch {
	case c.Namespace != "" && len(c.Namespaces) > 0:
		d.Errorf("set option %s or %s, not both", optNamespace, optNamespaces)
	case c.Namespace == "" && len(c.Namespaces) == 0:
		d.Errorf("option %s or %s is required: scrim never reads a whole cluster", optNamespace, optNamespaces)
	}
	for _, ns := range append([]string{c.Namespace}, c.Namespaces...) {
		if ns != "" && len(validation.IsDNS1123Label(ns)) > 0 {
			d.Errorf("namespace %q is not a valid namespace name", ns)
		}
	}
	slices.Sort(c.Namespaces)
	if len(slices.Compact(slices.Clone(c.Namespaces))) != len(c.Namespaces) {
		d.Errorf("option %s lists a namespace twice", optNamespaces)
	}
	if c.Timeout <= 0 {
		d.Errorf("option %s must be positive", optTimeout)
	}
	return c, d.Finish()
}

// restConfig builds the client configuration. It never consults KUBECONFIG,
// ~/.kube/config or a kubeconfig's current-context.
func (c Config) restConfig() (*rest.Config, error) {
	var (
		rc  *rest.Config
		err error
	)
	switch c.AuthMethod {
	case AuthKubeconfig:
		rc, err = kubeconfigRest(c.Kubeconfig, c.Context)
	default:
		rc, err = rest.InClusterConfig()
		if err != nil {
			err = fmt.Errorf("not running in a Kubernetes pod with a service account: %w", err)
		}
	}
	if err != nil {
		return nil, err
	}
	// No rest.Config.Timeout: it would end every watch after that long.
	// Requests get their own deadline from Config.Timeout instead.
	rc.QPS, rc.Burst = 20, 40
	rc.UserAgent = "scrim"
	return rc, nil
}

// kubeconfigRest loads one named context from one file.
func kubeconfigRest(path, context string) (*rest.Config, error) {
	kc, err := clientcmd.LoadFromFile(path)
	if err != nil {
		// The error names the file; a kubeconfig that fails to parse may
		// be quoted by the YAML decoder, so its text is dropped.
		return nil, fmt.Errorf("cannot load kubeconfig %s", path)
	}
	if err := clientcmd.ResolveLocalPaths(kc); err != nil {
		return nil, fmt.Errorf("kubeconfig %s: cannot resolve its file paths", path)
	}
	if _, ok := kc.Contexts[context]; !ok {
		return nil, fmt.Errorf("kubeconfig %s has no context %q", path, context)
	}
	rc, err := clientcmd.NewNonInteractiveClientConfig(*kc, context, &clientcmd.ConfigOverrides{}, nil).ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("kubeconfig %s context %q: incomplete", path, context)
	}
	return rc, nil
}
