// SPDX-License-Identifier: AGPL-3.0-only

package openbao

import (
	"net/url"
	"strings"
	"time"

	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/stores/internal/options"
	"github.com/heliopsy/scrim/internal/stores/internal/satoken"
)

// Option keys, relative to `stores.<instance>.`. docs/stores/openbao.md
// documents each one; keep the two in step. Credential fields are top-level
// names because the stores collection resolves and masks them by name.
const (
	optAddress         = "address"
	optNamespace       = "namespace"
	optMounts          = "mounts"
	optAuthMethod      = "auth.method"
	optAuthToken       = "token"
	optAppRoleMount    = "auth.approle.mount"
	optAppRoleRoleID   = "role-id"
	optAppRoleSecretID = "secret-id"
	optK8sMount        = "auth.kubernetes.mount"
	optK8sRole         = "auth.kubernetes.role"
	optK8sTokenFile    = "auth.kubernetes.token-file"
	optTimeout         = "timeout"
	optCAFile          = "tls.ca-file"
	optServerName      = "tls.server-name"
	optWatchInterval   = "watch.interval"
	optWatchMaxBackoff = "watch.max-backoff"
	optWriteOnly       = "write-only-paths"
	optLabelLookups    = "labels.lookups"
)

// Auth methods.
const (
	AuthToken      = "token"
	AuthAppRole    = "approle"
	AuthKubernetes = "kubernetes"
)

// Defaults.
const (
	DefaultTimeout         = 10 * time.Second
	DefaultWatchInterval   = 30 * time.Second
	DefaultWatchMaxBackoff = 5 * time.Minute
	DefaultAppRoleMount    = "approle"
	DefaultK8sMount        = "kubernetes"
	// DefaultK8sTokenFile is where the kubelet mounts the pod's default
	// service account token. A projected token with a dedicated audience
	// is the better choice; see docs/stores/openbao.md.
	DefaultK8sTokenFile = satoken.DefaultPath
)

// Options is the decoded configuration of one OpenBao instance.
type Options struct {
	Address   *url.URL
	Namespace string
	// Mounts lists KV v2 mount paths that span more than one path segment
	// (for example "teams/kv"). A reference's mount is the longest listed
	// mount it starts with, or else its first segment.
	Mounts       []string
	AuthMethod   string
	Token        config.SecretRef
	AppRoleMount string
	RoleID       config.SecretRef
	SecretID     config.SecretRef
	// K8sMount, K8sRole and K8sTokenFile configure Kubernetes auth: the
	// mount of the auth method, the role to log in as and the file holding
	// the pod's service account token, read again at every login.
	K8sMount        string
	K8sRole         string
	K8sTokenFile    string
	Timeout         time.Duration
	CAFile          string
	ServerName      string
	WatchInterval   time.Duration
	WatchMaxBackoff time.Duration
	// WriteOnly lists path prefixes (mount included) that scrim writes but
	// never reads back from the store.
	WriteOnly []string
	// LabelLookups allows the optional requests that fill native labels:
	// a secret's metadata on read and its mount's information.
	LabelLookups bool
}

// ParseOptions decodes and validates raw instance options. Every problem is
// reported, each naming its key; values of credential settings are never
// echoed.
func ParseOptions(raw map[string]any) (Options, error) {
	return parseOptions("openbao", raw)
}

func parseOptions(store string, raw map[string]any) (Options, error) {
	d := options.New(store, raw)
	o := Options{}
	addr := d.String(optAddress, "")
	o.Namespace = strings.Trim(d.String(optNamespace, ""), "/")
	for _, m := range d.Strings(optMounts) {
		if m = strings.Trim(m, "/"); m != "" {
			o.Mounts = append(o.Mounts, m)
		}
	}
	o.AuthMethod = d.String(optAuthMethod, AuthToken)
	o.Token = d.SecretRef(optAuthToken)
	o.AppRoleMount = strings.Trim(d.String(optAppRoleMount, DefaultAppRoleMount), "/")
	o.RoleID = d.SecretRef(optAppRoleRoleID)
	o.SecretID = d.SecretRef(optAppRoleSecretID)
	o.K8sMount = strings.Trim(d.String(optK8sMount, DefaultK8sMount), "/")
	o.K8sRole = d.String(optK8sRole, "")
	o.K8sTokenFile = d.String(optK8sTokenFile, DefaultK8sTokenFile)
	o.Timeout = d.Duration(optTimeout, DefaultTimeout)
	o.CAFile = d.String(optCAFile, "")
	o.ServerName = d.String(optServerName, "")
	o.WatchInterval = d.Duration(optWatchInterval, DefaultWatchInterval)
	o.WatchMaxBackoff = d.Duration(optWatchMaxBackoff, DefaultWatchMaxBackoff)
	o.LabelLookups = d.Bool(optLabelLookups, true)
	for _, p := range d.Strings(optWriteOnly) {
		if p = strings.Trim(p, "/"); p != "" {
			o.WriteOnly = append(o.WriteOnly, p)
		}
	}

	if addr == "" {
		d.Errorf("option %s is required", optAddress)
	} else if u, err := url.Parse(addr); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		d.Errorf("option %s must be an http or https URL", optAddress)
	} else {
		u.Path = strings.TrimSuffix(u.Path, "/")
		o.Address = u
	}
	switch o.AuthMethod {
	case AuthToken:
		if o.Token == "" {
			d.Errorf("option %s is required with auth.method %s", optAuthToken, AuthToken)
		}
	case AuthAppRole:
		if o.RoleID == "" {
			d.Errorf("option %s is required with auth.method %s", optAppRoleRoleID, AuthAppRole)
		}
		if o.SecretID == "" {
			d.Errorf("option %s is required with auth.method %s", optAppRoleSecretID, AuthAppRole)
		}
	case AuthKubernetes:
		if o.K8sRole == "" {
			d.Errorf("option %s is required with auth.method %s", optK8sRole, AuthKubernetes)
		}
		if o.K8sTokenFile == "" {
			d.Errorf("option %s must not be empty", optK8sTokenFile)
		}
		// The point of Kubernetes auth is that no static credential exists;
		// one configured anyway would sit unused in the cluster.
		for i, ref := range []config.SecretRef{o.Token, o.RoleID, o.SecretID} {
			if ref != "" {
				d.Errorf("option %s is not used with auth.method %s; remove it",
					[]string{optAuthToken, optAppRoleRoleID, optAppRoleSecretID}[i], AuthKubernetes)
			}
		}
	default:
		d.Errorf("option %s must be %s, %s or %s", optAuthMethod, AuthToken, AuthAppRole, AuthKubernetes)
	}
	if o.AppRoleMount == "" {
		o.AppRoleMount = DefaultAppRoleMount
	}
	if o.K8sMount == "" {
		o.K8sMount = DefaultK8sMount
	}
	for key, v := range map[string]time.Duration{optTimeout: o.Timeout, optWatchInterval: o.WatchInterval, optWatchMaxBackoff: o.WatchMaxBackoff} {
		if v <= 0 {
			d.Errorf("option %s must be positive", key)
		}
	}
	if o.WatchMaxBackoff < o.WatchInterval {
		o.WatchMaxBackoff = o.WatchInterval
	}
	return o, d.Finish()
}
