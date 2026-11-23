// SPDX-License-Identifier: AGPL-3.0-only

package vaultapi

import (
	"net/url"
	"strings"
	"time"

	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/stores/internal/options"
	"github.com/heliopsy/scrim/internal/stores/internal/satoken"
)

// Option keys shared by the adapters, relative to `stores.<instance>.`.
// Credential fields are top-level names because the stores collection
// resolves and masks them by name.
const (
	OptAddress         = "address"
	OptNamespace       = "namespace"
	OptAuthMethod      = "auth.method"
	OptAuthNamespace   = "auth.namespace"
	OptAuthToken       = "token"
	OptAppRoleMount    = "auth.approle.mount"
	OptAppRoleRoleID   = "role-id"
	OptAppRoleSecretID = "secret-id"
	OptK8sMount        = "auth.kubernetes.mount"
	OptK8sRole         = "auth.kubernetes.role"
	OptK8sTokenFile    = "auth.kubernetes.token-file"
	OptJWTMount        = "auth.jwt.mount"
	OptJWTRole         = "auth.jwt.role"
	OptJWTTokenFile    = "auth.jwt.token-file"
	OptJWT             = "jwt"
	OptTimeout         = "timeout"
	OptCAFile          = "tls.ca-file"
	OptServerName      = "tls.server-name"
)

// Auth methods.
const (
	AuthToken      = "token"
	AuthAppRole    = "approle"
	AuthKubernetes = "kubernetes"
	AuthJWT        = "jwt"
)

// Defaults.
const (
	DefaultTimeout      = 10 * time.Second
	DefaultAppRoleMount = "approle"
	DefaultK8sMount     = "kubernetes"
	DefaultJWTMount     = "jwt"
	// DefaultK8sTokenFile is where the kubelet mounts the pod's default
	// service account token.
	DefaultK8sTokenFile = satoken.DefaultPath
)

// Options is how to reach and log in to one store.
type Options struct {
	Address   *url.URL
	Namespace string
	// AuthNamespace, when set, is the namespace logins are sent to (an
	// auth method mounted in a parent namespace); requests use Namespace.
	AuthNamespace string
	AuthMethod    string
	Token         config.SecretRef
	AppRoleMount  string
	RoleID        config.SecretRef
	SecretID      config.SecretRef
	// K8sMount, K8sRole and K8sTokenFile configure Kubernetes auth: the
	// mount of the auth method, the role to log in as and the file holding
	// the pod's service account token, read again at every login.
	K8sMount     string
	K8sRole      string
	K8sTokenFile string
	// JWTMount and JWTRole configure JWT auth. The JWT comes from
	// JWTTokenFile or the JWT reference, read again at every login, since
	// such tokens are short-lived and rotated by whoever issues them.
	JWTMount     string
	JWTRole      string
	JWTTokenFile string
	JWT          config.SecretRef
	Timeout      time.Duration
	CAFile       string
	ServerName   string
}

// Features selects the optional parts of the shared options an adapter
// offers.
type Features struct {
	// JWT allows auth.method jwt and its options.
	JWT bool
	// AuthNamespace allows auth.namespace.
	AuthNamespace bool
}

// Parse decodes the shared options from d. Problems are recorded in d,
// each naming its key; values of credential settings are never echoed.
func Parse(d *options.Decoder, f Features) Options {
	o := Options{}
	addr := d.String(OptAddress, "")
	o.Namespace = strings.Trim(d.String(OptNamespace, ""), "/")
	if f.AuthNamespace {
		o.AuthNamespace = strings.Trim(d.String(OptAuthNamespace, ""), "/")
	}
	o.AuthMethod = d.String(OptAuthMethod, AuthToken)
	o.Token = d.SecretRef(OptAuthToken)
	o.AppRoleMount = strings.Trim(d.String(OptAppRoleMount, DefaultAppRoleMount), "/")
	o.RoleID = d.SecretRef(OptAppRoleRoleID)
	o.SecretID = d.SecretRef(OptAppRoleSecretID)
	o.K8sMount = strings.Trim(d.String(OptK8sMount, DefaultK8sMount), "/")
	o.K8sRole = d.String(OptK8sRole, "")
	o.K8sTokenFile = d.String(OptK8sTokenFile, DefaultK8sTokenFile)
	if f.JWT {
		o.JWTMount = strings.Trim(d.String(OptJWTMount, DefaultJWTMount), "/")
		o.JWTRole = d.String(OptJWTRole, "")
		o.JWTTokenFile = d.String(OptJWTTokenFile, "")
		o.JWT = d.SecretRef(OptJWT)
	}
	o.Timeout = d.Duration(OptTimeout, DefaultTimeout)
	o.CAFile = d.String(OptCAFile, "")
	o.ServerName = d.String(OptServerName, "")

	if addr == "" {
		d.Errorf("option %s is required", OptAddress)
	} else if u, err := url.Parse(addr); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		d.Errorf("option %s must be an http or https URL", OptAddress)
	} else {
		u.Path = strings.TrimSuffix(u.Path, "/")
		o.Address = u
	}
	// The point of Kubernetes and JWT auth is that no static credential
	// exists; one configured anyway would sit unused.
	unused := func(method string, keys ...string) {
		refs := map[string]config.SecretRef{OptAuthToken: o.Token, OptAppRoleRoleID: o.RoleID, OptAppRoleSecretID: o.SecretID, OptJWT: o.JWT}
		for _, k := range keys {
			if refs[k] != "" {
				d.Errorf("option %s is not used with auth.method %s; remove it", k, method)
			}
		}
	}
	switch o.AuthMethod {
	case AuthToken:
		if o.Token == "" {
			d.Errorf("option %s is required with auth.method %s", OptAuthToken, AuthToken)
		}
	case AuthAppRole:
		if o.RoleID == "" {
			d.Errorf("option %s is required with auth.method %s", OptAppRoleRoleID, AuthAppRole)
		}
		if o.SecretID == "" {
			d.Errorf("option %s is required with auth.method %s", OptAppRoleSecretID, AuthAppRole)
		}
	case AuthKubernetes:
		if o.K8sRole == "" {
			d.Errorf("option %s is required with auth.method %s", OptK8sRole, AuthKubernetes)
		}
		if o.K8sTokenFile == "" {
			d.Errorf("option %s must not be empty", OptK8sTokenFile)
		}
		unused(AuthKubernetes, OptAuthToken, OptAppRoleRoleID, OptAppRoleSecretID, OptJWT)
	case AuthJWT:
		if !f.JWT {
			d.Errorf("option %s must be %s, %s or %s", OptAuthMethod, AuthToken, AuthAppRole, AuthKubernetes)
			break
		}
		if o.JWTRole == "" {
			d.Errorf("option %s is required with auth.method %s", OptJWTRole, AuthJWT)
		}
		if (o.JWTTokenFile == "") == (o.JWT == "") {
			d.Errorf("auth.method %s needs exactly one of %s and %s", AuthJWT, OptJWTTokenFile, OptJWT)
		}
		unused(AuthJWT, OptAuthToken, OptAppRoleRoleID, OptAppRoleSecretID)
	default:
		if f.JWT {
			d.Errorf("option %s must be %s, %s, %s or %s", OptAuthMethod, AuthToken, AuthAppRole, AuthKubernetes, AuthJWT)
		} else {
			d.Errorf("option %s must be %s, %s or %s", OptAuthMethod, AuthToken, AuthAppRole, AuthKubernetes)
		}
	}
	if o.AppRoleMount == "" {
		o.AppRoleMount = DefaultAppRoleMount
	}
	if o.K8sMount == "" {
		o.K8sMount = DefaultK8sMount
	}
	if f.JWT && o.JWTMount == "" {
		o.JWTMount = DefaultJWTMount
	}
	if o.Timeout <= 0 {
		d.Errorf("option %s must be positive", OptTimeout)
	}
	return o
}
