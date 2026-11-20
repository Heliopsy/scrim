// SPDX-License-Identifier: AGPL-3.0-only

package infisical

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores"
	"github.com/heliopsy/scrim/internal/stores/internal/options"
	"github.com/heliopsy/scrim/internal/stores/internal/satoken"
)

// Option keys, relative to stores.<instance>. The full configuration key is
// stores.<instance>.<key>; the environment variable is SCRIM_ plus that key
// upper-cased with dots and dashes as underscores.
const (
	optAddress       = "address"
	optAuthMethod    = "auth.method"
	optClientID      = "client-id"
	optClientSecret  = "client-secret"
	optTimeout       = "timeout"
	optCAFile        = "tls.ca-file"
	optWatchInterval = "watch.interval"
	optWatchBackoff  = "watch.max-backoff"
	optCreateFolders = "create-folders"
	optExpandRefs    = "expand-references"
	optK8sIdentityID = "auth.kubernetes.identity-id"
	optK8sTokenFile  = "auth.kubernetes.token-file"
)

// Defaults.
const (
	defaultTimeout       = 10 * time.Second
	defaultWatchInterval = 30 * time.Second
	defaultWatchBackoff  = 5 * time.Minute
	methodUniversalAuth  = "universal-auth"
	methodKubernetesAuth = "kubernetes-auth"
)

// settings is the decoded, validated configuration of one instance.
type settings struct {
	address *url.URL
	method  string
	// identityID and tokenFile configure Kubernetes Auth: the machine
	// identity to log in as, and the service account token file, read
	// again at every login.
	identityID    string
	tokenFile     string
	idRef         config.SecretRef
	secretRef     config.SecretRef
	resolve       func(context.Context, config.SecretRef) (secret.Value, error)
	timeout       time.Duration
	caPEM         []byte
	watchInterval time.Duration
	watchBackoff  time.Duration
	createFolders bool
	expandRefs    bool
}

func decodeSettings(ctx context.Context, inst stores.Instance) (*settings, error) {
	d := options.New(inst.Name, inst.Options)
	s := &settings{
		timeout:       d.Duration(optTimeout, defaultTimeout),
		watchInterval: d.Duration(optWatchInterval, defaultWatchInterval),
		watchBackoff:  d.Duration(optWatchBackoff, defaultWatchBackoff),
		createFolders: d.Bool(optCreateFolders, true),
		expandRefs:    d.Bool(optExpandRefs, true),
	}
	for key, v := range map[string]time.Duration{optTimeout: s.timeout, optWatchInterval: s.watchInterval, optWatchBackoff: s.watchBackoff} {
		if v <= 0 {
			d.Errorf("option %s must be positive", key)
		}
	}
	if addr := d.String(optAddress, ""); addr == "" {
		d.Errorf("option %s is required (for Infisical Cloud use https://app.infisical.com)", optAddress)
	} else if u, err := url.Parse(strings.TrimRight(addr, "/")); err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		d.Errorf("option %s must be an http or https URL", optAddress)
	} else {
		s.address = u
	}
	s.method = d.String(optAuthMethod, methodUniversalAuth)
	s.identityID = strings.TrimSpace(d.String(optK8sIdentityID, ""))
	s.tokenFile = d.String(optK8sTokenFile, satoken.DefaultPath)
	// The client ID is not secret on its own, but it is half of the
	// credential and the stores collection takes it as a reference too.
	idRef := d.SecretRef(optClientID)
	ref := d.SecretRef(optClientSecret)
	switch s.method {
	case methodUniversalAuth:
		if idRef == "" {
			d.Errorf("option %s is required", optClientID)
		}
		if ref == "" {
			d.Errorf("option %s is required", optClientSecret)
		}
	case methodKubernetesAuth:
		if s.identityID == "" {
			d.Errorf("option %s is required with auth.method %s", optK8sIdentityID, methodKubernetesAuth)
		}
		if s.tokenFile == "" {
			d.Errorf("option %s must not be empty", optK8sTokenFile)
		}
		// Kubernetes Auth exists so that no static credential does; one
		// configured anyway would sit unused in the cluster.
		if idRef != "" {
			d.Errorf("option %s is not used with auth.method %s; remove it", optClientID, methodKubernetesAuth)
		}
		if ref != "" {
			d.Errorf("option %s is not used with auth.method %s; remove it", optClientSecret, methodKubernetesAuth)
		}
	default:
		d.Errorf("option %s: unsupported method %q (supported: %s, %s)", optAuthMethod, s.method, methodUniversalAuth, methodKubernetesAuth)
	}
	if ca := d.String(optCAFile, ""); ca != "" {
		pem, err := os.ReadFile(ca)
		if err != nil {
			d.Errorf("option %s: %v", optCAFile, err)
		}
		s.caPEM = pem
	}
	if err := d.Finish(); err != nil {
		return nil, err
	}
	if s.method == methodUniversalAuth && inst.Resolve == nil {
		return nil, fmt.Errorf("option %s: no secret resolver configured", optClientSecret)
	}
	// Credentials are resolved at the first login, not here: building an
	// adapter (for `scrim config validate`, for instance) reads no
	// credential source and contacts nothing.
	s.idRef, s.secretRef, s.resolve = idRef, ref, inst.Resolve
	return s, nil
}

// resolveCredentials resolves the client ID and secret references. Errors
// name the option and the reference form, never a value.
func (s *settings) resolveCredentials(ctx context.Context) (string, secret.Value, error) {
	id, err := s.resolve(ctx, s.idRef)
	if err != nil {
		return "", secret.Value{}, fmt.Errorf("option %s: cannot resolve %s: %w", optClientID, s.idRef, err)
	}
	var clientID string
	_ = id.Expose(func(b []byte) error { clientID = string(b); return nil })
	id.Wipe()
	if clientID == "" {
		return "", secret.Value{}, fmt.Errorf("option %s resolved to an empty value", optClientID)
	}
	v, err := s.resolve(ctx, s.secretRef)
	if err != nil {
		return "", secret.Value{}, fmt.Errorf("option %s: cannot resolve %s: %w", optClientSecret, s.secretRef, err)
	}
	if v.IsZero() {
		v.Wipe()
		return "", secret.Value{}, fmt.Errorf("option %s resolved to an empty value", optClientSecret)
	}
	return clientID, v, nil
}
