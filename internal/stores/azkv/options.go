// SPDX-License-Identifier: AGPL-3.0-only

package azkv

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
)

// Option keys, relative to stores.<instance>.
const (
	optVaultURL      = "vault-url"
	optAuthMethod    = "auth.method"
	optTenantID      = "tenant-id"
	optClientID      = "client-id"
	optClientSecret  = "client-secret"
	optCertificate   = "certificate"
	optPassword      = "password"
	optToken         = "token"
	optTokenFile     = "auth.token-file"
	optCloud         = "cloud"
	optAuthorityHost = "authority-host"
	optFormat        = "format"
	optPathSep       = "path-separator"
	optReadOnly      = "read-only"
	optWriteOnly     = "write-only-paths"
	optTimeout       = "timeout"
	optCAFile        = "tls.ca-file"
	optWatchInterval = "watch.interval"
	optWatchBackoff  = "watch.max-backoff"
)

// Authentication methods.
const (
	methodDefault     = "default"
	methodWorkload    = "workload-identity"
	methodManaged     = "managed-identity"
	methodSecret      = "client-secret"
	methodCertificate = "client-certificate"
	methodToken       = "access-token"
)

// Value formats.
const (
	formatRaw  = "raw"
	formatJSON = "json"
)

// Defaults.
const (
	defaultTimeout       = 10 * time.Second
	defaultWatchInterval = 30 * time.Second
	defaultWatchBackoff  = 5 * time.Minute
	defaultPathSep       = "--"
)

// clouds maps the cloud option to the Microsoft Entra authority host.
var clouds = map[string]string{
	"public": "https://login.microsoftonline.com/",
	"china":  "https://login.chinacloudapi.cn/",
	"usgov":  "https://login.microsoftonline.us/",
}

// settings is the decoded, validated configuration of one instance.
type settings struct {
	vault     *url.URL
	method    string
	tenantID  string
	tokenFile string
	// authority is the Entra authority host; custom is set when it came
	// from authority-host, which turns off instance discovery.
	authority string
	custom    bool

	clientIDRef config.SecretRef
	secretRef   config.SecretRef
	certRef     config.SecretRef
	passwordRef config.SecretRef
	tokenRef    config.SecretRef
	resolve     func(context.Context, config.SecretRef) (secret.Value, error)

	format    string
	sep       string
	readOnly  bool
	writeOnly []string

	timeout       time.Duration
	caPEM         []byte
	watchInterval time.Duration
	watchBackoff  time.Duration
}

func decodeSettings(inst stores.Instance) (*settings, error) {
	d := options.New(inst.Name, inst.Options)
	s := &settings{
		method:        d.String(optAuthMethod, methodDefault),
		tenantID:      strings.TrimSpace(d.String(optTenantID, "")),
		tokenFile:     d.String(optTokenFile, ""),
		clientIDRef:   d.SecretRef(optClientID),
		secretRef:     d.SecretRef(optClientSecret),
		certRef:       d.SecretRef(optCertificate),
		passwordRef:   d.SecretRef(optPassword),
		tokenRef:      d.SecretRef(optToken),
		format:        d.String(optFormat, formatRaw),
		sep:           d.String(optPathSep, defaultPathSep),
		readOnly:      d.Bool(optReadOnly, false),
		timeout:       d.Duration(optTimeout, defaultTimeout),
		watchInterval: d.Duration(optWatchInterval, defaultWatchInterval),
		watchBackoff:  d.Duration(optWatchBackoff, defaultWatchBackoff),
		resolve:       inst.Resolve,
	}
	for key, v := range map[string]time.Duration{optTimeout: s.timeout, optWatchInterval: s.watchInterval, optWatchBackoff: s.watchBackoff} {
		if v <= 0 {
			d.Errorf("option %s must be positive", key)
		}
	}
	if raw := d.String(optVaultURL, ""); raw == "" {
		d.Errorf("option %s is required (for example https://my-vault.vault.azure.net)", optVaultURL)
	} else if u, err := url.Parse(strings.TrimRight(raw, "/")); err != nil || u.Scheme != "https" || u.Host == "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.User != nil {
		d.Errorf("option %s must be an https URL without a path, for example https://my-vault.vault.azure.net", optVaultURL)
	} else {
		u.Path = ""
		s.vault = u
	}
	cloudName := d.String(optCloud, "public")
	authority, ok := clouds[cloudName]
	if !ok {
		d.Errorf("option %s: unknown cloud %q (public, china, usgov)", optCloud, cloudName)
	}
	s.authority = authority
	if h := d.String(optAuthorityHost, ""); h != "" {
		if u, err := url.Parse(h); err != nil || u.Scheme != "https" || u.Host == "" {
			d.Errorf("option %s must be an https URL", optAuthorityHost)
		} else {
			s.authority, s.custom = strings.TrimRight(h, "/")+"/", true
		}
	}
	switch s.format {
	case formatRaw, formatJSON:
	default:
		d.Errorf("option %s: unknown format %q (raw, json)", optFormat, s.format)
	}
	if s.sep == "" || strings.Trim(s.sep, "-") != "" {
		d.Errorf("option %s must be one or more dashes (Key Vault names hold only letters, digits and dashes)", optPathSep)
	}
	for _, p := range d.Strings(optWriteOnly) {
		if p = strings.Trim(p, "/"); p != "" {
			s.writeOnly = append(s.writeOnly, p)
		}
	}
	if ca := d.String(optCAFile, ""); ca != "" {
		pem, err := os.ReadFile(ca)
		if err != nil {
			d.Errorf("option %s: %v", optCAFile, err)
		}
		s.caPEM = pem
	}
	s.checkMethod(d)
	if err := d.Finish(); err != nil {
		return nil, err
	}
	if s.needsResolve() && s.resolve == nil {
		return nil, fmt.Errorf("store %s: no secret resolver configured for the credential options", inst.Name)
	}
	return s, nil
}

// checkMethod validates which credential options go with auth.method. An
// option the method would not use is an error, so a credential is never
// configured and silently ignored.
func (s *settings) checkMethod(d *options.Decoder) {
	type use struct {
		key  string
		set  bool
		need bool
	}
	opts := func(tenant, client, secret, cert, password, token, file bool) []use {
		return []use{
			{optTenantID, s.tenantID != "", tenant},
			{optClientID, s.clientIDRef != "", client},
			{optClientSecret, s.secretRef != "", secret},
			{optCertificate, s.certRef != "", cert},
			{optPassword, s.passwordRef != "", password},
			{optToken, s.tokenRef != "", token},
			{optTokenFile, s.tokenFile != "", file},
		}
	}
	var allowed []use
	var required []string
	switch s.method {
	case methodDefault:
		// DefaultAzureCredential reads AZURE_* variables itself (a
		// user-assigned identity's AZURE_CLIENT_ID included); only the
		// tenant may be given here.
		allowed = opts(true, false, false, false, false, false, false)
	case methodWorkload:
		allowed = opts(true, true, false, false, false, false, true)
	case methodManaged:
		allowed = opts(false, true, false, false, false, false, false)
	case methodSecret:
		allowed = opts(true, true, true, false, false, false, false)
		required = []string{optTenantID, optClientID, optClientSecret}
	case methodCertificate:
		allowed = opts(true, true, false, true, true, false, false)
		required = []string{optTenantID, optClientID, optCertificate}
	case methodToken:
		allowed = opts(false, false, false, false, false, true, false)
		required = []string{optToken}
	default:
		d.Errorf("option %s: unsupported method %q (%s, %s, %s, %s, %s, %s)", optAuthMethod, s.method,
			methodDefault, methodWorkload, methodManaged, methodSecret, methodCertificate, methodToken)
		return
	}
	for _, u := range allowed {
		if u.set && !u.need {
			d.Errorf("option %s is not used with %s %s; remove it", u.key, optAuthMethod, s.method)
		}
	}
	set := map[string]bool{}
	for _, u := range allowed {
		set[u.key] = u.set
	}
	for _, k := range required {
		if !set[k] {
			d.Errorf("option %s is required with %s %s", k, optAuthMethod, s.method)
		}
	}
}

func (s *settings) needsResolve() bool {
	return s.clientIDRef != "" || s.secretRef != "" || s.certRef != "" || s.passwordRef != "" || s.tokenRef != ""
}

// resolveRef resolves one credential option. Errors name the option and
// the reference form, never a value.
func (s *settings) resolveRef(ctx context.Context, key string, ref config.SecretRef) (secret.Value, error) {
	v, err := s.resolve(ctx, ref)
	if err != nil {
		return secret.Value{}, fmt.Errorf("option %s: cannot resolve %s: %w", key, ref, err)
	}
	if v.IsZero() {
		v.Wipe()
		return secret.Value{}, fmt.Errorf("option %s resolved to an empty value", key)
	}
	return v, nil
}

// resolveString resolves a credential option that is an identifier (the
// client ID): not secret on its own, so it may become a string.
func (s *settings) resolveString(ctx context.Context, key string, ref config.SecretRef) (string, error) {
	if ref == "" {
		return "", nil
	}
	v, err := s.resolveRef(ctx, key, ref)
	if err != nil {
		return "", err
	}
	defer v.Wipe()
	var out string
	_ = v.Expose(func(b []byte) error { out = strings.TrimSpace(string(b)); return nil })
	return out, nil
}
