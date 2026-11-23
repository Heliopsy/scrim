// SPDX-License-Identifier: AGPL-3.0-only

package gcpsm

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores"
	"github.com/heliopsy/scrim/internal/stores/internal/options"
)

// Option keys, relative to stores.<instance>.
const (
	optProject       = "project"
	optLocation      = "location"
	optEndpoint      = "endpoint"
	optAuthMethod    = "auth.method"
	optCredentials   = "credentials"
	optToken         = "token"
	optImpersonate   = "auth.impersonate-service-account"
	optDelegates     = "auth.delegates"
	optFormat        = "format"
	optSeparator     = "path-separator"
	optReplicas      = "replication.locations"
	optReadOnly      = "read-only"
	optWriteOnly     = "write-only-paths"
	optTimeout       = "timeout"
	optWatchInterval = "watch.interval"
	optWatchBackoff  = "watch.max-backoff"
)

// Authentication methods.
const (
	methodADC         = "adc"
	methodCredentials = "credentials"
	methodAccessToken = "access-token"
)

// Payload formats.
const (
	formatRaw  = "raw"
	formatJSON = "json"
)

// Defaults.
const (
	defaultTimeout       = 10 * time.Second
	defaultWatchInterval = 30 * time.Second
	defaultWatchBackoff  = 5 * time.Minute
	defaultSeparator     = "--"
	globalEndpoint       = "https://secretmanager.googleapis.com"
)

var (
	// projectPattern is a project ID (6 to 30 characters) or a project
	// number.
	projectPattern  = regexp.MustCompile(`^([a-z][a-z0-9-]{4,28}[a-z0-9]|[0-9]{1,20})$`)
	locationPattern = regexp.MustCompile(`^[a-z]+(-[a-z0-9]+)+$`)
	emailPattern    = regexp.MustCompile(`^[^@\s/]+@[^@\s/]+$`)
)

// settings is the decoded, validated configuration of one instance.
type settings struct {
	project       string
	location      string // "" for global secrets
	endpoint      *url.URL
	method        string
	credRef       config.SecretRef
	tokenRef      config.SecretRef
	impersonate   string
	delegates     []string
	format        string
	sep           string
	replicas      []string
	readOnly      bool
	writeOnly     []string
	timeout       time.Duration
	watchInterval time.Duration
	watchBackoff  time.Duration
	resolve       func(context.Context, config.SecretRef) (secret.Value, error)
}

func decodeSettings(inst stores.Instance) (*settings, error) {
	d := options.New(inst.Name, inst.Options)
	s := &settings{
		project:       strings.TrimSpace(d.String(optProject, "")),
		location:      strings.TrimSpace(d.String(optLocation, "")),
		method:        d.String(optAuthMethod, methodADC),
		credRef:       d.SecretRef(optCredentials),
		tokenRef:      d.SecretRef(optToken),
		impersonate:   strings.TrimSpace(d.String(optImpersonate, "")),
		delegates:     d.Strings(optDelegates),
		format:        d.String(optFormat, formatRaw),
		sep:           d.String(optSeparator, defaultSeparator),
		replicas:      d.Strings(optReplicas),
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
	if s.project != "" && !projectPattern.MatchString(s.project) {
		d.Errorf("option %s must be a project ID or number", optProject)
	}
	if s.location != "" && (s.location == "global" || !locationPattern.MatchString(s.location)) {
		d.Errorf("option %s must be a region such as europe-west1 (leave it unset for global secrets)", optLocation)
	}
	ep := d.String(optEndpoint, "")
	switch {
	case ep != "":
		u, err := url.Parse(strings.TrimRight(ep, "/"))
		if err != nil || u.Host == "" || (u.Scheme != "https" && (u.Scheme != "http" || !loopback(u.Hostname()))) {
			d.Errorf("option %s must be an https URL (http only on a loopback address)", optEndpoint)
		} else {
			s.endpoint = u
		}
	case s.location != "":
		s.endpoint, _ = url.Parse("https://secretmanager." + s.location + ".rep.googleapis.com")
	default:
		s.endpoint, _ = url.Parse(globalEndpoint)
	}
	switch s.method {
	case methodADC:
		if s.credRef != "" || s.tokenRef != "" {
			d.Errorf("options %s and %s are not used with auth.method %s; remove them", optCredentials, optToken, methodADC)
		}
	case methodCredentials:
		if s.credRef == "" {
			d.Errorf("option %s is required with auth.method %s", optCredentials, methodCredentials)
		}
		if s.tokenRef != "" {
			d.Errorf("option %s is not used with auth.method %s; remove it", optToken, methodCredentials)
		}
	case methodAccessToken:
		if s.tokenRef == "" {
			d.Errorf("option %s is required with auth.method %s", optToken, methodAccessToken)
		}
		if s.credRef != "" || s.impersonate != "" {
			d.Errorf("options %s and %s are not used with auth.method %s; remove them", optCredentials, optImpersonate, methodAccessToken)
		}
	default:
		d.Errorf("option %s: unsupported method %q (supported: %s, %s, %s)", optAuthMethod, s.method, methodADC, methodCredentials, methodAccessToken)
	}
	if s.impersonate != "" && !emailPattern.MatchString(s.impersonate) {
		d.Errorf("option %s must be a service account email", optImpersonate)
	}
	for _, dl := range s.delegates {
		if !emailPattern.MatchString(dl) {
			d.Errorf("option %s must list service account emails", optDelegates)
			break
		}
	}
	if len(s.delegates) > 0 && s.impersonate == "" {
		d.Errorf("option %s needs %s", optDelegates, optImpersonate)
	}
	if s.format != formatRaw && s.format != formatJSON {
		d.Errorf("option %s must be %s or %s", optFormat, formatRaw, formatJSON)
	}
	if s.sep == "" || strings.Trim(s.sep, "-_") != "" || strings.Contains(s.sep, "/") {
		d.Errorf("option %s must be made of '-' and '_' (default %s)", optSeparator, defaultSeparator)
	}
	if len(s.replicas) > 0 && s.location != "" {
		d.Errorf("option %s does not apply to regional secrets (%s is set)", optReplicas, optLocation)
	}
	for _, r := range s.replicas {
		if !locationPattern.MatchString(r) {
			d.Errorf("option %s must list regions such as europe-west1", optReplicas)
			break
		}
	}
	for _, p := range d.Strings(optWriteOnly) {
		if p = strings.Trim(p, "/"); p != "" {
			s.writeOnly = append(s.writeOnly, p)
		}
	}
	if err := d.Finish(); err != nil {
		return nil, err
	}
	if (s.credRef != "" || s.tokenRef != "") && s.resolve == nil {
		return nil, fmt.Errorf("store %s: no secret resolver configured", inst.Name)
	}
	return s, nil
}

func loopback(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}
