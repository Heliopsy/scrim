// SPDX-License-Identifier: AGPL-3.0-only

package aws

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

// Option keys, relative to stores.<instance>. Both kinds share every key
// except the write settings marked below.
const (
	optRegion          = "region"
	optProfile         = "profile"
	optEndpoint        = "endpoint"
	optFIPS            = "fips"
	optAccessKeyID     = "access-key-id"
	optSecretAccessKey = "secret-access-key"
	optRoleARN         = "assume-role.arn"
	optExternalID      = "assume-role.external-id"
	optSessionName     = "assume-role.session-name"
	optRoleDuration    = "assume-role.duration"
	optSTSEndpoint     = "assume-role.sts-endpoint"
	optTimeout         = "timeout"
	optMaxAttempts     = "max-attempts"
	optWatchInterval   = "watch.interval"
	optWatchBackoff    = "watch.max-backoff"
	optKMSKey          = "kms-key-id"
	// awssm only.
	optCreateSecrets = "create-secrets"
	// ssm only.
	optParamType = "parameter-type"
	optTier      = "tier"
)

// Defaults.
const (
	defaultTimeout       = 10 * time.Second
	defaultMaxAttempts   = 3
	defaultWatchInterval = 30 * time.Second
	defaultWatchBackoff  = 5 * time.Minute
	defaultSessionName   = "scrim"
)

// settings is the decoded, validated configuration of one instance.
type settings struct {
	region        string
	profile       string
	endpoint      *url.URL
	fips          bool
	keyIDRef      config.SecretRef
	secretKeyRef  config.SecretRef
	roleARN       string
	externalID    string
	sessionName   string
	roleDuration  time.Duration
	stsEndpoint   string
	timeout       time.Duration
	maxAttempts   int
	watchInterval time.Duration
	watchBackoff  time.Duration
	kmsKey        string
	createSecrets bool
	paramType     string
	tier          string
	resolve       func(context.Context, config.SecretRef) (secret.Value, error)
}

var (
	regionPattern  = regexp.MustCompile(`^[a-z]{2}(-[a-z]+)+-\d+$`)
	roleARNPattern = regexp.MustCompile(`^arn:aws[a-z-]*:iam::\d{12}:role/.+$`)
	// sessionPattern is STS's RoleSessionName constraint.
	sessionPattern = regexp.MustCompile(`^[\w+=,.@-]{2,64}$`)
)

func decodeSettings(inst stores.Instance, kind string) (*settings, error) {
	d := options.New(inst.Name, inst.Options)
	s := &settings{
		region:        strings.TrimSpace(d.String(optRegion, "")),
		profile:       strings.TrimSpace(d.String(optProfile, "")),
		fips:          d.Bool(optFIPS, false),
		keyIDRef:      d.SecretRef(optAccessKeyID),
		secretKeyRef:  d.SecretRef(optSecretAccessKey),
		roleARN:       strings.TrimSpace(d.String(optRoleARN, "")),
		externalID:    d.String(optExternalID, ""),
		sessionName:   d.String(optSessionName, defaultSessionName),
		roleDuration:  d.Duration(optRoleDuration, 0),
		stsEndpoint:   d.String(optSTSEndpoint, ""),
		timeout:       d.Duration(optTimeout, defaultTimeout),
		maxAttempts:   int(d.Int(optMaxAttempts, defaultMaxAttempts)),
		watchInterval: d.Duration(optWatchInterval, defaultWatchInterval),
		watchBackoff:  d.Duration(optWatchBackoff, defaultWatchBackoff),
		kmsKey:        strings.TrimSpace(d.String(optKMSKey, "")),
		resolve:       inst.Resolve,
	}
	switch kind {
	case KindSecretsManager:
		s.createSecrets = d.Bool(optCreateSecrets, true)
	case KindParameterStore:
		s.paramType = d.String(optParamType, "SecureString")
		s.tier = d.String(optTier, "")
		switch s.paramType {
		case "SecureString", "String":
		default:
			d.Errorf("option %s must be SecureString or String", optParamType)
		}
		switch s.tier {
		case "", "Standard", "Advanced", "Intelligent-Tiering":
		default:
			d.Errorf("option %s must be Standard, Advanced or Intelligent-Tiering", optTier)
		}
		if s.kmsKey != "" && s.paramType != "SecureString" {
			d.Errorf("option %s only applies to parameter-type SecureString", optKMSKey)
		}
	}
	for key, v := range map[string]time.Duration{optTimeout: s.timeout, optWatchInterval: s.watchInterval, optWatchBackoff: s.watchBackoff} {
		if v <= 0 {
			d.Errorf("option %s must be positive", key)
		}
	}
	if s.maxAttempts < 1 || s.maxAttempts > 10 {
		d.Errorf("option %s must be between 1 and 10", optMaxAttempts)
	}
	if s.region != "" && !regionPattern.MatchString(s.region) {
		d.Errorf("option %s must be an AWS region such as eu-west-1", optRegion)
	}
	if e := d.String(optEndpoint, ""); e != "" {
		u, err := parseEndpoint(e)
		if err != nil {
			d.Errorf("option %s %v", optEndpoint, err)
		}
		s.endpoint = u
		if s.fips {
			d.Errorf("option %s and option %s exclude each other; name the FIPS endpoint itself", optFIPS, optEndpoint)
		}
	}
	if s.stsEndpoint != "" {
		if _, err := parseEndpoint(s.stsEndpoint); err != nil {
			d.Errorf("option %s %v", optSTSEndpoint, err)
		}
	}
	if (s.keyIDRef == "") != (s.secretKeyRef == "") {
		d.Errorf("options %s and %s go together", optAccessKeyID, optSecretAccessKey)
	}
	if s.keyIDRef != "" && s.profile != "" {
		d.Errorf("option %s and static keys exclude each other", optProfile)
	}
	if s.roleARN != "" {
		if !roleARNPattern.MatchString(s.roleARN) {
			d.Errorf("option %s must be an IAM role ARN (arn:aws:iam::<account>:role/<name>)", optRoleARN)
		}
		if !sessionPattern.MatchString(s.sessionName) {
			d.Errorf("option %s must be 2 to 64 letters, digits or +=,.@_-", optSessionName)
		}
		if s.roleDuration != 0 && (s.roleDuration < 15*time.Minute || s.roleDuration > 12*time.Hour) {
			d.Errorf("option %s must be between 15m and 12h", optRoleDuration)
		}
	} else if s.externalID != "" || s.roleDuration != 0 || s.stsEndpoint != "" {
		d.Errorf("options assume-role.* need %s", optRoleARN)
	}
	if err := d.Finish(); err != nil {
		return nil, err
	}
	if s.keyIDRef != "" && s.resolve == nil {
		return nil, fmt.Errorf("option %s: no secret resolver configured", optSecretAccessKey)
	}
	return s, nil
}

func parseEndpoint(e string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimRight(e, "/"))
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" {
		return nil, fmt.Errorf("must be an http or https URL without a path")
	}
	u.Path = ""
	return u, nil
}
