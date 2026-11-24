// SPDX-License-Identifier: AGPL-3.0-only

package ca

import (
	"fmt"
	"time"

	"github.com/heliopsy/scrim/internal/config"
)

// Settings of the interception CA.
var (
	DirSetting = config.Register(config.Spec[string]{
		Key:     "tool-proxy.ca.dir",
		Default: "",
		Description: "Directory of the generated interception CA (certificates, private keys, rotation state, trust manifest). " +
			"Empty means $XDG_STATE_HOME/scrim/ca (~/.local/state/scrim/ca). Created with mode 0700.",
		RestartRequired: true,
	})
	CertFileSetting = config.Register(config.Spec[string]{
		Key:     "tool-proxy.ca.cert-file",
		Default: "",
		Description: "PEM certificate of an operator-supplied interception CA, used together with tool-proxy.ca.key. " +
			"An operator-supplied CA is never rotated by scrim; a warning is logged once it is within tool-proxy.ca.rotate-before of expiry.",
		RestartRequired: true,
	})
	KeySetting = config.Register(config.Spec[config.SecretRef]{
		Key:     "tool-proxy.ca.key",
		Default: "",
		Description: "Reference to the PKCS#8 PEM private key of the operator-supplied CA in tool-proxy.ca.cert-file " +
			"(env:, file:, cred: or a store reference). Empty means scrim generates and rotates its own CA.",
		RequireReference: true,
		RestartRequired:  true,
	})
	ValiditySetting = config.Register(config.Spec[time.Duration]{
		Key:             "tool-proxy.ca.validity",
		Default:         17520 * time.Hour,
		Description:     "Validity of each generated CA certificate.",
		Validate:        atLeast("tool-proxy.ca.validity", 48*time.Hour),
		RestartRequired: true,
	})
	RotateBeforeSetting = config.Register(config.Spec[time.Duration]{
		Key:     "tool-proxy.ca.rotate-before",
		Default: 30 * 24 * time.Hour,
		Description: "A generated CA is rotated when less than this much of its validity remains. " +
			"For an operator-supplied CA it is how early the expiry warning starts.",
		Validate:        atLeast("tool-proxy.ca.rotate-before", time.Hour),
		RestartRequired: true,
	})
	OverlapSetting = config.Register(config.Spec[time.Duration]{
		Key:     "tool-proxy.ca.overlap",
		Default: 7 * 24 * time.Hour,
		Description: "After a rotation, how long the previous CA stays trusted through a cross certificate and in the trust bundle. " +
			"Capped at the previous certificate's expiry.",
		Validate:        atLeast("tool-proxy.ca.overlap", 0),
		RestartRequired: true,
	})
)

func atLeast(key string, minimum time.Duration) func(time.Duration) error {
	return func(d time.Duration) error {
		if d < minimum {
			return fmt.Errorf("%s must be at least %s", key, minimum)
		}
		return nil
	}
}

// policy is the rotation policy read from the configuration.
type policy struct {
	validity, rotateBefore, overlap time.Duration
}

func policyFrom(cfg *config.Config) (policy, error) {
	p := policy{validity: ValiditySetting.Get(cfg), rotateBefore: RotateBeforeSetting.Get(cfg), overlap: OverlapSetting.Get(cfg)}
	if p.rotateBefore*2 > p.validity {
		return p, fmt.Errorf("%s (%s) must be at most half of %s (%s)",
			RotateBeforeSetting.Name(), p.rotateBefore, ValiditySetting.Name(), p.validity)
	}
	return p, nil
}

// Settings of the edge CA, which issues only the edge listener's certificate
// (specs/credential-injection "Edge channel identifies the pod"). Its
// rotation policy is the interception CA's (tool-proxy.ca.validity,
// rotate-before and overlap).
var (
	EdgeDirSetting = config.Register(config.Spec[string]{
		Key:     "edge.ca.dir",
		Default: "",
		Description: "Directory of the generated edge CA, which issues only the edge listener's certificate. " +
			"Empty means $XDG_STATE_HOME/scrim/edge-ca (~/.local/state/scrim/edge-ca). Created with mode 0700. " +
			"Never the interception CA's directory.",
		RestartRequired: true,
	})
	EdgeCertFileSetting = config.Register(config.Spec[string]{
		Key:     "edge.ca.cert-file",
		Default: "",
		Description: "PEM certificate of an operator-supplied edge CA, used together with edge.ca.key. It must have its own " +
			"key, not the interception CA's, and its name constraints, if any, must allow edge.server-names. Never rotated by scrim.",
		RestartRequired: true,
	})
	EdgeKeySetting = config.Register(config.Spec[config.SecretRef]{
		Key:     "edge.ca.key",
		Default: "",
		Description: "Reference to the PKCS#8 PEM private key of the operator-supplied edge CA in edge.ca.cert-file " +
			"(env:, file:, cred: or a store reference). Empty means scrim generates and rotates its own edge CA.",
		RequireReference: true,
		RestartRequired:  true,
	})
)
