// SPDX-License-Identifier: AGPL-3.0-only

package policy

import "github.com/heliopsy/scrim/internal/config"

// Settings owned by this package.
var (
	// DefaultEffect is the decision when no rule matches. Anything but deny
	// weakens the default-deny invariant.
	DefaultEffect = config.Register(config.Spec[string]{
		Key:         "policy.default",
		Default:     "deny",
		Enum:        []string{"deny", "ask", "allow"},
		Description: "Decision applied when no rule matches. Anything other than deny is reported as a weakened protection.",
		Weakening:   true,
	})
)
