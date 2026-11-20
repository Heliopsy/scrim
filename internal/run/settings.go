// SPDX-License-Identifier: AGPL-3.0-only

package run

import (
	"strings"

	"github.com/heliopsy/scrim/internal/config"
)

// Settings owned by scrim run.
var (
	// AllowUnredactedStart starts the agent without scrim when scrim cannot
	// serve it. It weakens fail-closed start-up.
	AllowUnredactedStart = config.Register(config.Spec[bool]{
		Key: "run.allow-unredacted-start",
		Description: "Start the agent anyway when scrim cannot start, its data plane is not ready or no session can be minted. " +
			"The agent then reaches providers directly and unredacted; scrim run prints a warning.",
		Flag:      true,
		Weakening: true,
	})

	// MCP registers `scrim mcp` with agents that support it.
	MCP = config.Register(config.Spec[bool]{
		Key:         "run.mcp",
		Default:     true,
		Description: "Register scrim mcp with the agent for this session (Claude Code --mcp-config, Codex -c mcp_servers.scrim). Nothing is written to the agent's own configuration.",
		Flag:        true,
	})

	// PlaceholderEnv exports declared catalog placeholders.
	PlaceholderEnv = config.Register(config.Spec[bool]{
		Key:         "run.placeholder-env",
		Default:     true,
		Description: "Export each declared catalog placeholder that resolves for the session as an environment variable of the same name holding the placeholder, for example SCRIM_ACME_KEY=SCRIM_ACME_KEY.",
		Flag:        true,
	})
)

// ReservedBy returns a check for names scrim reads itself: settings,
// collection fields and its own variables. A placeholder with such a name
// is not exported, so it cannot change scrim's configuration inside the
// session.
func ReservedBy(r *config.Registry) func(string) bool {
	var prefixes []string
	for _, c := range r.Collections() {
		prefixes = append(prefixes, config.EnvVar(c.Key))
	}
	own := map[string]bool{"SCRIM_CONFIG": true, "SCRIM_DP_FD": true, EnvSessionID: true}
	return func(name string) bool {
		if own[name] {
			return true
		}
		if _, ok := r.LookupEnv(name); ok {
			return true
		}
		for _, p := range prefixes {
			if name == p || strings.HasPrefix(name, p+"_") {
				return true
			}
		}
		return false
	}
}
