// SPDX-License-Identifier: AGPL-3.0-only

package cli

import (
	"context"
	"fmt"
	"strings"

	"github.com/heliopsy/scrim/internal/agentstore"
	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/daemon"
	"github.com/heliopsy/scrim/internal/redactscope"
	"github.com/heliopsy/scrim/internal/status"
)

// redactionIdentityChecks report whose identity loads the redaction set
// (specs/agent-identity "Redaction coverage is separate from use"). They
// read configuration only and never resolve a credential.
func redactionIdentityChecks(cfg *config.Config) []status.Check {
	const name = "redaction: identity"
	return []status.Check{
		{Name: name, Run: func(context.Context) []status.Finding { return redactionIdentityFindings(cfg) }},
		{Name: "redaction: detectors", Run: func(context.Context) []status.Finding {
			f := daemon.DetectorFinding(cfg)
			f.Check = "redaction: detectors"
			return []status.Finding{f}
		}},
		{Name: "redaction: guard transforms", Run: func(context.Context) []status.Finding {
			f := daemon.GuardTransformFinding(cfg)
			f.Check = "redaction: guard transforms"
			return []status.Finding{f}
		}},
	}
}

func redactionIdentityFindings(cfg *config.Config) []status.Finding {
	const check = "redaction: identity"
	if !redactscope.LimitToAgentIdentity.Get(cfg) {
		return []status.Finding{{Check: check, Outcome: status.Pass,
			Message: "the redaction set is loaded with each store's own credentials and covers values an agent cannot use"}}
	}
	c, err := agentstore.New(agentstore.Options{Login: agentstore.Login.Get(cfg), Credentials: agentstore.Credentials.Get(cfg)})
	if err != nil {
		return []status.Finding{{Check: check, Outcome: status.Fail, Message: err.Error(),
			Fix: "fix identity.store-login or identity.store-credentials"}}
	}
	var out []status.Finding
	for _, store := range c.Governed() {
		agents := c.ReadAgents(store)
		if len(agents) == 0 {
			continue
		}
		out = append(out, status.Finding{Check: check, Outcome: status.Warn,
			Message: fmt.Sprintf("weakened (%s): store %s: provider requests of the scrim run sessions of %s are not redacted for values their own credential cannot read",
				redactscope.LimitKey, store, strings.Join(agents, ", ")),
			Fix: "turn off " + redactscope.LimitKey + " so every value is redacted for every agent"})
	}
	if len(out) == 0 {
		out = append(out, status.Finding{Check: check, Outcome: status.Warn,
			Message: redactscope.LimitKey + " is on but has no effect: no store has a per-agent credential in identity.store-credentials",
			Fix:     "turn off " + redactscope.LimitKey})
	}
	return out
}
