// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"log/slog"
	"maps"
	"slices"

	pb "github.com/heliopsy/scrim/internal/dataplane/dataplanev1"
	"github.com/heliopsy/scrim/internal/redactscope"
	"github.com/heliopsy/scrim/internal/stores"
)

// redactionScopes builds the snapshot's redaction scopes from what checker
// knows: per agent with exemptions, its sessions this daemon minted (whose
// tokens are in the snapshot, so the data plane can check them) and the
// references its own store identity cannot read. Only references of entries
// in values are listed.
func redactionScopes(checker *redactscope.Checker, sessions func() map[string][]string) func([]*pb.ValueEntry) []*pb.RedactionScope {
	return func(values []*pb.ValueEntry) []*pb.RedactionScope {
		in := make([]redactscope.Value, 0, len(values))
		for _, e := range values {
			r, err := stores.ParseRef(e.GetRef())
			if err != nil {
				// "store:<name>" credentials and session tokens: always redacted.
				continue
			}
			in = append(in, redactscope.Value{Store: e.GetStore(), Ref: r})
		}
		exempt := checker.Exempt(in)
		if len(exempt) == 0 {
			return nil
		}
		live := sessions()
		var out []*pb.RedactionScope
		for _, agent := range slices.Sorted(maps.Keys(exempt)) {
			ids := slices.Sorted(slices.Values(live[agent]))
			if len(ids) == 0 {
				continue
			}
			out = append(out, &pb.RedactionScope{Agent: agent, Sessions: ids, ExemptRefs: exempt[agent]})
		}
		return out
	}
}

// warnLimitedRedaction is the start-up warning of
// redaction.limit-to-agent-identity, beyond the generic weakening warning:
// what it changes and for whom.
func warnLimitedRedaction(log *slog.Logger, reader redactscope.AgentReader, storeNames []string) {
	agents := map[string]bool{}
	for _, s := range storeNames {
		for _, a := range reader.ReadAgents(s) {
			agents[a] = true
		}
	}
	if len(agents) == 0 {
		log.Warn("weakened redaction has no effect: no store has a per-agent credential in identity.store-credentials",
			"setting", redactscope.LimitKey)
		return
	}
	log.Warn("weakened redaction: provider requests of these agents' scrim run sessions are not redacted for values their own store identity cannot read",
		"setting", redactscope.LimitKey, "agents", slices.Sorted(maps.Keys(agents)))
}
