// SPDX-License-Identifier: AGPL-3.0-only

package identity

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// RulesFromMap turns the identity.peers setting into rules. Each key is an
// agent name and each value a space-separated list of selectors:
// uid:<n>, user:<name>, gid:<n>, group:<name>, scope:<scope> and
// label:<key>=<value>. For example
//
//	identity.peers:
//	  claude: "user:agent1"
//	  ci: "group:ci-agents scope:secrets:list label:team=infra"
//
// An empty map yields DefaultPeerRules.
func RulesFromMap(m map[string]string) ([]PeerRule, error) {
	if len(m) == 0 {
		return DefaultPeerRules(), nil
	}
	names := make([]string, 0, len(m))
	for k := range m {
		names = append(names, k)
	}
	slices.Sort(names)
	rules := make([]PeerRule, 0, len(m))
	for _, agent := range names {
		r := PeerRule{Agent: agent}
		for sel := range strings.FieldsSeq(m[agent]) {
			kind, val, ok := strings.Cut(sel, ":")
			if !ok || val == "" {
				return nil, fmt.Errorf("identity.peers.%s: selector %q is not kind:value", agent, sel)
			}
			switch kind {
			case "uid", "gid":
				n, err := strconv.ParseUint(val, 10, 32)
				if err != nil {
					return nil, fmt.Errorf("identity.peers.%s: %s %q is not a number", agent, kind, val)
				}
				if kind == "uid" {
					r.UIDs = append(r.UIDs, uint32(n))
				} else {
					r.GIDs = append(r.GIDs, uint32(n))
				}
			case "user":
				r.Users = append(r.Users, val)
			case "group":
				r.Groups = append(r.Groups, val)
			case "scope":
				r.Scopes = append(r.Scopes, Scope(val))
			case "label":
				k, v, ok := strings.Cut(val, "=")
				if !ok || k == "" {
					return nil, fmt.Errorf("identity.peers.%s: label %q is not key=value", agent, val)
				}
				if r.Labels == nil {
					r.Labels = map[string]string{}
				}
				r.Labels[k] = v
			default:
				return nil, fmt.Errorf("identity.peers.%s: unknown selector kind %q", agent, kind)
			}
		}
		rules = append(rules, r)
	}
	return rules, nil
}
