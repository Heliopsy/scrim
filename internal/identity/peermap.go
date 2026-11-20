// SPDX-License-Identifier: AGPL-3.0-only

package identity

import (
	"errors"
	"fmt"
	"maps"
	"os"
	"os/user"
	"regexp"
	"slices"
	"strconv"
)

// PeerRule maps local users or groups to one agent. It is the configuration
// shape of `identity.peers`.
type PeerRule struct {
	// Agent is the agent name the matching callers get.
	Agent string `json:"agent" yaml:"agent"`
	// UIDs and Users match the peer's user ID.
	UIDs  []uint32 `json:"uids,omitempty" yaml:"uids,omitempty"`
	Users []string `json:"users,omitempty" yaml:"users,omitempty"`
	// GIDs and Groups match the peer's primary group ID.
	GIDs   []uint32 `json:"gids,omitempty" yaml:"gids,omitempty"`
	Groups []string `json:"groups,omitempty" yaml:"groups,omitempty"`
	// Scopes limit what the agent may do. Empty means every scope.
	Scopes []Scope `json:"scopes,omitempty" yaml:"scopes,omitempty"`
	// Labels are attributes policy can match on.
	Labels map[string]string `json:"labels,omitempty" yaml:"labels,omitempty"`
}

// Accounts resolves user and group names. The default reads the system's
// user database; tests substitute a fixed table.
type Accounts interface {
	UserID(name string) (uint32, error)
	GroupID(name string) (uint32, error)
}

// SystemAccounts resolves names through os/user.
type SystemAccounts struct{}

// UserID looks up a user name.
func (SystemAccounts) UserID(name string) (uint32, error) {
	u, err := user.Lookup(name)
	if err != nil {
		return 0, err
	}
	return parseID(u.Uid)
}

// GroupID looks up a group name.
func (SystemAccounts) GroupID(name string) (uint32, error) {
	g, err := user.LookupGroup(name)
	if err != nil {
		return 0, err
	}
	return parseID(g.Gid)
}

func parseID(s string) (uint32, error) {
	n, err := strconv.ParseUint(s, 10, 32)
	return uint32(n), err
}

// agentName is the shape of an agent name: it appears in principals, audit
// entries and policy, so it is kept to a plain, unambiguous alphabet.
var agentName = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)

// ValidAgentName reports whether s can name an agent.
func ValidAgentName(s string) bool { return agentName.MatchString(s) }

// PeerMap maps peer credentials to agent identities. A user ID match wins
// over a group match; within each, configuration that maps one ID to two
// agents is rejected when the map is built.
type PeerMap struct {
	byUID map[uint32]*PeerRule
	byGID map[uint32]*PeerRule
}

// NewPeerMap compiles rules, resolving user and group names through acc.
func NewPeerMap(rules []PeerRule, acc Accounts) (*PeerMap, error) {
	if acc == nil {
		acc = SystemAccounts{}
	}
	m := &PeerMap{byUID: map[uint32]*PeerRule{}, byGID: map[uint32]*PeerRule{}}
	var errs []error
	for i := range rules {
		r := rules[i]
		r.UIDs, r.GIDs = slices.Clone(r.UIDs), slices.Clone(r.GIDs)
		r.Scopes, r.Labels = slices.Clone(r.Scopes), maps.Clone(r.Labels)
		where := fmt.Sprintf("identity.peers[%d]", i)
		if !ValidAgentName(r.Agent) {
			errs = append(errs, fmt.Errorf("%s: agent %q must match %s", where, r.Agent, agentName))
		}
		for _, s := range r.Scopes {
			if !ValidScope(s) {
				errs = append(errs, fmt.Errorf("%s: unknown scope %q", where, s))
			}
		}
		if len(r.Scopes) == 0 {
			r.Scopes = slices.Clone(AllScopes)
		}
		for _, name := range r.Users {
			id, err := acc.UserID(name)
			if err != nil {
				errs = append(errs, fmt.Errorf("%s: user %q: %w", where, name, err))
				continue
			}
			r.UIDs = append(r.UIDs, id)
		}
		for _, name := range r.Groups {
			id, err := acc.GroupID(name)
			if err != nil {
				errs = append(errs, fmt.Errorf("%s: group %q: %w", where, name, err))
				continue
			}
			r.GIDs = append(r.GIDs, id)
		}
		if len(r.UIDs) == 0 && len(r.GIDs) == 0 {
			errs = append(errs, fmt.Errorf("%s: agent %q matches no user or group", where, r.Agent))
		}
		rule := &r
		errs = append(errs, claim(m.byUID, r.UIDs, rule, where, "uid")...)
		errs = append(errs, claim(m.byGID, r.GIDs, rule, where, "gid")...)
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	return m, nil
}

func claim(idx map[uint32]*PeerRule, ids []uint32, r *PeerRule, where, kind string) []error {
	var errs []error
	for _, id := range ids {
		if prev, ok := idx[id]; ok && prev.Agent != r.Agent {
			errs = append(errs, fmt.Errorf("%s: %s %d is already mapped to agent %q", where, kind, id, prev.Agent))
			continue
		}
		idx[id] = r
	}
	return errs
}

// Lookup returns the identity for a peer, or false when no rule matches.
func (m *PeerMap) Lookup(p Peer) (Identity, bool) {
	if m == nil {
		return Unknown(p), false
	}
	r, ok := m.byUID[p.UID]
	if !ok {
		r, ok = m.byGID[p.GID]
	}
	if !ok {
		return Unknown(p), false
	}
	return Identity{
		Agent:  r.Agent,
		Source: SourcePeer,
		Peer:   p,
		Scopes: slices.Clone(r.Scopes),
		Labels: maps.Clone(r.Labels),
	}, true
}

// DefaultPeerRules is the mapping used when none is configured: the user
// scrim runs as is one agent named after that user. Every other local user
// is unknown and denied.
func DefaultPeerRules() []PeerRule {
	uid := uint32(os.Getuid()) // #nosec G115 -- uid_t is 32 bits
	name := "local"
	if u, err := user.LookupId(strconv.FormatUint(uint64(uid), 10)); err == nil && ValidAgentName(u.Username) {
		name = u.Username
	}
	return []PeerRule{{Agent: name, UIDs: []uint32{uid}}}
}
