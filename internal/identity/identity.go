// SPDX-License-Identifier: AGPL-3.0-only

// Package identity establishes which agent is behind a local call.
//
// A local caller is identified only by its transport, never by anything it
// claims in a request: the operating system's peer credentials on the Unix
// socket ([PeerOf]), mapped to an agent through configuration ([PeerMap]),
// and optionally a session token minted for one `scrim run` invocation
// ([Manager]). A session token is bound to the peer user and to the process
// tree it was minted for, so a process outside that tree cannot use it even
// when it reads the token from another process's environment.
//
// The [Identity] a [Resolver] returns is what policy, grants, approvals and
// audit key on. Its [Identity.Principal] separates two sessions of the same
// agent, so their grants never mix.
package identity

import (
	"maps"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/heliopsy/scrim/internal/policy"
)

// Source says how an identity was established.
type Source string

// The sources a local identity can come from.
const (
	// SourceUnknown is a caller whose identity could not be established.
	SourceUnknown Source = "unknown"
	// SourcePeer is a caller identified by its socket peer credentials alone.
	SourcePeer Source = "peer"
	// SourceSession is a caller that presented a valid session token from a
	// matching peer.
	SourceSession Source = "session"
)

// Scope names one class of agent tool a caller may use.
type Scope string

// The scopes an identity can hold. A session carries a subset of the scopes
// of the peer that minted it.
const (
	// ScopeSecretsList allows secrets_list.
	ScopeSecretsList Scope = "secrets:list"
	// ScopeSecretsRequest allows secret_request, approval_status and grants_list.
	ScopeSecretsRequest Scope = "secrets:request"
	// ScopeSecretsWrite allows secret_gen, secret_capture, secret_ask_human and
	// secret put.
	ScopeSecretsWrite Scope = "secrets:write"
	// ScopeSessionsMint allows minting session tokens. Sessions never hold it.
	ScopeSessionsMint Scope = "sessions:mint"
)

// AgentScopes are the scopes an agent tool caller needs for every tool.
var AgentScopes = []Scope{ScopeSecretsList, ScopeSecretsRequest, ScopeSecretsWrite}

// AllScopes are every scope a peer identity can hold.
var AllScopes = append(slices.Clone(AgentScopes), ScopeSessionsMint)

// ValidScope reports whether s is a known scope.
func ValidScope(s Scope) bool { return slices.Contains(AllScopes, s) }

// Peer is what the operating system reports about the other end of a Unix
// socket. PID is 0 when the platform cannot report it.
type Peer struct {
	UID uint32 `json:"uid"`
	GID uint32 `json:"gid"`
	PID int32  `json:"pid,omitempty"`
}

// Identity is a resolved caller.
type Identity struct {
	// Agent is the configured agent name, empty for an unknown caller.
	Agent string `json:"agent,omitempty"`
	// Source says how the identity was established.
	Source Source `json:"source"`
	// Peer is the transport the caller arrived on.
	Peer Peer `json:"peer"`
	// SessionID is the public identifier of the session token, never the
	// token itself. Empty unless Source is SourceSession.
	SessionID string `json:"session_id,omitempty"`
	// SessionName is the optional label `scrim run` gave the session.
	SessionName string `json:"session_name,omitempty"`
	// ExpiresAt is when the session token expires, zero for peer identities.
	ExpiresAt time.Time `json:"expires_at,omitzero"`
	// Scopes are what the caller may do.
	Scopes []Scope `json:"scopes,omitempty"`
	// Labels are configured attributes policy can match on.
	Labels map[string]string `json:"labels,omitempty"`
}

// Unknown returns the identity of a caller that could not be identified.
func Unknown(p Peer) Identity { return Identity{Source: SourceUnknown, Peer: p} }

// Known reports whether the caller was identified.
func (i Identity) Known() bool { return i.Source != SourceUnknown && i.Agent != "" }

// Has reports whether the identity holds scope s.
func (i Identity) Has(s Scope) bool { return i.Known() && slices.Contains(i.Scopes, s) }

// Principal is the key grants, approvals and asks are owned by. Two sessions
// of one agent have different principals, and neither shares one with the
// agent's peer identity, so none of them can use or see another's grants.
func (i Identity) Principal() string {
	switch {
	case !i.Known():
		return ""
	case i.Source == SourceSession:
		return i.Agent + "/" + i.SessionID
	case i.Source == SourceKubernetes:
		// Derived agent names hold a slash; the prefix keeps them apart
		// from a session principal.
		return "k8s:" + i.Agent
	case i.Source == SourceCertificate:
		// Derived agent names hold slashes too.
		return "mtls:" + i.Agent
	default:
		return i.Agent
	}
}

// String is a short, value-free description for logs and audit.
func (i Identity) String() string {
	if !i.Known() {
		return "unknown(uid=" + strconv.FormatUint(uint64(i.Peer.UID), 10) + ")"
	}
	var b strings.Builder
	b.WriteString(i.Principal())
	b.WriteString(" (")
	b.WriteString(string(i.Source))
	b.WriteString(")")
	return b.String()
}

// PolicyAgent is the identity as policy rules, grants and audit see it. The
// session ID is carried separately, so rules can match the agent name while
// grants and approvals stay owned by one session.
func (i Identity) PolicyAgent() policy.Agent {
	kind := policy.IdentityUnknown
	switch i.Source {
	case SourcePeer:
		kind = policy.IdentityPeer
	case SourceSession:
		kind = policy.IdentitySession
	case SourceKubernetes:
		kind = policy.IdentityK8s
	case SourceCertificate:
		kind = policy.IdentityMTLS
	}
	if !i.Known() {
		kind = policy.IdentityUnknown
	}
	labels := maps.Clone(i.Labels)
	if labels == nil {
		labels = map[string]string{}
	}
	if i.Source != SourceKubernetes && i.Source != SourceCertificate {
		labels["uid"] = strconv.FormatUint(uint64(i.Peer.UID), 10)
	}
	if i.SessionName != "" {
		labels["session_name"] = i.SessionName
	}
	a := policy.Agent{ID: i.Agent, Kind: kind, Session: i.SessionID, Labels: labels}
	if kind == policy.IdentityUnknown {
		a.ID, a.Session = "", ""
	}
	return a
}
