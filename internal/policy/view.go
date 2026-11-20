// SPDX-License-Identifier: AGPL-3.0-only

package policy

import "time"

// The types below are the view of a [Request] that CEL rules see. They are
// separate from Request so the rule language has stable, documented,
// lower-case field names (docs/policy.md) whatever the Go structs look like.

// RuleAgent is `agent` in a rule.
type RuleAgent struct {
	// ID is the stable identity key, for example `k8s:agents/reviewer`.
	ID string `cel:"id" json:"id,omitempty"`
	// Kind is how the identity was established: peer, session, k8s, mtls,
	// or empty for unknown callers.
	Kind string `cel:"kind" json:"kind,omitempty"`
	// Known is false for callers whose identity could not be established.
	Known bool `cel:"known" json:"known,omitempty"`
	// Session is the scrim session ID, if any.
	Session string `cel:"session" json:"session,omitempty"`
	// Labels are identity attributes: namespace, service_account, pod,
	// user, uid, spiffe_id, profile and operator-assigned labels.
	Labels map[string]string `cel:"labels" json:"labels,omitempty"`
}

// RuleSecret is `secret` in a rule.
type RuleSecret struct {
	// Ref is the canonical reference string, `bao://kv/agents/github`.
	Ref string `cel:"ref" json:"ref,omitempty"`
	// Name is the catalog name, if any.
	Name string `cel:"name" json:"name,omitempty"`
	// Store is the store instance name.
	Store string `cel:"store" json:"store,omitempty"`
	// Class is the catalog class.
	Class string `cel:"class" json:"class,omitempty"`
	// Labels are catalog or store metadata labels.
	Labels map[string]string `cel:"labels" json:"labels,omitempty"`
}

// RuleDest is `dest` in a rule.
type RuleDest struct {
	Host   string `cel:"host" json:"host,omitempty"`
	Method string `cel:"method" json:"method,omitempty"`
	Path   string `cel:"path" json:"path,omitempty"`
}

// RuleTool is `tool` in a rule.
type RuleTool struct {
	Name    string `cel:"name" json:"name,omitempty"`
	Command string `cel:"command" json:"command,omitempty"`
}

// view is the rule-facing form of a request.
type view struct {
	op       string
	agent    RuleAgent
	secret   RuleSecret
	provider string
	dest     RuleDest
	tool     RuleTool
	now      time.Time
}

func newView(r *Request) view {
	v := view{
		op: string(r.Action),
		agent: RuleAgent{
			ID: r.Agent.ID, Kind: string(r.Agent.Kind), Known: r.Agent.Kind != IdentityUnknown,
			Session: r.Agent.Session, Labels: r.Agent.Labels,
		},
		secret: RuleSecret{
			Name: r.Name, Store: r.Store, Class: r.SecretClass, Labels: r.SecretLabels,
		},
		provider: r.Provider,
		dest:     RuleDest{Host: r.Host, Method: r.Method, Path: r.Path},
		tool:     RuleTool{Name: r.Tool, Command: r.Command},
		now:      r.Time,
	}
	if !r.Ref.IsZero() {
		v.secret.Ref = r.Ref.String()
	}
	if v.now.IsZero() {
		v.now = time.Now()
	}
	return v
}

func (v *view) activation() map[string]any {
	return map[string]any{
		"op":       v.op,
		"agent":    v.agent,
		"secret":   v.secret,
		"provider": v.provider,
		"dest":     v.dest,
		"tool":     v.tool,
		"now":      v.now,
	}
}
