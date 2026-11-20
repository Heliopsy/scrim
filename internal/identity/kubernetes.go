// SPDX-License-Identifier: AGPL-3.0-only

package identity

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"path"
	"slices"
	"strings"

	"github.com/heliopsy/scrim/internal/identity/kube"
)

// SourceKubernetes is a caller that presented a projected Kubernetes service
// account token with scrim's audience, verified by the cluster.
const SourceKubernetes Source = "kubernetes"

// Labels a Kubernetes identity carries, as policy sees them
// (`agent.labels.namespace` and so on).
const (
	LabelNamespace      = "namespace"
	LabelServiceAccount = "service_account"
	LabelPod            = "pod"
	LabelPodUID         = "pod_uid"
)

// What to do with a verified service account no identity.kubernetes.agents
// rule maps.
const (
	// UnmappedDerive names the agent <namespace>/<service account>.
	UnmappedDerive = "derive"
	// UnmappedUnknown treats the caller as unknown.
	UnmappedUnknown = "unknown"
)

// TokenReviewer verifies a service account token; [kube.Reviewer]
// implements it.
type TokenReviewer interface {
	Review(ctx context.Context, tok []byte) (kube.Account, error)
}

// KubeRule maps service accounts to one agent.
type KubeRule struct {
	Agent string
	// Accounts are namespace/name patterns; either part may be a glob
	// (`agents/*`).
	Accounts []string
	Scopes   []Scope
	Labels   map[string]string
}

// KubeResolver identifies callers by service account tokens.
type KubeResolver struct {
	Reviewer TokenReviewer
	Rules    []KubeRule
	// Unmapped is UnmappedDerive (the default) or UnmappedUnknown.
	Unmapped string
}

// KubeRulesFromMap turns identity.kubernetes.agents into rules. Each key is an
// agent name and each value a space-separated list of selectors:
// sa:<namespace>/<name> (globs allowed in either part), scope:<scope> and
// label:<key>=<value>. For example
//
//	identity.kubernetes.agents:
//	  reviewer: "sa:agents/reviewer label:team=platform"
//	  ci: "sa:ci/* scope:secrets:list"
func KubeRulesFromMap(m map[string]string) ([]KubeRule, error) {
	names := slices.Sorted(maps.Keys(m))
	rules := make([]KubeRule, 0, len(m))
	var errs []error
	for _, agent := range names {
		where := "identity.kubernetes.agents." + agent
		if !ValidAgentName(agent) {
			errs = append(errs, fmt.Errorf("%s: agent name must match %s", where, agentName))
			continue
		}
		r := KubeRule{Agent: agent}
		for sel := range strings.FieldsSeq(m[agent]) {
			kind, val, ok := strings.Cut(sel, ":")
			if !ok || val == "" {
				errs = append(errs, fmt.Errorf("%s: selector %q is not kind:value", where, sel))
				continue
			}
			switch kind {
			case "sa":
				ns, name, ok := strings.Cut(val, "/")
				_, e1 := path.Match(ns, "")
				_, e2 := path.Match(name, "")
				if !ok || ns == "" || name == "" || e1 != nil || e2 != nil {
					errs = append(errs, fmt.Errorf("%s: sa %q is not <namespace>/<name>", where, val))
					continue
				}
				r.Accounts = append(r.Accounts, val)
			case "scope":
				s := Scope(val)
				if !ValidScope(s) || s == ScopeSessionsMint {
					errs = append(errs, fmt.Errorf("%s: scope %q is not an agent scope", where, val))
					continue
				}
				r.Scopes = append(r.Scopes, s)
			case "label":
				k, v, ok := strings.Cut(val, "=")
				if !ok || k == "" {
					errs = append(errs, fmt.Errorf("%s: label %q is not key=value", where, val))
					continue
				}
				if isKubeLabel(k) {
					errs = append(errs, fmt.Errorf("%s: label %q is set from the token and cannot be configured", where, k))
					continue
				}
				if r.Labels == nil {
					r.Labels = map[string]string{}
				}
				r.Labels[k] = v
			default:
				errs = append(errs, fmt.Errorf("%s: unknown selector kind %q", where, kind))
			}
		}
		if len(r.Accounts) == 0 {
			errs = append(errs, fmt.Errorf("%s: no sa: selector", where))
		}
		rules = append(rules, r)
	}
	return rules, errors.Join(errs...)
}

func isKubeLabel(k string) bool {
	switch k {
	case LabelNamespace, LabelServiceAccount, LabelPod, LabelPodUID:
		return true
	}
	return false
}

func (r KubeRule) matches(ns, sa string) bool {
	for _, p := range r.Accounts {
		pn, ps, _ := strings.Cut(p, "/")
		okNS, _ := path.Match(pn, ns)
		okSA, _ := path.Match(ps, sa)
		if okNS && okSA {
			return true
		}
	}
	return false
}

// Resolve verifies tok and returns the caller. A token the cluster does not
// accept for scrim's audience is a [RefusedError], never a fall-back to
// anything else; a failure to reach the cluster is a plain error.
func (k *KubeResolver) Resolve(ctx context.Context, tok []byte) (Identity, error) {
	if k == nil || k.Reviewer == nil {
		return Unknown(Peer{}), &RefusedError{Reason: RefusedKubeDisabled}
	}
	a, err := k.Reviewer.Review(ctx, tok)
	switch {
	case errors.Is(err, kube.ErrNotAuthenticated), errors.Is(err, kube.ErrWrongAudience),
		errors.Is(err, kube.ErrNotServiceAccount), errors.Is(err, kube.ErrMalformed):
		return Unknown(Peer{}), &RefusedError{Reason: RefusalReason(err.Error())}
	case err != nil:
		return Unknown(Peer{}), err
	}
	return k.identityOf(a), nil
}

func (k *KubeResolver) identityOf(a kube.Account) Identity {
	labels := map[string]string{}
	agent, scopes := "", AgentScopes
	for _, r := range k.Rules {
		if r.matches(a.Namespace, a.ServiceAccount) {
			agent = r.Agent
			if len(r.Scopes) > 0 {
				scopes = r.Scopes
			}
			maps.Copy(labels, r.Labels)
			break
		}
	}
	if agent == "" {
		if k.Unmapped == UnmappedUnknown {
			return Unknown(Peer{})
		}
		agent = a.Namespace + "/" + a.ServiceAccount
	}
	labels[LabelNamespace] = a.Namespace
	labels[LabelServiceAccount] = a.ServiceAccount
	if a.Pod != "" {
		labels[LabelPod] = a.Pod
	}
	if a.PodUID != "" {
		labels[LabelPodUID] = a.PodUID
	}
	return Identity{Agent: agent, Source: SourceKubernetes, ExpiresAt: a.ExpiresAt,
		Scopes: slices.Clone(scopes), Labels: labels}
}

// RefusedKubeDisabled is a Kubernetes token sent to a scrim that does not
// verify them (identity.kubernetes.enabled is false).
const RefusedKubeDisabled RefusalReason = "kubernetes identity is not enabled"
