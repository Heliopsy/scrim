// SPDX-License-Identifier: AGPL-3.0-only

package cli

import (
	"context"
	"fmt"
	"maps"
	"os"
	"slices"

	"github.com/heliopsy/scrim/internal/agentapi"
	"github.com/heliopsy/scrim/internal/agentstore"
	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/status"
	"github.com/heliopsy/scrim/internal/stores/storeconfig"
)

// identityChecks report how agents are identified in a cluster and which
// store identity each agent uses (specs/agent-identity "Static per-agent
// store credentials as fallback"). They read configuration only and never
// resolve a credential.
func identityChecks(cfg *config.Config) []status.Check {
	return []status.Check{
		{Name: "identity: kubernetes", Run: func(context.Context) []status.Finding { return kubeFindings(cfg) }},
		{Name: "identity: store identity per agent", Run: func(context.Context) []status.Finding { return storeIdentityFindings(cfg) }},
	}
}

func kubeFindings(cfg *config.Config) []status.Finding {
	const check = "identity: kubernetes"
	if !agentapi.KubeEnabled.Get(cfg) {
		return []status.Finding{{Check: check, Outcome: status.Skip, Message: "off (identity.kubernetes.enabled)"}}
	}
	var out []status.Finding
	api := agentapi.KubeAPIServer.Get(cfg)
	if api == "" {
		if os.Getenv("KUBERNETES_SERVICE_HOST") == "" {
			out = append(out, status.Finding{Check: check, Outcome: status.Fail,
				Message: "no API server: identity.kubernetes.api-server is empty and this is not a pod",
				Fix:     "set identity.kubernetes.api-server or run scrim in the cluster"})
		}
		api = "in-cluster"
	}
	for _, f := range []struct{ key, path string }{
		{agentapi.KubeCAFile.Name(), agentapi.KubeCAFile.Get(cfg)},
		{agentapi.KubeTokenFile.Name(), agentapi.KubeTokenFile.Get(cfg)},
	} {
		if _, err := os.Stat(f.path); err != nil {
			out = append(out, status.Finding{Check: check, Outcome: status.Fail,
				Message: fmt.Sprintf("%s %s is not readable", f.key, f.path),
				Fix:     "mount the pod's service account (automountServiceAccountToken) or set " + f.key})
		}
	}
	if len(out) > 0 {
		return out
	}
	return []status.Finding{{Check: check, Outcome: status.Pass, Message: fmt.Sprintf(
		"service account tokens with audience %q verified by TokenReview (%s); unmapped service accounts: %s",
		agentapi.KubeAudience.Get(cfg), api, agentapi.KubeUnmapped.Get(cfg))}}
}

func storeIdentityFindings(cfg *config.Config) []status.Finding {
	const check = "identity: store identity per agent"
	c, err := agentstore.New(agentstore.Options{Login: agentstore.Login.Get(cfg), Credentials: agentstore.Credentials.Get(cfg)})
	if err != nil {
		return []status.Finding{{Check: check, Outcome: status.Fail, Message: err.Error(),
			Fix: "fix identity.store-login or identity.store-credentials"}}
	}
	var storeNames []string
	for _, inst := range storeconfig.Collection.Get(cfg) {
		storeNames = append(storeNames, inst.Name)
	}
	slices.Sort(storeNames)
	agents := map[string]bool{}
	for a := range maps.Keys(agentapi.Peers.Get(cfg)) {
		agents[a] = true
	}
	for a := range maps.Keys(agentapi.KubeAgents.Get(cfg)) {
		agents[a] = true
	}
	var out []status.Finding
	for _, r := range c.Report(storeNames, slices.Sorted(maps.Keys(agents))) {
		f := status.Finding{Check: check, Outcome: status.Pass,
			Message: fmt.Sprintf("store %s, agent %s: %s (%s)", r.Store, r.Agent, r.Source, r.Detail)}
		switch r.Source {
		case agentstore.SourceShared:
			f.Message = fmt.Sprintf("store %s: every agent uses scrim's own identity (no per-agent credential)", r.Store)
		case agentstore.SourceNone:
			f.Outcome = status.Warn
			f.Fix = "give the agent a credential in identity.store-credentials." + r.Store + "/" + r.Agent + ", or expect it to be refused for this store"
			if r.Agent == "*" {
				f.Fix = "agents not listed are refused for this store"
			}
		}
		out = append(out, f)
	}
	return out
}
