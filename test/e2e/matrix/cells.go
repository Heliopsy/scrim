// SPDX-License-Identifier: AGPL-3.0-only

// Package matrix is scrim's end-to-end matrix (tasks.md 16.1): real traffic
// from an agent process, through an interception mode, into the real
// `scrim proxy` and data plane, with the secrets in a real store (or its
// emulator) and the fake model provider (fakeprovider, with the cloud front
// ends of fakeprovider.Cloud) as the upstream, and the leak suite's checker
// asserting zero leaks.
//
// The axes are the interception mode ([Modes]), the store ([Stores]) and the
// provider ([Providers]). The full cross product is large, so [Plan] is a
// covering design: every pair of values from two axes runs in at least one
// cell (TestPlanCoversEveryPair checks it). One CI job runs the cells of one
// store; `test/e2e/matrix/run.sh <store>` runs the same thing locally.
//
// Each traffic cell runs the bypass matrix of the leak suite (every row, every
// seed, the same gate as `scrim audit run`) for its provider's API, and for
// the four native APIs the scenario corpus too. A cloud provider cell sends
// the Anthropic Messages rows in that provider's wire format (Bedrock
// InvokeModel, Vertex rawPredict, Foundry under /anthropic, ...) to a fake of
// that provider that refuses any request scrim did not authenticate with the
// credentials from the store under test. The MCP-only cell runs scrim's MCP
// server for an agent whose model traffic goes straight to the provider, and
// checks that no tool result carries a value.
package matrix

import (
	"fmt"
	"strings"
)

// Mode is how the agent's traffic reaches scrim.
type Mode string

// Interception modes.
const (
	// ModeBaseURL: the agent runs under `scrim run` and sends provider
	// requests to the base URLs it sets (ANTHROPIC_BASE_URL, ...).
	ModeBaseURL Mode = "run-base-url"
	// ModeForwardProxy: the agent runs under `scrim run`, ignores the base
	// URLs and sends to the provider's own host name through HTTPS_PROXY,
	// trusting the CA bundle scrim run hands it.
	ModeForwardProxy Mode = "run-forward-proxy"
	// ModeTransparent: the agent has no configuration and connects to the
	// provider's host on port 443; an nftables redirect in the sandbox's
	// network namespace sends it to scrim's transparent listener, which
	// reads the original destination and the server name (the listener the
	// eBPF connect hooks land on as well).
	ModeTransparent Mode = "transparent"
	// ModeMCPOnly: no interception. The agent calls scrim's MCP tools and
	// sends its model requests straight to the provider.
	ModeMCPOnly Mode = "mcp-only"
)

// Modes are the interception modes that carry the agent's model traffic, in
// the order the plan rotates through them.
var Modes = []Mode{ModeBaseURL, ModeForwardProxy, ModeTransparent}

// Store is the kind of store the seeds and the cloud credentials live in.
type Store string

// Stores.
const (
	StoreFile    Store = "file"
	StoreOpenBao Store = "openbao"
	StoreVault   Store = "vault"
	StoreAWSSM   Store = "awssm"
)

// Stores in plan order. Each has a real server or emulator in rootless podman
// except the file store.
var Stores = []Store{StoreFile, StoreOpenBao, StoreVault, StoreAWSSM}

// Provider is a provider route: a native API of scrim's built-in routes or a
// cloud provider route (docs/providers).
type Provider string

// Providers.
const (
	ProviderAnthropic       Provider = "anthropic"
	ProviderOpenAIChat      Provider = "openai-chat"
	ProviderOpenAIResponses Provider = "openai-responses"
	ProviderGemini          Provider = "gemini"
	ProviderBedrock         Provider = "bedrock"
	ProviderBedrockMantle   Provider = "bedrock-mantle"
	ProviderAnthropicAWS    Provider = "anthropic-aws"
	ProviderFoundry         Provider = "foundry"
	ProviderFoundryEntra    Provider = "foundry-entra"
	ProviderVertex          Provider = "vertex"
)

// Providers in plan order.
var Providers = []Provider{
	ProviderAnthropic, ProviderOpenAIChat, ProviderOpenAIResponses, ProviderGemini,
	ProviderBedrock, ProviderBedrockMantle, ProviderAnthropicAWS, ProviderFoundry, ProviderFoundryEntra, ProviderVertex,
}

// Cell is one combination that runs.
type Cell struct {
	Mode     Mode
	Store    Store
	Provider Provider // empty for ModeMCPOnly, where scrim carries no model traffic
}

func (c Cell) String() string {
	if c.Mode == ModeMCPOnly {
		return fmt.Sprintf("%s/%s", c.Mode, c.Store)
	}
	return fmt.Sprintf("%s/%s/%s", c.Mode, c.Store, c.Provider)
}

// Plan returns the cells of one store. Over all stores the traffic cells form
// a covering array of strength two: provider p runs with store s in mode
// Modes[(p+s) mod 3], so every store meets every provider once, and since a
// store meets ten providers and a provider meets four stores, every store and
// every provider meet every mode. One MCP-only cell per store adds that mode,
// which carries no model traffic and so has no provider. 4 x 10 + 4 = 44
// cells instead of the 4 x 4 x 10 = 160 of the full product.
func Plan(s Store) []Cell {
	si := -1
	for i, x := range Stores {
		if x == s {
			si = i
		}
	}
	if si < 0 {
		return nil
	}
	var out []Cell
	for pi, p := range Providers {
		out = append(out, Cell{Mode: Modes[(pi+si)%len(Modes)], Store: s, Provider: p})
	}
	return append(out, Cell{Mode: ModeMCPOnly, Store: s})
}

// ParseCells parses "mode/store/provider" (or "mcp-only/store") cells
// separated by spaces or commas, for running a subset by hand.
func ParseCells(spec string) ([]Cell, error) {
	var out []Cell
	for _, f := range strings.FieldsFunc(spec, func(r rune) bool { return r == ' ' || r == ',' }) {
		parts := strings.Split(f, "/")
		c := Cell{Mode: Mode(parts[0])}
		switch {
		case c.Mode == ModeMCPOnly && len(parts) == 2:
			c.Store = Store(parts[1])
		case len(parts) == 3:
			c.Store, c.Provider = Store(parts[1]), Provider(parts[2])
		default:
			return nil, fmt.Errorf("cell %q: want mode/store/provider or mcp-only/store", f)
		}
		if !known(c) {
			return nil, fmt.Errorf("cell %q: unknown mode, store or provider", f)
		}
		out = append(out, c)
	}
	return out, nil
}

func known(c Cell) bool {
	in := func(v string, set []string) bool {
		for _, s := range set {
			if s == v {
				return true
			}
		}
		return false
	}
	var modes, stores, providers []string
	for _, m := range Modes {
		modes = append(modes, string(m))
	}
	for _, s := range Stores {
		stores = append(stores, string(s))
	}
	for _, p := range Providers {
		providers = append(providers, string(p))
	}
	if !in(string(c.Store), stores) {
		return false
	}
	if c.Mode == ModeMCPOnly {
		return c.Provider == ""
	}
	return in(string(c.Mode), modes) && in(string(c.Provider), providers)
}
