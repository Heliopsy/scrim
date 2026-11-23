// SPDX-License-Identifier: AGPL-3.0-only

package matrix

import "testing"

// TestPlanCoversEveryPair checks the covering property the plan's comment
// and docs/leak-assurance.md claim: every (mode, store), (mode, provider) and
// (store, provider) pair runs in at least one cell, and MCP-only runs with
// every store.
func TestPlanCoversEveryPair(t *testing.T) {
	type pair struct{ a, b string }
	seen := map[pair]bool{}
	var cells []Cell
	for _, s := range Stores {
		cells = append(cells, Plan(s)...)
	}
	for _, c := range cells {
		seen[pair{string(c.Mode), string(c.Store)}] = true
		if c.Mode != ModeMCPOnly {
			seen[pair{string(c.Mode), string(c.Provider)}] = true
			seen[pair{string(c.Store), string(c.Provider)}] = true
		}
	}
	for _, m := range append(append([]Mode{}, Modes...), ModeMCPOnly) {
		for _, s := range Stores {
			if !seen[pair{string(m), string(s)}] {
				t.Errorf("mode %s never runs with store %s", m, s)
			}
		}
	}
	for _, p := range Providers {
		for _, m := range Modes {
			if !seen[pair{string(m), string(p)}] {
				t.Errorf("mode %s never runs with provider %s", m, p)
			}
		}
		for _, s := range Stores {
			if !seen[pair{string(s), string(p)}] {
				t.Errorf("store %s never runs with provider %s", s, p)
			}
		}
	}
	if want := len(Stores)*len(Providers) + len(Stores); len(cells) != want {
		t.Errorf("%d cells, want %d", len(cells), want)
	}
}

func TestParseCells(t *testing.T) {
	got, err := ParseCells("transparent/vault/bedrock, mcp-only/file")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != (Cell{ModeTransparent, StoreVault, ProviderBedrock}) || got[1] != (Cell{Mode: ModeMCPOnly, Store: StoreFile}) {
		t.Errorf("ParseCells = %v", got)
	}
	for _, bad := range []string{"transparent/vault", "mcp-only/file/anthropic", "dns/file/anthropic", "transparent/s3/anthropic"} {
		if _, err := ParseCells(bad); err == nil {
			t.Errorf("ParseCells(%q) accepted", bad)
		}
	}
}

// TestCloudRequest checks the wire rewrite keeps every other member byte for
// byte, so a matrix row's chosen escaping reaches scrim unchanged.
func TestCloudRequest(t *testing.T) {
	body := `{"model":"claude-sonnet-4-5", "stream":true,"messages":[{"role":"user","content":"aA\/b"}],"x":1}`
	path, out := cloudRequest(ProviderBedrock, "/v1/messages", []byte(body))
	if path != "/model/claude-sonnet-4-5/invoke-with-response-stream" {
		t.Errorf("bedrock path %q", path)
	}
	if want := `{"anthropic_version":"bedrock-2023-05-31","messages":[{"role":"user","content":"aA\/b"}],"x":1}`; string(out) != want {
		t.Errorf("bedrock body\n got %s\nwant %s", out, want)
	}
	path, out = cloudRequest(ProviderVertex, "/v1/messages", []byte(`{"model":"m@1","messages":[]}`))
	if path != "/v1/projects/scrim-matrix/locations/us-east5/publishers/anthropic/models/m@1:rawPredict" ||
		string(out) != `{"anthropic_version":"vertex-2023-10-16","messages":[]}` {
		t.Errorf("vertex: %s %s", path, out)
	}
	if path, out = cloudRequest(ProviderFoundry, "/v1/messages", []byte(body)); path != "/anthropic/v1/messages" || string(out) != body {
		t.Errorf("foundry: %s %s", path, out)
	}
	if _, out = cloudRequest(ProviderBedrock, "/v1/messages", []byte("not json")); string(out) != "not json" {
		t.Errorf("a body that is not an object changed: %s", out)
	}
}
