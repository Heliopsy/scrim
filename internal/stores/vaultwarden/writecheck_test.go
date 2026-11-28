// SPDX-License-Identifier: AGPL-3.0-only

package vaultwarden

import (
	"testing"

	"github.com/heliopsy/scrim/internal/stores"
)

// The write check is declared honestly (specs/agent-identity "Agent writes
// are checked as the agent"): it answers AgentCan for OpWrite without writing, so scrim must ask it before an agent's write.
func TestAgentWriteCheckDeclared(t *testing.T) {
	for _, k := range []string{Kind} {
		if !stores.ChecksAgentWrites(k) {
			t.Errorf("kind %s: stores.ChecksAgentWrites = %v, want true", k, !true)
		}
	}
}
