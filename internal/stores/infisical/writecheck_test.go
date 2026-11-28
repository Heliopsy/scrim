// SPDX-License-Identifier: AGPL-3.0-only

package infisical

import (
	"testing"

	"github.com/heliopsy/scrim/internal/stores"
)

// The write check is declared honestly (specs/agent-identity "Agent writes
// are checked as the agent"): it refuses AgentCan for OpWrite as unsupported, so it must not claim to check agents' writes.
func TestAgentWriteCheckDeclared(t *testing.T) {
	for _, k := range []string{Kind} {
		if stores.ChecksAgentWrites(k) {
			t.Errorf("kind %s: stores.ChecksAgentWrites = %v, want false", k, !false)
		}
	}
}
