// SPDX-License-Identifier: AGPL-3.0-only

package localapi

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/heliopsy/scrim/internal/agenttools"
	"github.com/heliopsy/scrim/internal/identity"
)

// TestExecRoute: POST /v1/exec reaches the broker with the caller's
// transport identity and the request as sent, and answers with its result
// or its error; without a broker it is unavailable.
func TestExecRoute(t *testing.T) {
	h := start(t)
	_, err := h.peer.Exec(bg, agenttools.ExecInput{Command: []string{"git"}})
	if codeOf(t, err) != agenttools.CodeUnavailable {
		t.Fatalf("no broker: %v", err)
	}

	var (
		mu  sync.Mutex
		who identity.Identity
		got agenttools.ExecInput
	)
	h = startWith(t, func(s *Server) {
		s.Exec = func(_ context.Context, id identity.Identity, in agenttools.ExecInput) (agenttools.ExecOutput, error) {
			mu.Lock()
			defer mu.Unlock()
			who, got = id, in
			if in.Command[0] == "sh" {
				return agenttools.ExecOutput{}, agenttools.Errorf(agenttools.CodeDenied, "sh is never run by the exec broker")
			}
			return agenttools.ExecOutput{ExitCode: 4, Stderr: "⟦scrim:x:01aa⟧\n", Refs: []string{"bao://kv/x"}}, nil
		}
	})
	stdin := strings.Repeat("a", 200<<10) // above the JSON limit of the other routes
	out, err := h.peer.Exec(bg, agenttools.ExecInput{Command: []string{"git", "push"}, Env: map[string]string{"T": "SCRIM_T"}, Stdin: stdin})
	if err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	if out.ExitCode != 4 || out.Stderr != "⟦scrim:x:01aa⟧\n" || who.Agent != "dev" || got.Env["T"] != "SCRIM_T" || len(got.Stdin) != len(stdin) {
		t.Fatalf("out = %+v, who = %+v", out, who)
	}
	mu.Unlock()
	_, err = h.peer.Exec(bg, agenttools.ExecInput{Command: []string{"sh"}})
	if codeOf(t, err) != agenttools.CodeDenied {
		t.Fatalf("refusal: %v", err)
	}
	// Unknown fields are refused, as on every route.
	var raw map[string]any
	err = h.peer.json(bg, "POST", "/exec", map[string]any{"command": []string{"git"}, "value": "x"}, &raw)
	if codeOf(t, err) != agenttools.CodeInvalid {
		t.Fatalf("unknown field: %v", err)
	}
}
