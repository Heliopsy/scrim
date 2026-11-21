// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/heliopsy/scrim/internal/agenthooks"
	"github.com/heliopsy/scrim/internal/localapi"
	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/testing/fakeprovider"
)

// TestHooksRedactRealDataPlane runs the agent hooks against the local API of
// a daemon on the real data plane (hooks-only interception): a tool result
// holding a generated secret comes back with its placeholder for Claude Code
// and as a block reason for Codex, a prompt holding it is blocked, and the
// secret is in no answer and not in the log.
func TestHooksRedactRealDataPlane(t *testing.T) {
	bin := realDataPlane(t)
	up := httptest.NewServer(fakeprovider.New(fakeprovider.Options{}))
	defer up.Close()
	token := seed(t, "sk-hook-")
	h := newHarness(t, token)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	d := h.startReal(t, ctx, bin, up.URL)
	c := localapi.NewClient(d.Addrs().AgentAPI, secret.Value{})
	defer c.Close()

	out, err := c.Redact(ctx, []byte("API_KEY="+token+"\n"))
	if err != nil {
		t.Fatal(err)
	}
	if out.Replacements != 1 || strings.Contains(out.Text, token) || !strings.Contains(out.Text, "⟦scrim:acme:") {
		t.Fatalf("redact = %+v", out)
	}

	resp, _ := json.Marshal(map[string]any{"stdout": "API_KEY=" + token + "\n", "stderr": "", "interrupted": false, "isImage": false})
	in, _ := json.Marshal(map[string]any{"hook_event_name": "PostToolUse", "tool_name": "Bash", "tool_response": json.RawMessage(resp)})
	prompt, _ := json.Marshal(map[string]any{"hook_event_name": "UserPromptSubmit", "prompt": "use " + token})
	for _, tc := range []struct {
		agent, event string
		in           []byte
		want         string
	}{
		{"claude", agenthooks.EventPostToolUse, in, `"updatedToolOutput":{"interrupted":false,"isImage":false,"stderr":"","stdout":"API_KEY=⟦scrim:acme:`},
		{"codex", agenthooks.EventPostToolUse, in, `"decision":"block"`},
		{"claude", agenthooks.EventUserPromptSubmit, prompt, `"decision":"block"`},
	} {
		var w bytes.Buffer
		if err := agenthooks.Run(ctx, tc.agent, tc.event, bytes.NewReader(tc.in), &w, c); err != nil {
			t.Fatalf("%s %s: %v", tc.agent, tc.event, err)
		}
		got := w.String()
		if strings.Contains(got, token) || !strings.Contains(got, tc.want) || !strings.Contains(got, "⟦scrim:acme:") {
			t.Fatalf("%s %s answered %s", tc.agent, tc.event, got)
		}
	}
	if strings.Contains(h.logs.String(), token) {
		t.Fatal("the secret reached the log")
	}
}
