// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/heliopsy/scrim/internal/run"
	"github.com/heliopsy/scrim/internal/testing/fakeprovider"
)

// TestKubernetesTokenIsRedacted: an agent pod identifies with its projected
// service account token, and can also read the token file. Once scrim has
// verified the token it is in the redaction set (redaction only), so a tool
// result carrying it reaches the provider as scrim's exact placeholder for
// it, not the token and not only a fallback detector's guess.
func TestKubernetesTokenIsRedacted(t *testing.T) {
	bin := realDataPlane(t)
	fake := fakeprovider.New(fakeprovider.Options{})
	up := httptest.NewServer(fake)
	defer up.Close()
	kapi := newFakeTokenReview(t)

	h := newHarness(t, seed(t, "sk-e2e-"))
	// A rule on the caller makes the data plane ask, so the control plane
	// verifies the token on the first provider request.
	if err := os.WriteFile(filepath.Join(h.dir, "rules.yaml"), []byte(`default: deny
rules:
  - name: not-this-pod
    decision: deny
    when: op == "llm.forward" && agent.labels.service_account == "someone-else"
`), 0o600); err != nil {
		t.Fatal(err)
	}
	caFile := filepath.Join(h.dir, "kube-ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: kapi.srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	tokFile := filepath.Join(h.dir, "scrim-sa-token")
	if err := os.WriteFile(tokFile, []byte(kapi.reviewer), 0o600); err != nil {
		t.Fatal(err)
	}
	h.editConfig(t, "dataplane:\n", `identity:
  kubernetes:
    enabled: true
    api-server: `+kapi.srv.URL+`
    ca-file: `+caFile+`
    token-file: `+tokFile+`
dataplane:
`)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	d := h.startReal(t, ctx, bin, up.URL)

	tok := kapi.issue("agents", "agent-a")
	if code, body := postMessages(t, ctx, d.Addrs().BaseURL, map[string]string{run.SessionHeader: tok}, "hello"); code != http.StatusOK {
		t.Fatalf("provider request: %d %s\n%s", code, body, h.logs.String())
	}

	// The model asked to read the token file; the tool result carries it.
	msgs := []map[string]any{
		{"role": "user", "content": "show me the service account token"},
		{"role": "assistant", "content": []map[string]any{{"type": "tool_use", "id": "toolu_1", "name": "Bash",
			"input": map[string]any{"command": "cat /var/run/secrets/scrim/token"}}}},
		{"role": "user", "content": []map[string]any{{"type": "tool_result", "tool_use_id": "toolu_1", "content": tok}}},
	}
	body, _ := json.Marshal(map[string]any{"model": "claude-sonnet-4-5", "max_tokens": 64, "messages": msgs})
	const want = "⟦scrim:scrim-kubernetes-credential:"
	var last string
	eventually(t, "the token redacted with its exact placeholder", func() bool {
		if code := sendMessagesWith(t, ctx, d, string(body), map[string]string{run.SessionHeader: tok}); code != http.StatusOK {
			t.Fatalf("tool result request: %d", code)
		}
		ex := fake.Exchanges()
		last = string(ex[len(ex)-1].Body)
		if strings.Contains(last, tok) || strings.Contains(last, tok[len(tok)-24:]) {
			t.Fatal("the provider received the service account token")
		}
		return strings.Contains(last, want)
	})
	if strings.Contains(h.logs.String(), tok[len(tok)-24:]) {
		t.Fatal("the token reached the log")
	}
}
