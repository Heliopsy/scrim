// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/heliopsy/scrim/internal/testing/fakeprovider"
)

// realDataPlane returns the Rust data plane to run: SCRIM_TEST_DATAPLANE
// (what `just test` and CI set) or SCRIM_DATAPLANE_PATH.
func realDataPlane(t *testing.T) string {
	t.Helper()
	p := os.Getenv("SCRIM_TEST_DATAPLANE")
	if p == "" {
		p = os.Getenv("SCRIM_DATAPLANE_PATH")
	}
	if p == "" || p == "embedded" {
		t.Skip("SCRIM_TEST_DATAPLANE is not set; run `just test` to build and use the Rust data plane")
	}
	return p
}

// TestEndToEndRealDataPlane runs the daemon with the real data plane, an env
// store holding a generated secret and the fake model provider as the
// Anthropic upstream, sends a Messages request carrying the secret to the
// base URL listener, and checks the provider received placeholders only.
func TestEndToEndRealDataPlane(t *testing.T) {
	bin := realDataPlane(t)
	fake := fakeprovider.New(fakeprovider.Options{})
	up := httptest.NewServer(fake)
	defer up.Close()

	token := seed(t, "sk-e2e-")
	h := newHarness(t, token)
	h.opts.DataPlaneEnv = nil
	h.opts.Config.Environ = append(h.opts.Config.Environ, "SCRIM_DATAPLANE_PATH="+bin,
		"SCRIM_PROXY_UPSTREAM_ANTHROPIC="+up.URL, "SCRIM_PROXY_FORWARD_LISTEN=")

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	d, err := Start(ctx, h.opts)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = d.Shutdown(context.Background()) }()

	// Until the data plane serves the base URL listener it stays not
	// ready. On a data plane without the LLM proxy wired in, the listener
	// reports why it is unbound: skip with that reason.
	deadline := time.Now().Add(30 * time.Second)
	for !d.Ready(ctx) {
		sctx, scancel := context.WithTimeout(ctx, 5*time.Second)
		st, serr := d.Supervisor().Status(sctx)
		scancel()
		if serr == nil {
			for _, l := range st.GetListeners() {
				if l.GetName() == "llm" && !l.GetBound() && strings.Contains(l.GetError(), "not implemented") {
					t.Skipf("the data plane does not serve the base URL listener yet (%s); feat/dataplane-wiring wires it", l.GetError())
				}
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("daemon not ready: %+v\n%s", d.Info().Problems, h.logs.String())
		}
		time.Sleep(100 * time.Millisecond)
	}

	body := `{"model":"claude-sonnet-4-5","max_tokens":64,"messages":[{"role":"user","content":"deploy with key ` + token + ` please"}]}`
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, d.Addrs().BaseURL+"/anthropic/v1/messages", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", "agent-own-key")
	req.Header.Set("anthropic-version", "2023-06-01")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	reply, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d: %s", resp.StatusCode, reply)
	}

	ex := fake.Exchanges()
	if len(ex) != 1 {
		t.Fatalf("provider saw %d requests", len(ex))
	}
	if strings.Contains(string(ex[0].Body), token) {
		t.Fatal("the provider received the secret")
	}
	if len(ex[0].Placeholders) == 0 || !strings.HasPrefix(ex[0].Placeholders[0], "⟦scrim:acme:") {
		t.Fatalf("no placeholder in what the provider saw: %s", ex[0].Body)
	}
	if ex[0].Header.Get("x-api-key") != "agent-own-key" {
		t.Fatal("the agent's own credential did not pass through")
	}
	if strings.Contains(h.logs.String(), token) {
		t.Fatal("the secret reached the log")
	}
}
