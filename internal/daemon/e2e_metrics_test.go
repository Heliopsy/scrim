// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/heliopsy/scrim/internal/testing/fakeprovider"
)

// TestEndToEndMetricsRealDataPlane enables metrics, sends traffic through the
// real Rust data plane (a forwarded request carrying a seeded secret, a
// streamed one, and a refused one) and checks that the data plane's series
// reach the control plane's /metrics with the expected values, and that no
// seeded value, reference or agent credential appears in any encoding.
func TestEndToEndMetricsRealDataPlane(t *testing.T) {
	bin := realDataPlane(t)
	fake := fakeprovider.New(fakeprovider.Options{})
	up := httptest.NewServer(fake)
	defer up.Close()

	token := seed(t, "sk-metrics-")
	agentKey := seed(t, "agent-key-")
	h := newHarness(t, token)
	h.opts.DataPlaneEnv = nil
	h.opts.Config.Environ = append(h.opts.Config.Environ, "SCRIM_DATAPLANE_PATH="+bin,
		"SCRIM_PROXY_UPSTREAM_ANTHROPIC="+up.URL, "SCRIM_METRICS_ENABLED=true")
	d := startDaemon(t, h)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	send := func(body string, header map[string]string) int {
		t.Helper()
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, d.Addrs().BaseURL+"/anthropic/v1/messages", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("x-api-key", agentKey)
		req.Header.Set("anthropic-version", "2023-06-01")
		for k, v := range header {
			req.Header.Set(k, v)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	msg := `{"model":"claude-sonnet-4-5","max_tokens":64,%s"messages":[{"role":"user","content":"deploy with key ` + token + ` please"}]}`
	if code := send(strings.Replace(msg, "%s", "", 1), nil); code != http.StatusOK {
		t.Fatalf("forwarded request: status %d", code)
	}
	if code := send(strings.Replace(msg, "%s", `"stream":true,`, 1), nil); code != http.StatusOK {
		t.Fatalf("streamed request: status %d", code)
	}
	if code := send(strings.Replace(msg, "%s", "", 1), map[string]string{"Content-Encoding": "gzip"}); code != http.StatusUnsupportedMediaType {
		t.Fatalf("compressed request: status %d, want 415", code)
	}

	addr := d.Addrs().Metrics
	rp := map[string]string{"route": "anthropic", "provider": "anthropic"}
	with := func(kv ...string) map[string]string {
		m := map[string]string{}
		for k, v := range rp {
			m[k] = v
		}
		for i := 0; i+1 < len(kv); i += 2 {
			m[kv[i]] = kv[i+1]
		}
		return m
	}
	var page string
	eventually(t, "data plane series", func() bool {
		_, page = scrapeMetrics(t, addr, "/metrics", "")
		v, ok := sample(page, "scrim_dataplane_requests_total", with("outcome", "forwarded"))
		return ok && v == 2
	})
	for _, c := range []struct {
		name   string
		labels map[string]string
		want   float64
		atLeat bool
	}{
		{"scrim_dataplane_metrics_up", nil, 1, false},
		{"scrim_dataplane_up", nil, 1, false},
		{"scrim_dataplane_requests_total", with("outcome", "refused"), 1, false},
		{"scrim_dataplane_refusals_total", with("source", "llm", "code", "unsupported_encoding"), 1, false},
		{"scrim_dataplane_request_added_seconds_count", with("stage", "total"), 2, false},
		{"scrim_dataplane_request_added_seconds_count", with("stage", "redaction"), 2, false},
		{"scrim_dataplane_request_added_seconds_count", with("stage", "guard"), 2, false},
		{"scrim_dataplane_request_body_bytes_count", rp, 2, false},
		{"scrim_dataplane_redaction_hits_total", with("source", "llm", "class", "value"), 2, true},
		{"scrim_dataplane_upstream_responses_total", with("status_class", "2xx"), 2, false},
		{"scrim_dataplane_upstream_seconds_count", rp, 2, false},
		{"scrim_dataplane_restore_chunk_seconds_count", rp, 1, true},
		{"scrim_dataplane_connections_total", map[string]string{"listener": "base_url"}, 1, true},
		{"scrim_dataplane_snapshot_applies_total", map[string]string{"result": "applied"}, 1, true},
		{"scrim_dataplane_snapshot_version", nil, 1, true},
		{"scrim_dataplane_values", nil, 1, true},
		{"scrim_snapshot_pushes_total", map[string]string{"result": "ok"}, 1, true},
	} {
		v, ok := sample(page, c.name, c.labels)
		if !ok || (c.atLeat && v < c.want) || (!c.atLeat && v != c.want) {
			t.Errorf("%s%v = %v (present %v), want %v", c.name, c.labels, v, ok, c.want)
		}
	}
	// The data plane's version agrees with what the control plane pushed.
	dpv, _ := sample(page, "scrim_dataplane_snapshot_version", nil)
	cpv, _ := sample(page, "scrim_snapshot_version", nil)
	if dpv != cpv {
		t.Errorf("data plane snapshot %v, control plane pushed %v", dpv, cpv)
	}
	assertNoLeak(t, page, token, agentKey, "SCRIMTEST_TOKEN", "testenv://")
	if strings.Contains(h.logs.String(), token) {
		t.Fatal("the secret reached the log")
	}
}
