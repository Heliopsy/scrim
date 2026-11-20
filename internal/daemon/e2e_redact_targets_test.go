// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/heliopsy/scrim/internal/status"
	"github.com/heliopsy/scrim/internal/stores/refresh"
	"github.com/heliopsy/scrim/internal/testing/fakeprovider"
)

const harnessRedact = `    redact: ["testenv://SCRIMTEST_TOKEN"]
`

// editConfig rewrites the harness configuration file.
func (h *harness) editConfig(t *testing.T, old, repl string) {
	t.Helper()
	p := filepath.Join(h.dir, "config.yaml")
	b, err := os.ReadFile(p) //nolint:gosec // the test's own config
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), old) {
		t.Fatalf("config has no %q", old)
	}
	if err := os.WriteFile(p, []byte(strings.Replace(string(b), old, repl, 1)), 0o600); err != nil {
		t.Fatal(err)
	}
}

// startReal starts the daemon on the real data plane with up as the
// Anthropic upstream and waits until it serves the base URL listener.
func (h *harness) startReal(t *testing.T, ctx context.Context, bin, up string) *Daemon {
	t.Helper()
	h.opts.DataPlaneEnv = nil
	h.opts.Config.Environ = append(h.opts.Config.Environ, "SCRIM_DATAPLANE_PATH="+bin, "SCRIM_PROXY_UPSTREAM_ANTHROPIC="+up)
	d, err := Start(ctx, h.opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Shutdown(context.Background()) })
	wctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := d.WaitReady(wctx); err != nil {
		t.Fatalf("%v\n%s", err, h.logs.String())
	}
	return d
}

// sendMessages posts one Anthropic Messages request body and returns the
// status code.
func sendMessages(t *testing.T, ctx context.Context, d *Daemon, body string) int {
	t.Helper()
	return sendMessagesWith(t, ctx, d, body, nil)
}

// sendMessagesWith is [sendMessages] with extra request headers.
func sendMessagesWith(t *testing.T, ctx context.Context, d *Daemon, body string, hdr map[string]string) int {
	t.Helper()
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, d.Addrs().BaseURL+"/anthropic/v1/messages", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", "agent-own-key")
	req.Header.Set("anthropic-version", "2023-06-01")
	for k, v := range hdr {
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

// TestQuickstartGlobRedactsEndToEnd is the README quickstart on the real
// data plane: an env store with `redact: [local://SCRIM_SECRET_*]`. v0.1.0
// read the glob as one secret named `SCRIM_SECRET_*`, loaded nothing and
// forwarded SCRIM_SECRET_X to the provider in the clear.
func TestQuickstartGlobRedactsEndToEnd(t *testing.T) {
	bin := realDataPlane(t)
	fake := fakeprovider.New(fakeprovider.Options{})
	up := httptest.NewServer(fake)
	defer up.Close()

	secretX := seed(t, "qs-")
	h := newHarness(t, seed(t, "tok-"))
	h.editConfig(t, harnessRedact, harnessRedact+`  local:
    kind: env
    prefix: SCRIM_SECRET_
    redact:
      - local://SCRIM_SECRET_*
`)
	t.Setenv("SCRIM_SECRET_X", secretX)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	d := h.startReal(t, ctx, bin, up.URL)

	body := `{"model":"claude-sonnet-4-5","max_tokens":64,"messages":[{"role":"user","content":"use ` + secretX + ` now"}]}`
	if code := sendMessages(t, ctx, d, body); code != http.StatusOK {
		t.Fatalf("status %d\n%s", code, h.logs.String())
	}
	ex := fake.Exchanges()
	if len(ex) != 1 {
		t.Fatalf("provider saw %d requests", len(ex))
	}
	if strings.Contains(string(ex[0].Body), secretX) {
		t.Fatal("the provider received SCRIM_SECRET_X")
	}
	if len(ex[0].Placeholders) == 0 {
		t.Fatalf("no placeholder in what the provider saw: %s", ex[0].Body)
	}
	if strings.Contains(h.logs.String(), secretX) {
		t.Fatal("the secret reached the log")
	}
	in := d.Info()
	i := slices.IndexFunc(in.Stores, func(s status.Store) bool { return s.Name == "local" })
	if i < 0 || len(in.Stores[i].Targets) != 1 || in.Stores[i].Targets[0].Values < 1 || in.Stores[i].Degraded {
		t.Fatalf("stores = %+v", in.Stores)
	}
}

// TestEmptyRedactTargetStopsStartUp: a target that matches nothing stops
// the daemon with an error naming it.
func TestEmptyRedactTargetStopsStartUp(t *testing.T) {
	h := newHarness(t, seed(t, "tok-"))
	h.editConfig(t, harnessRedact, `    redact: ["testenv://SCRIMTEST_NOTHING_*"]
`)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	d, err := Start(ctx, h.opts)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = d.Shutdown(context.Background()) }()
	select {
	case <-d.Done():
	case <-ctx.Done():
		t.Fatal("the daemon kept running with a redact target that loads nothing")
	}
	err = d.Err()
	if !errors.Is(err, refresh.ErrEmptyTarget) || !strings.Contains(err.Error(), "testenv://SCRIMTEST_NOTHING_*") ||
		!strings.Contains(err.Error(), refresh.AllowEmptyTargetsKey) {
		t.Fatalf("daemon error = %v", err)
	}
}

// TestEmptyRedactTargetAllowedIsDegraded: with the weakening setting the
// daemon starts, but the target shows 0 values, the store is degraded and
// redaction is not reported active.
func TestEmptyRedactTargetAllowedIsDegraded(t *testing.T) {
	h := newHarness(t, seed(t, "tok-"))
	h.editConfig(t, harnessRedact, `    redact: ["testenv://SCRIMTEST_TOKEN", "testenv://SCRIMTEST_NOTHING_*"]
`)
	h.opts.Config.Environ = append(h.opts.Config.Environ, "SCRIM_REDACTION_ALLOW_EMPTY_TARGETS=true")
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	d, err := Start(ctx, h.opts)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = d.Shutdown(context.Background()) }()
	if err := d.WaitReady(ctx); err != nil {
		t.Fatalf("%v\n%s", err, h.logs.String())
	}
	in := d.Info()
	i := slices.IndexFunc(in.Stores, func(s status.Store) bool { return s.Name == "testenv" })
	if i < 0 {
		t.Fatalf("stores = %+v", in.Stores)
	}
	s := in.Stores[i]
	got := map[string]int{}
	for _, tg := range s.Targets {
		got[tg.Target] = tg.Values
	}
	if !s.Degraded || got["testenv://SCRIMTEST_TOKEN"] != 1 || got["testenv://SCRIMTEST_NOTHING_*"] != 0 ||
		!strings.Contains(s.Reason, "testenv://SCRIMTEST_NOTHING_*") {
		t.Fatalf("store = %+v", s)
	}
	for _, p := range in.Runtime.Protections {
		if p.Name == "redaction" && (p.Active || !strings.Contains(p.Detail, "testenv://SCRIMTEST_NOTHING_*")) {
			t.Fatalf("redaction protection = %+v", p)
		}
	}
	weak := false
	for _, w := range d.app.Config.Current().Weakened() {
		weak = weak || w.Setting.Key == refresh.AllowEmptyTargetsKey
	}
	if !weak || !strings.Contains(h.logs.String(), refresh.AllowEmptyTargetsKey) {
		t.Fatalf("the weakening setting is not reported or warned\n%s", h.logs.String())
	}
}
