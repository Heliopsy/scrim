// SPDX-License-Identifier: AGPL-3.0-only

package app_test

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/heliopsy/scrim/internal/app"
	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/policy"
	"github.com/heliopsy/scrim/internal/state"
)

func TestNewDefaults(t *testing.T) {
	var logs bytes.Buffer
	a, err := app.New(context.Background(), isolated(t), &logs)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = a.Close() }()
	d, err := a.Policy.Decide(context.Background(), policy.Request{})
	if err != nil || d.Effect != policy.Deny {
		t.Fatalf("default policy = %+v, %v", d, err)
	}
	if rep := a.Health.Run(context.Background(), true); rep.Status != "ok" {
		t.Fatalf("readiness = %+v", rep)
	}
}

func TestWeakenedSettingWarns(t *testing.T) {
	var logs bytes.Buffer
	a, err := app.New(context.Background(), isolated(t, "SCRIM_POLICY_DEFAULT=allow"), &logs)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = a.Close() }()
	if !strings.Contains(logs.String(), "weakened protection active") || !strings.Contains(logs.String(), "policy.default") {
		t.Fatalf("no start-up warning: %s", logs.String())
	}
}

// isolated returns config options that read no file outside the test.
func isolated(t *testing.T, env ...string) config.Options {
	t.Helper()
	dir := t.TempDir()
	return config.Options{
		Registry:  config.Default,
		Environ:   append([]string{"HOME=" + dir, "XDG_CONFIG_HOME=" + dir, "XDG_STATE_HOME=" + dir}, env...),
		SystemDir: dir,
	}
}

func TestSQLiteBackendWired(t *testing.T) {
	var logs bytes.Buffer
	a, err := app.New(context.Background(), isolated(t, "SCRIM_STATE_BACKEND=sqlite"), &logs)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = a.Close() }()
	if a.State.Backend() != "sqlite" {
		t.Fatalf("backend = %s", a.State.Backend())
	}
	if rep := a.Health.Run(context.Background(), true); rep.Status != "ok" {
		t.Fatalf("readiness = %+v", rep)
	}
	if err := a.State.View(context.Background(), func(state.Tx) error { return nil }); err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	a.Metrics.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if !strings.Contains(rec.Body.String(), `scrim_state_transaction_seconds_count{backend="sqlite",kind="view"}`) {
		t.Errorf("state transactions not observed:\n%s", rec.Body.String())
	}
	if st := a.Config.Status(); st.Version != 1 {
		t.Fatalf("config status = %+v", st)
	}
}

func TestDataPlaneNeedsABinary(t *testing.T) {
	var logs bytes.Buffer
	a, err := app.New(context.Background(), isolated(t, "SCRIM_DATAPLANE_PATH=/nonexistent/scrim-dataplane"), &logs)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = a.Close() }()
	if _, err := a.DataPlane(); err == nil {
		t.Fatal("a missing data plane binary was accepted")
	}
}
