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
	// Metrics on: the test checks the state backend is instrumented.
	a, err := app.New(context.Background(), isolated(t, "SCRIM_STATE_BACKEND=sqlite", "SCRIM_METRICS_ENABLED=true"), &logs)
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

// TestReplicasNeedSharedBackends: more than one replica refuses to start on
// local events, unshared state or without shared placeholder keys
// (specs/state-and-scaling "Replica count is declared").
func TestReplicasNeedSharedBackends(t *testing.T) {
	for _, tc := range []struct {
		env  []string
		want string
	}{
		{[]string{"SCRIM_EVENTS_BACKEND=local"}, "events.backend"},
		{[]string{"SCRIM_EVENTS_BACKEND=postgres"}, "state.backend"},
		{[]string{"SCRIM_EVENTS_BACKEND=postgres", "SCRIM_STATE_BACKEND=postgres"}, "redaction.placeholder-keys"},
	} {
		var logs bytes.Buffer
		a, err := app.New(context.Background(), isolated(t, append([]string{"SCRIM_DEPLOYMENT_REPLICAS=2"}, tc.env...)...), &logs)
		if err == nil {
			_ = a.Close()
			t.Fatalf("%v: started with two replicas", tc.env)
		}
		if !strings.Contains(err.Error(), tc.want) || !strings.Contains(err.Error(), "deployment.replicas") {
			t.Fatalf("%v: error %q does not name %s", tc.env, err, tc.want)
		}
	}
}

// TestConfigDigestIsValueFree: the digest follows the configuration and
// holds nothing of it.
func TestConfigDigestIsValueFree(t *testing.T) {
	load := func(env ...string) *config.Config {
		t.Helper()
		cfg, err := config.Load(config.Default, config.EnvLayer(env))
		if err != nil {
			t.Fatal(err)
		}
		return cfg
	}
	a, b := app.ConfigDigest(load()), app.ConfigDigest(load("SCRIM_APPROVALS_TIMEOUT=5m"))
	if a == b || !strings.HasPrefix(a, "sha256:") || len(a) != len("sha256:")+16 {
		t.Fatalf("digests %q %q", a, b)
	}
	if a != app.ConfigDigest(load()) {
		t.Fatal("digest is not deterministic")
	}
}
