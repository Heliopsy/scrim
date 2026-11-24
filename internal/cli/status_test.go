// SPDX-License-Identifier: AGPL-3.0-only

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/heliopsy/scrim/internal/audit"
	"github.com/heliopsy/scrim/internal/auditlog"
	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/policy"
	"github.com/heliopsy/scrim/internal/state"
	"github.com/heliopsy/scrim/internal/state/sqlite"
	"github.com/heliopsy/scrim/internal/status"
)

// isolatedEnv reads no config outside the test and keeps SQLite state in a
// temp dir.
func isolatedEnv(t *testing.T, extra ...string) []string {
	dir := t.TempDir()
	return append([]string{"HOME=" + dir, "XDG_CONFIG_HOME=" + dir, "XDG_STATE_HOME=" + dir,
		"SCRIM_STATE_BACKEND=sqlite", "SCRIM_STATE_SQLITE_PATH=" + filepath.Join(dir, "scrim", "state.db")}, extra...)
}

func TestStatusJSONShowsWeakenedAndState(t *testing.T) {
	env := isolatedEnv(t, "SCRIM_STATE_SQLITE_ALLOW_NETWORK_FILESYSTEM=true")
	seedState(t, strings.TrimPrefix(env[4], "SCRIM_STATE_SQLITE_PATH="))
	e, out, errb := newEnv(env...)
	if code := Run(context.Background(), e, []string{"status", "-o", "json"}); code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	var r status.Report
	if err := json.Unmarshal(out.Bytes(), &r); err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	if len(r.Weakened) != 1 || r.Weakened[0].Key != "state.sqlite.allow-network-filesystem" {
		t.Fatalf("weakened = %+v", r.Weakened)
	}
	if r.State.Backend != "sqlite" || !r.State.Healthy || r.State.SchemaVersion != 2 || r.Config == nil {
		t.Fatalf("state = %+v config = %+v", r.State, r.Config)
	}
	// The data plane is not reported by this process, so it is degraded,
	// never claimed healthy.
	if r.DataPlane.Running || r.OK() {
		t.Fatalf("status claims health it could not check: %+v", r)
	}
}

// TestBinaryPassIsWeakened: redaction.binary pass is reported as weakened by
// status and doctor; block, also a value other than the default, is not.
func TestBinaryPassIsWeakened(t *testing.T) {
	for v, want := range map[string]bool{"pass": true, "block": false, "scan": false} {
		e, out, errb := newEnv(isolatedEnv(t, "SCRIM_REDACTION_BINARY="+v)...)
		if code := Run(context.Background(), e, []string{"status", "-o", "json"}); code != 0 {
			t.Fatalf("%s: exit %d: %s", v, code, errb.String())
		}
		var r status.Report
		if err := json.Unmarshal(out.Bytes(), &r); err != nil {
			t.Fatalf("%v\n%s", err, out.String())
		}
		got := len(r.Weakened) == 1 && r.Weakened[0].Key == "redaction.binary"
		if got != want || (!want && len(r.Weakened) != 0) {
			t.Errorf("%s: status weakened = %+v", v, r.Weakened)
		}
		e, out, _ = newEnv(isolatedEnv(t, "SCRIM_REDACTION_BINARY="+v)...)
		_ = Run(context.Background(), e, []string{"doctor"})
		if got := strings.Contains(out.String(), "redaction.binary"); got != want {
			t.Errorf("%s: doctor names redaction.binary = %v:\n%s", v, got, out.String())
		}
	}
}

func TestStatusHumanAndBadOutput(t *testing.T) {
	e, out, _ := newEnv(isolatedEnv(t)...)
	if code := Run(context.Background(), e, []string{"status"}); code != 0 {
		t.Fatalf("exit %d", code)
	}
	for _, want := range []string{"Weakened protections", "State", "sqlite at "} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("status lacks %q:\n%s", want, out.String())
		}
	}
	e, _, errb := newEnv(isolatedEnv(t)...)
	if code := Run(context.Background(), e, []string{"status", "-o", "yaml"}); code != 1 || !strings.Contains(errb.String(), "yaml") {
		t.Fatalf("bad output accepted: %d %s", code, errb.String())
	}
}

func TestStatusWhileStateHeld(t *testing.T) {
	env := isolatedEnv(t)
	path := strings.TrimPrefix(env[4], "SCRIM_STATE_SQLITE_PATH=")
	held, err := sqlite.Open(context.Background(), path, sqlite.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = held.Close() }()
	e, out, errb := newEnv(env...)
	if code := Run(context.Background(), e, []string{"status", "--json"}); code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	var r status.Report
	_ = json.Unmarshal(out.Bytes(), &r)
	if !r.State.Healthy || !strings.Contains(r.State.Detail, "in use by scrim process") {
		t.Fatalf("held state = %+v", r.State)
	}
}

func TestDoctorFailsWithoutDataPlane(t *testing.T) {
	e, out, errb := newEnv(isolatedEnv(t)...)
	if code := Run(context.Background(), e, []string{"doctor"}); code != 1 {
		t.Fatalf("exit %d, want 1", code)
	}
	if !strings.Contains(out.String(), "[fail] data-plane") || !strings.Contains(out.String(), "fix:") ||
		!strings.Contains(errb.String(), "checks failed") {
		t.Fatalf("doctor output:\n%s\n%s", out.String(), errb.String())
	}
	e, out, _ = newEnv(isolatedEnv(t)...)
	_ = Run(context.Background(), e, []string{"doctor", "-o", "json"})
	var d status.Diagnosis
	if err := json.Unmarshal(out.Bytes(), &d); err != nil || d.Failed == 0 {
		t.Fatalf("doctor json = %s (%v)", out.String(), err)
	}
}

func TestAuditLog(t *testing.T) {
	env := isolatedEnv(t)
	path := strings.TrimPrefix(env[4], "SCRIM_STATE_SQLITE_PATH=")
	s, err := sqlite.Open(context.Background(), path, sqlite.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	err = s.Update(context.Background(), func(tx state.Tx) error {
		for i, e := range []audit.Entry{
			{Action: "decision", Agent: policy.Agent{ID: "claude-laptop"}, Effect: policy.Ask, Outcome: audit.OutcomePending, Time: now.Add(-3 * time.Hour)},
			{Action: "decision", Agent: policy.Agent{ID: "claude-laptop"}, Effect: policy.Ask, Outcome: audit.OutcomePending, Time: now.Add(-30 * time.Minute)},
			{Action: "decision", Agent: policy.Agent{ID: "other"}, Effect: policy.Ask, Time: now.Add(-10 * time.Minute)},
			{Action: "decision", Agent: policy.Agent{ID: "claude-laptop"}, Effect: policy.Allow, Time: now.Add(-5 * time.Minute)},
			{Action: "decision", Agent: policy.Agent{ID: "claude-laptop"}, Effect: policy.Ask, Outcome: audit.OutcomeOK, Time: now.Add(-time.Minute), Target: "api.github.com"},
		} {
			e.RequestID = string(rune('a' + i))
			if err := tx.AppendAudit(context.Background(), &e); err != nil {
				return err
			}
		}
		return nil
	})
	_ = s.Close()
	if err != nil {
		t.Fatal(err)
	}

	e, out, errb := newEnv(env...)
	if code := Run(context.Background(), e, []string{"audit", "log", "--agent", "claude-laptop", "--decision", "ask", "--since", "1h", "-o", "json"}); code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	var p auditlog.Page
	if err := json.Unmarshal(out.Bytes(), &p); err != nil {
		t.Fatal(err)
	}
	if len(p.Entries) != 2 || p.Entries[0].RequestID != "e" || p.Entries[1].RequestID != "b" {
		t.Fatalf("asks of claude-laptop in the last hour, newest first = %+v", p.Entries)
	}

	e, out, _ = newEnv(env...)
	if code := Run(context.Background(), e, []string{"audit", "log", "--limit", "2"}); code != 0 {
		t.Fatal(code)
	}
	if !strings.Contains(out.String(), "api.github.com") || !strings.Contains(out.String(), "more: --before") {
		t.Fatalf("human output:\n%s", out.String())
	}

	for _, bad := range [][]string{{"--decision", "maybe"}, {"--since", "yesterday"}, {"--limit", "5000"}, {"--ref", "nope"}} {
		e, _, errb := newEnv(env...)
		if code := Run(context.Background(), e, append([]string{"audit", "log"}, bad...)); code != 1 {
			t.Errorf("%v accepted: %s", bad, errb.String())
		}
	}
}

// statusStateConfig is a configuration whose SQLite state lives in a temp
// dir, and that path.
func statusStateConfig(t *testing.T) (*config.Config, string) {
	t.Helper()
	env := isolatedEnv(t)
	cfg, err := config.Build(config.Options{Registry: config.Default, Environ: env, SystemDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	return cfg, strings.TrimPrefix(env[4], "SCRIM_STATE_SQLITE_PATH=")
}

// seedState creates and migrates the SQLite state at path, as a first
// daemon start would, and closes it.
func seedState(t *testing.T, path string) {
	t.Helper()
	s, err := sqlite.Open(t.Context(), path, sqlite.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
}

// A daemon that starts while status has the state open must still get the
// database: status never takes the process lock or writes.
func TestStatusDoesNotBlockStartingDaemon(t *testing.T) {
	cfg, path := statusStateConfig(t)
	seedState(t, path)

	st, closeStatus := openStateForStatus(t.Context(), cfg)
	defer closeStatus()
	daemon, err := sqlite.Open(t.Context(), path, sqlite.Options{})
	if err != nil {
		t.Fatalf("daemon start while status has the state open: %v", err)
	}
	defer func() { _ = daemon.Close() }()
	if err := daemon.Migrate(t.Context()); err != nil {
		t.Fatalf("daemon migrate while status has the state open: %v", err)
	}
	got := st.StateStatus(t.Context())
	if !got.Healthy || got.SchemaVersion != 2 || got.Location != path {
		t.Fatalf("status state = %+v", got)
	}
}

// Status before the first start reports the missing file and creates
// nothing, so the daemon creates the database with its own permissions.
func TestStatusDoesNotCreateState(t *testing.T) {
	cfg, path := statusStateConfig(t)
	st, closeStatus := openStateForStatus(t.Context(), cfg)
	got := st.StateStatus(t.Context())
	closeStatus()
	if !got.Healthy || !strings.Contains(got.Detail, "not created yet") {
		t.Fatalf("status state = %+v", got)
	}
	for _, p := range []string{path, path + ".lock", path + "-wal", path + "-shm"} {
		if _, err := os.Stat(p); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("status created %s (%v)", p, err)
		}
	}
}
