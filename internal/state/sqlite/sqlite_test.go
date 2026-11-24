// SPDX-License-Identifier: AGPL-3.0-only

package sqlite_test

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/heliopsy/scrim/internal/audit"
	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/obs"
	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/state"
	"github.com/heliopsy/scrim/internal/state/migrate"
	"github.com/heliopsy/scrim/internal/state/sqlite"
	"github.com/heliopsy/scrim/internal/state/statetest"
)

func open(t *testing.T, path string, o sqlite.Options) *sqlite.Store {
	t.Helper()
	s, err := sqlite.Open(t.Context(), path, o)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if err := s.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestContract(t *testing.T) {
	statetest.Run(t, func(t *testing.T) state.Store {
		s, err := sqlite.Open(t.Context(), filepath.Join(t.TempDir(), "state.db"), sqlite.Options{})
		if err != nil {
			t.Fatal(err)
		}
		return s
	})
}

func TestOpenByName(t *testing.T) {
	dir := t.TempDir()
	cfg, err := config.Load(config.Default, config.EnvLayer([]string{
		"SCRIM_STATE_BACKEND=sqlite",
		"SCRIM_STATE_SQLITE_PATH=" + filepath.Join(dir, "s.db"),
	}))
	if err != nil {
		t.Fatal(err)
	}
	s, err := state.Open(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	if s.Backend() != sqlite.Name {
		t.Fatalf("backend = %s", s.Backend())
	}
}

func TestWALAndPrivateFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "state.db")
	s := open(t, path, sqlite.Options{})
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Errorf("state file mode %04o, want 0600", st.Mode().Perm())
	}
	if dst, _ := os.Stat(filepath.Dir(path)); dst.Mode().Perm() != 0o700 {
		t.Errorf("state dir mode %04o, want 0700", dst.Mode().Perm())
	}
	if v, err := s.SchemaVersion(t.Context()); err != nil || v != 3 {
		t.Errorf("SchemaVersion = %d, %v", v, err)
	}
	raw, err := sql.Open("sqlite", "file:"+path+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = raw.Close() }()
	var mode string
	if err := raw.QueryRow("PRAGMA journal_mode").Scan(&mode); err != nil || mode != "wal" {
		t.Errorf("journal_mode = %q, %v", mode, err)
	}
}

func TestSecondOpenRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	_ = open(t, path, sqlite.Options{})
	_, err := sqlite.Open(t.Context(), path, sqlite.Options{})
	var le *sqlite.LockedError
	if !errors.As(err, &le) {
		t.Fatalf("second open = %v, want LockedError", err)
	}
	if le.PID != os.Getpid() || !strings.Contains(err.Error(), path) || !strings.Contains(err.Error(), strconv.Itoa(os.Getpid())) {
		t.Fatalf("error does not name the file and holder: %v", err)
	}
}

// TestSecondProcessRefused runs a real second process against a held file.
func TestSecondProcessRefused(t *testing.T) {
	if p := os.Getenv("SCRIM_SQLITE_HOLDER_TEST"); p != "" {
		_, err := sqlite.Open(context.Background(), p, sqlite.Options{})
		fmt.Println(err)
		os.Exit(0)
	}
	path := filepath.Join(t.TempDir(), "state.db")
	_ = open(t, path, sqlite.Options{})
	cmd := exec.Command(os.Args[0], "-test.run=^TestSecondProcessRefused$") // #nosec G204 -- the test binary itself
	cmd.Env = append(os.Environ(), "SCRIM_SQLITE_HOLDER_TEST="+path)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("child: %v\n%s", err, out)
	}
	msg := string(out)
	if !strings.Contains(msg, "in use by process "+strconv.Itoa(os.Getpid())) || !strings.Contains(msg, path) {
		t.Fatalf("child output does not name the file and holder:\n%s", msg)
	}
}

func TestLockReleasedOnClose(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	s, err := sqlite.Open(t.Context(), path, sqlite.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s2, err := sqlite.Open(t.Context(), path, sqlite.Options{})
	if err != nil {
		t.Fatalf("reopen after close: %v", err)
	}
	_ = s2.Close()
}

func TestNetworkFilesystemRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	nfs := sqlite.WithDetectFS(sqlite.Options{}, func(string) sqlite.FSKind { return sqlite.FSNFS })
	_, err := sqlite.Open(t.Context(), path, nfs)
	if !errors.Is(err, sqlite.ErrNetworkFS) || !strings.Contains(err.Error(), "postgres") ||
		!strings.Contains(err.Error(), "state.sqlite.allow-network-filesystem") {
		t.Fatalf("Open on NFS = %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("refused open still created the database")
	}
	allowed := sqlite.WithDetectFS(sqlite.Options{AllowNetworkFS: true}, func(string) sqlite.FSKind { return sqlite.FSNFS })
	s := open(t, path, allowed)
	if s.Filesystem() != sqlite.FSNFS {
		t.Fatalf("Filesystem = %s", s.Filesystem())
	}
}

func TestRefusesNewerSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	s := open(t, path, sqlite.Options{})
	if err := s.Update(t.Context(), func(state.Tx) error { return nil }); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	raw, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`INSERT INTO schema_migrations (version, name, applied_at) VALUES (7, 'future', 'x')`); err != nil {
		t.Fatal(err)
	}
	_ = raw.Close()

	s2, err := sqlite.Open(t.Context(), path, sqlite.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s2.Close() }()
	err = s2.Migrate(t.Context())
	if !errors.Is(err, state.ErrSchemaTooNew) || !strings.Contains(err.Error(), "version 7") || !strings.Contains(err.Error(), "version 3") {
		t.Fatalf("Migrate on a newer schema = %v", err)
	}
}

// TestAuditFaultInjection fails the transaction between the state change
// and its audit entry, and at commit, and checks neither is left.
func TestAuditFaultInjection(t *testing.T) {
	for _, point := range []string{"AppendAudit", "Emit", "commit"} {
		t.Run(point, func(t *testing.T) {
			boom := errors.New("injected fault at " + point)
			var armed bool
			s := open(t, filepath.Join(t.TempDir(), "state.db"), sqlite.Options{Faults: func(op string) error {
				if armed && op == point {
					return boom
				}
				return nil
			}})
			armed = true
			err := applyGrant(t.Context(), s, "g1")
			if !errors.Is(err, boom) {
				t.Fatalf("Apply = %v, want the injected fault", err)
			}
			assertNothing(t, s)
			armed = false
			if err := applyGrant(t.Context(), s, "g1"); err != nil {
				t.Fatalf("Apply after the fault: %v", err)
			}
		})
	}
}

func applyGrant(ctx context.Context, s state.Store, id string) error {
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	return state.Apply(ctx, s, func(tx state.Tx) (state.Change, error) {
		err := tx.CreateGrant(ctx, &state.Grant{ID: id, CreatedAt: t0, ExpiresAt: t0.Add(time.Hour)})
		return state.Change{
			Audit:  audit.Entry{Action: "grant.created", Subject: id, Time: t0},
			Events: []state.Event{{Kind: "grant.created", Subject: id, Time: t0}},
		}, err
	})
}

func assertNothing(t *testing.T, s state.Store) {
	t.Helper()
	err := s.View(t.Context(), func(tx state.Tx) error {
		if _, err := tx.GetGrant(t.Context(), "g1"); !errors.Is(err, state.ErrNotFound) {
			t.Errorf("grant survived the fault: %v", err)
		}
		if es, _ := tx.QueryAudit(t.Context(), state.AuditQuery{}); len(es) != 0 {
			t.Errorf("audit survived the fault: %+v", es)
		}
		if ev, _ := tx.EventsAfter(t.Context(), 0, 0); len(ev) != 0 {
			t.Errorf("events survived the fault: %+v", ev)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestConcurrentWriters checks the single-writer discipline: many goroutines
// writing at once all succeed, none sees SQLITE_BUSY, and readers run
// alongside.
func TestConcurrentWriters(t *testing.T) {
	s := open(t, filepath.Join(t.TempDir(), "state.db"), sqlite.Options{})
	const writers, each = 8, 25
	var wg sync.WaitGroup
	errs := make(chan error, writers*each*2)
	for w := range writers {
		wg.Add(2)
		go func() {
			defer wg.Done()
			for i := range each {
				if err := applyGrant(t.Context(), s, fmt.Sprintf("g-%d-%d", w, i)); err != nil {
					errs <- err
				}
			}
		}()
		go func() {
			defer wg.Done()
			for range each {
				if err := s.View(t.Context(), func(tx state.Tx) error {
					_, err := tx.QueryAudit(t.Context(), state.AuditQuery{Limit: 10})
					return err
				}); err != nil {
					errs <- err
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	_ = s.View(t.Context(), func(tx state.Tx) error {
		es, _ := tx.QueryAudit(t.Context(), state.AuditQuery{})
		ev, _ := tx.EventsAfter(t.Context(), 0, 0)
		if len(es) != writers*each || len(ev) != writers*each {
			t.Errorf("audit %d, events %d, want %d each", len(es), len(ev), writers*each)
		}
		return nil
	})
}

// TestNoValueInDatabaseFile seeds known values, writes rows that carry them
// in every free-text field, then reads the database file and its WAL as raw
// bytes: no value may appear, in any common encoding.
func TestNoValueInDatabaseFile(t *testing.T) {
	leaks := []string{"sk-ant-LEAKTEST-0f1e2d3c4b5a69788796a5b4", "ghp_LEAKTESTzyxwvutsrqponmlkjihgfedcba98"}
	vals := make([]secret.Value, len(leaks))
	for i, l := range leaks {
		vals[i] = secret.FromString(l)
	}
	path := filepath.Join(t.TempDir(), "state.db")
	s := open(t, path, sqlite.Options{Scrubber: obs.NewValueScrubber(vals...)})
	statetest.LeakTraffic(t, s, leaks)

	var dump []byte
	for _, p := range []string{path, path + "-wal"} {
		b, err := os.ReadFile(p) // #nosec G304 -- test file
		if err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
		dump = append(dump, b...)
	}
	if !bytes.Contains(dump, []byte(secret.Marker)) {
		t.Fatal("no marker in the database: the scrubber was not exercised")
	}
	for _, l := range leaks {
		for _, f := range []string{l, hex.EncodeToString([]byte(l)), base64.StdEncoding.EncodeToString([]byte(l))} {
			if bytes.Contains(dump, []byte(f)) {
				t.Errorf("database file holds a seeded value (%d bytes form)", len(f))
			}
		}
	}
}

// TestUpgradeKeepsSessions migrates a schema 1 database with a session in it
// to the current schema: the row survives, the new columns take their
// defaults, and the downgrade refusal still names the new version.
func TestUpgradeKeepsSessions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	all, err := sqlite.Migrations()
	if err != nil || len(all) < 2 {
		t.Fatalf("Migrations = %d, %v", len(all), err)
	}
	raw, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := migrate.Run(t.Context(), raw, migrate.SQLite, all[:1], migrate.Hooks{}); err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`INSERT INTO sessions (id, agent_id, agent, token_hash, created_at, expires_at, labels)
		VALUES ('old', 'a1', '{"ID":"a1"}', 'sha256:old', 1, 2, '{}')`); err != nil {
		t.Fatal(err)
	}
	_ = raw.Close()

	s := open(t, path, sqlite.Options{})
	if v, err := s.SchemaVersion(t.Context()); err != nil || v != migrate.Latest(all) {
		t.Fatalf("SchemaVersion = %d, %v", v, err)
	}
	err = s.View(t.Context(), func(tx state.Tx) error {
		got, err := tx.GetSession(t.Context(), "old")
		if err != nil {
			return err
		}
		if got.Agent.ID != "a1" || got.TokenHash != "sha256:old" || got.UID != 0 || got.RootPID != 0 ||
			got.Scopes != nil || got.Name != "" || got.EndReason != "" {
			t.Errorf("upgraded session = %+v", got)
		}
		list, err := tx.ListSessions(t.Context(), state.SessionFilter{AgentID: "a1", Open: true})
		if err != nil || len(list) != 1 {
			t.Errorf("ListSessions after upgrade = %+v, %v", list, err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// OpenReadOnly takes no lock and writes nothing: the owner can open the file
// while a reader has it, the reader sees committed rows, and writes and
// migrations through the reader fail.
func TestOpenReadOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	if _, err := sqlite.OpenReadOnly(t.Context(), path); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("read-only open of a missing file = %v, want ErrNotExist", err)
	}
	if _, err := os.Stat(path); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("read-only open created %s", path)
	}
	seed := open(t, path, sqlite.Options{})
	if err := seed.Close(); err != nil {
		t.Fatal(err)
	}

	ro, err := sqlite.OpenReadOnly(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ro.Close() }()
	if sqlite.Holder(path) != 0 {
		t.Fatalf("holder recorded with no owner open")
	}
	owner := open(t, path, sqlite.Options{})
	if got := sqlite.Holder(path); got != os.Getpid() {
		t.Fatalf("Holder = %d, want %d", got, os.Getpid())
	}
	if err := applyGrant(t.Context(), owner, "g1"); err != nil {
		t.Fatal(err)
	}
	err = ro.View(t.Context(), func(tx state.Tx) error {
		_, err := tx.GetGrant(t.Context(), "g1")
		return err
	})
	if err != nil {
		t.Fatalf("read-only store does not see the owner's commit: %v", err)
	}
	if err := applyGrant(t.Context(), ro, "g2"); err == nil {
		t.Fatal("write through a read-only store succeeded")
	}
	if err := ro.Migrate(t.Context()); !errors.Is(err, sqlite.ErrReadOnly) {
		t.Fatalf("Migrate = %v, want ErrReadOnly", err)
	}
}
