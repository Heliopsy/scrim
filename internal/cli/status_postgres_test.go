// SPDX-License-Identifier: AGPL-3.0-only

package cli

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/state/migrate"
	"github.com/heliopsy/scrim/internal/state/postgres"
	"github.com/heliopsy/scrim/internal/testing/pgtest"
)

// The daemons' migration lock key (postgres.migrateLockKey).
const pgMigrateLockKey int64 = 0x7363_7269_6d00_0001

// pgStatusConfig is a configuration whose state is the PostgreSQL database
// dsn names.
func pgStatusConfig(t *testing.T, dsn string) *config.Config {
	t.Helper()
	dir := t.TempDir()
	cfg, err := config.Build(config.Options{Registry: config.Default, SystemDir: dir, Environ: []string{
		"HOME=" + dir, "XDG_CONFIG_HOME=" + dir, "XDG_STATE_HOME=" + dir,
		"SCRIM_STATE_BACKEND=postgres", "SCRIM_STATE_POSTGRES_DSN=env:SCRIMTEST_STATUS_PG_DSN",
		"SCRIMTEST_STATUS_PG_DSN=" + dsn,
	}})
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func pgDB(t *testing.T, dsn string) *sql.DB {
	t.Helper()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// seedPostgres migrates the database to version upTo, as a daemon of the
// release that shipped it would.
func seedPostgres(t *testing.T, dsn string, upTo int) {
	t.Helper()
	all, err := postgres.Migrations()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := migrate.Run(t.Context(), pgDB(t, dsn), migrate.Postgres, all[:upTo], migrate.Hooks{}); err != nil {
		t.Fatal(err)
	}
}

func latestPostgresSchema(t *testing.T) int {
	t.Helper()
	all, err := postgres.Migrations()
	if err != nil {
		t.Fatal(err)
	}
	return migrate.Latest(all)
}

// publicRelations lists every table, view, sequence and index in the public
// schema.
func publicRelations(t *testing.T, db *sql.DB) []string {
	t.Helper()
	rows, err := db.QueryContext(t.Context(), `SELECT c.relname FROM pg_class c
		JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'public' ORDER BY 1`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatal(err)
		}
		out = append(out, n)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func pgSchemaVersion(t *testing.T, db *sql.DB) int {
	t.Helper()
	var v int
	if err := db.QueryRowContext(t.Context(), `SELECT COALESCE(MAX(version), 0) FROM schema_migrations`).Scan(&v); err != nil {
		t.Fatal(err)
	}
	return v
}

// Status against a database no daemon has used yet reports it as not
// created and creates nothing: the first daemon owns the schema.
func TestStatusPostgresEmptyCreatesNothing(t *testing.T) {
	dsn := pgtest.FreshDSN(t)
	st, closeStatus := openStateForStatus(t.Context(), pgStatusConfig(t, dsn))
	got := st.StateStatus(t.Context())
	closeStatus()
	if !got.Healthy || got.SchemaVersion != 0 || !strings.Contains(got.Detail, "not created yet") {
		t.Errorf("status state = %+v", got)
	}
	if rels := publicRelations(t, pgDB(t, dsn)); len(rels) != 0 {
		t.Errorf("status created %v", rels)
	}
}

// Status against a schema an older release left behind reports it and
// leaves the migration to a daemon, which takes the migration lock.
func TestStatusPostgresOldSchemaNotMigrated(t *testing.T) {
	dsn := pgtest.FreshDSN(t)
	seedPostgres(t, dsn, 1)
	st, closeStatus := openStateForStatus(t.Context(), pgStatusConfig(t, dsn))
	got := st.StateStatus(t.Context())
	closeStatus()
	want := latestPostgresSchema(t)
	if !got.Healthy || got.SchemaVersion != 1 || !strings.Contains(got.Detail, "behind") ||
		!strings.Contains(got.Detail, fmt.Sprint(want)) {
		t.Errorf("status state = %+v", got)
	}
	if v := pgSchemaVersion(t, pgDB(t, dsn)); v != 1 {
		t.Errorf("status migrated the schema to %d", v)
	}
}

// Status from a binary older than the schema reports both versions instead
// of the generic open failure.
func TestStatusPostgresSchemaAhead(t *testing.T) {
	dsn := pgtest.FreshDSN(t)
	want := latestPostgresSchema(t)
	seedPostgres(t, dsn, want)
	if _, err := pgDB(t, dsn).ExecContext(t.Context(),
		`INSERT INTO schema_migrations (version, name, applied_at) VALUES ($1, 'future', 'now')`, want+1); err != nil {
		t.Fatal(err)
	}
	st, closeStatus := openStateForStatus(t.Context(), pgStatusConfig(t, dsn))
	got := st.StateStatus(t.Context())
	closeStatus()
	if got.Healthy || got.SchemaVersion != want+1 || !strings.Contains(got.Detail, "ahead") {
		t.Errorf("status state = %+v", got)
	}
}

// Status works for a role that can only read: it runs no DDL.
func TestStatusPostgresReadOnlyRole(t *testing.T) {
	dsn := pgtest.FreshDSN(t)
	want := latestPostgresSchema(t)
	seedPostgres(t, dsn, want)
	admin := pgDB(t, dsn)
	role, password := "scrim_ro_"+randHex(t, 4), randHex(t, 16)
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	dbName := strings.TrimPrefix(u.Path, "/")
	for _, q := range []string{
		fmt.Sprintf(`CREATE ROLE %s LOGIN PASSWORD '%s'`, role, password),
		`REVOKE CREATE ON SCHEMA public FROM PUBLIC`,
		fmt.Sprintf(`GRANT CONNECT ON DATABASE %s TO %s`, dbName, role),
		fmt.Sprintf(`GRANT USAGE ON SCHEMA public TO %s`, role),
		fmt.Sprintf(`GRANT SELECT ON ALL TABLES IN SCHEMA public TO %s`, role),
	} {
		if _, err := admin.ExecContext(t.Context(), q); err != nil {
			t.Fatalf("%s: %v", strings.Fields(q)[0], err)
		}
	}
	t.Cleanup(func() {
		ctx := context.WithoutCancel(t.Context())
		_, _ = admin.ExecContext(ctx, `DROP OWNED BY `+role)
		_, _ = admin.ExecContext(ctx, fmt.Sprintf(`REVOKE ALL ON DATABASE %s FROM %s`, dbName, role))
		_, _ = admin.ExecContext(ctx, `DROP ROLE IF EXISTS `+role)
	})
	u.User = url.UserPassword(role, password)

	st, closeStatus := openStateForStatus(t.Context(), pgStatusConfig(t, u.String()))
	got := st.StateStatus(t.Context())
	closeStatus()
	if !got.Healthy || got.SchemaVersion != want || got.Detail != "" {
		t.Errorf("status state with a read-only role = %+v", got)
	}
	if !strings.Contains(got.Location, role+"@") || strings.Contains(got.Location, password) {
		t.Errorf("location = %q", got.Location)
	}
}

// A daemon migrating while status runs is never held up by it, and status
// does not wait for the migration either: status takes no advisory lock.
func TestStatusPostgresDoesNotBlockMigratingDaemon(t *testing.T) {
	dsn := pgtest.FreshDSN(t)
	cfg := pgStatusConfig(t, dsn)
	admin := pgDB(t, dsn)

	// A daemon is in the middle of migrating: it holds the migration lock.
	conn, err := admin.Conn(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.ExecContext(t.Context(), `SELECT pg_advisory_lock($1)`, pgMigrateLockKey); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	st, closeStatus := openStateForStatus(ctx, cfg)
	defer closeStatus()
	got := st.StateStatus(ctx)
	cancel()
	if !got.Healthy || got.SchemaVersion != 0 {
		t.Fatalf("status while a daemon holds the migration lock = %+v", got)
	}
	var held int
	if err := admin.QueryRowContext(t.Context(), `SELECT COUNT(*) FROM pg_locks l
		JOIN pg_stat_activity a ON a.pid = l.pid
		WHERE l.locktype = 'advisory' AND a.application_name = $1`, postgres.StatusApplicationName).Scan(&held); err != nil {
		t.Fatal(err)
	}
	if held != 0 {
		t.Errorf("status holds %d advisory locks", held)
	}
	if _, err := conn.ExecContext(t.Context(), `SELECT pg_advisory_unlock($1)`, pgMigrateLockKey); err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()

	// A daemon starts and migrates while status still has its connection.
	dctx, dcancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer dcancel()
	daemon, err := postgres.Open(dctx, secret.FromString(dsn), postgres.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = daemon.Close() }()
	if err := daemon.Migrate(dctx); err != nil {
		t.Fatalf("daemon migrate while status is connected: %v", err)
	}
	want := latestPostgresSchema(t)
	if got := st.StateStatus(t.Context()); !got.Healthy || got.SchemaVersion != want || got.Detail != "" {
		t.Errorf("status after the daemon migrated = %+v", got)
	}
}

func randHex(t *testing.T, n int) string {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}
