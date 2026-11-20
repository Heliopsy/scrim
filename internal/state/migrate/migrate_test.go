// SPDX-License-Identifier: AGPL-3.0-only

package migrate_test

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"testing/fstest"

	_ "modernc.org/sqlite"

	"github.com/heliopsy/scrim/internal/state/migrate"
)

func openDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+filepath.Join(t.TempDir(), "m.db"))
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func set(files map[string]string) fstest.MapFS {
	fs := fstest.MapFS{}
	for k, v := range files {
		fs[k] = &fstest.MapFile{Data: []byte(v)}
	}
	return fs
}

func TestLoadOrdersAndValidates(t *testing.T) {
	all, err := migrate.Load(set(map[string]string{
		"0002_b.sql": "CREATE TABLE b (x INTEGER)",
		"0001_a.sql": "CREATE TABLE a (x INTEGER)",
		"README.md":  "ignored",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 || all[0].Name != "a" || all[1].Version != 2 {
		t.Fatalf("got %+v", all)
	}

	bad := map[string]map[string]string{
		"gap":       {"0001_a.sql": "", "0003_c.sql": ""},
		"bad name":  {"0001_A.sql": ""},
		"no number": {"a.sql": ""},
		"starts 2":  {"0002_b.sql": ""},
	}
	for name, files := range bad {
		if _, err := migrate.Load(set(files)); err == nil {
			t.Errorf("%s: Load accepted %v", name, files)
		}
	}
}

func TestRunAppliesInOrderAndIsIdempotent(t *testing.T) {
	ctx := context.Background()
	db := openDB(t)
	all, _ := migrate.Load(set(map[string]string{
		"0001_a.sql": "CREATE TABLE a (x INTEGER); INSERT INTO a VALUES (1);",
		"0002_b.sql": "ALTER TABLE a ADD COLUMN y TEXT NOT NULL DEFAULT 'semi;colon'",
	}))
	res, err := migrate.Run(ctx, db, migrate.SQLite, all, migrate.Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	if res != (migrate.Result{From: 0, To: 2, Applied: 2}) {
		t.Fatalf("first run = %+v", res)
	}
	res, err = migrate.Run(ctx, db, migrate.SQLite, all, migrate.Hooks{})
	if err != nil || res.Applied != 0 || res.To != 2 {
		t.Fatalf("second run = %+v, %v", res, err)
	}
	var y string
	if err := db.QueryRow(`SELECT y FROM a`).Scan(&y); err != nil || y != "semi;colon" {
		t.Fatalf("y = %q, %v", y, err)
	}
	if v, err := migrate.Current(ctx, db); err != nil || v != 2 {
		t.Fatalf("Current = %d, %v", v, err)
	}
}

func TestFailedMigrationLeavesPreviousVersion(t *testing.T) {
	ctx := context.Background()
	db := openDB(t)
	all, _ := migrate.Load(set(map[string]string{
		"0001_a.sql": "CREATE TABLE a (x INTEGER)",
		"0002_b.sql": "CREATE TABLE b (x INTEGER); CREATE TABLE nope (",
	}))
	res, err := migrate.Run(ctx, db, migrate.SQLite, all, migrate.Hooks{})
	if err == nil || !strings.Contains(err.Error(), "0002_b") {
		t.Fatalf("err = %v, want one naming 0002_b", err)
	}
	if res.To != 1 {
		t.Fatalf("To = %d, want 1", res.To)
	}
	if _, err := db.Exec(`SELECT * FROM b`); err == nil {
		t.Fatal("table b exists although its migration failed")
	}
}

func TestRefusesNewerSchema(t *testing.T) {
	ctx := context.Background()
	db := openDB(t)
	newer, _ := migrate.Load(set(map[string]string{
		"0001_a.sql": "CREATE TABLE a (x INTEGER)",
		"0002_b.sql": "CREATE TABLE b (x INTEGER)",
	}))
	if _, err := migrate.Run(ctx, db, migrate.SQLite, newer, migrate.Hooks{}); err != nil {
		t.Fatal(err)
	}
	_, err := migrate.Run(ctx, db, migrate.SQLite, newer[:1], migrate.Hooks{})
	if !errors.Is(err, migrate.ErrSchemaTooNew) {
		t.Fatalf("err = %v, want ErrSchemaTooNew", err)
	}
	var tn *migrate.TooNewError
	if !errors.As(err, &tn) || tn.Database != 2 || tn.Known != 1 {
		t.Fatalf("err = %#v", err)
	}
	if !strings.Contains(err.Error(), "2") || !strings.Contains(err.Error(), "1") {
		t.Fatalf("message does not name both versions: %v", err)
	}
}

func TestLockHookWrapsRun(t *testing.T) {
	ctx := context.Background()
	db := openDB(t)
	var locked, unlocked bool
	all, _ := migrate.Load(set(map[string]string{"0001_a.sql": "CREATE TABLE a (x INTEGER)"}))
	_, err := migrate.Run(ctx, db, migrate.SQLite, all, migrate.Hooks{
		Lock: func(context.Context, *sql.Conn) (func(), error) {
			locked = true
			return func() { unlocked = true }, nil
		},
	})
	if err != nil || !locked || !unlocked {
		t.Fatalf("err=%v locked=%v unlocked=%v", err, locked, unlocked)
	}
	_, err = migrate.Run(ctx, openDB(t), migrate.SQLite, all, migrate.Hooks{
		Lock: func(context.Context, *sql.Conn) (func(), error) { return nil, errors.New("busy") },
	})
	if err == nil {
		t.Fatal("Run ignored a failed lock")
	}
}

func TestSplit(t *testing.T) {
	got := migrate.Split(`
-- a comment; with a semicolon
CREATE TABLE a (x TEXT DEFAULT 'a;b'); /* block; comment */
CREATE TABLE "we;ird" (y INTEGER);
`)
	want := []string{`CREATE TABLE a (x TEXT DEFAULT 'a;b')`, `CREATE TABLE "we;ird" (y INTEGER)`}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Split = %q, want %q", got, want)
	}
}
