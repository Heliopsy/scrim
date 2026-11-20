// SPDX-License-Identifier: AGPL-3.0-only

// Package migrate applies embedded, versioned, forward-only SQL migrations to
// a state database and refuses a schema newer than the binary understands.
//
// Each backend embeds its own migration files named NNNN_name.sql. Versions
// are consecutive integers starting at 1, so a gap or a duplicate is caught
// when the files are loaded rather than when a database is half migrated.
// Every migration runs in its own transaction together with the row that
// records it in schema_migrations, so a failed migration leaves the database
// at the previous version.
package migrate

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Migration is one schema step.
type Migration struct {
	Version int
	Name    string
	SQL     string
}

// Dialect is the SQL flavour a migration set runs against.
type Dialect int

// Dialects the runner supports.
const (
	SQLite Dialect = iota + 1
	Postgres
)

// String names the dialect for messages.
func (d Dialect) String() string {
	switch d {
	case SQLite:
		return "sqlite"
	case Postgres:
		return "postgres"
	default:
		return "unknown"
	}
}

// ErrSchemaTooNew is returned when the database holds a schema version this
// binary does not know. It wraps a *TooNewError carrying both versions.
var ErrSchemaTooNew = errors.New("state schema is newer than this scrim understands")

// TooNewError names the database's schema version and the newest one this
// binary knows.
type TooNewError struct {
	Database int
	Known    int
}

func (e *TooNewError) Error() string {
	return fmt.Sprintf("state schema version %d is newer than version %d, the newest this scrim understands; "+
		"upgrade scrim, or point it at another database", e.Database, e.Known)
}

// Unwrap lets errors.Is match ErrSchemaTooNew.
func (e *TooNewError) Unwrap() error { return ErrSchemaTooNew }

var fileName = regexp.MustCompile(`^([0-9]{4})_([a-z0-9_]+)\.sql$`)

// Load reads every migration in the root of fsys, in version order. Files
// that are not .sql are ignored; a .sql file with a bad name, a duplicate
// version or a gap in the sequence is an error.
func Load(fsys fs.FS) ([]Migration, error) {
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return nil, fmt.Errorf("reading migrations: %w", err)
	}
	var out []Migration
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".sql") {
			continue
		}
		m := fileName.FindStringSubmatch(name)
		if m == nil {
			return nil, fmt.Errorf("migration %q must be named NNNN_name.sql in lowercase", name)
		}
		v, _ := strconv.Atoi(m[1])
		body, err := fs.ReadFile(fsys, name)
		if err != nil {
			return nil, fmt.Errorf("reading migration %q: %w", name, err)
		}
		out = append(out, Migration{Version: v, Name: m[2], SQL: string(body)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Version < out[j].Version })
	for i, m := range out {
		if m.Version != i+1 {
			if i > 0 && out[i-1].Version == m.Version {
				return nil, fmt.Errorf("migrations %q and %q share version %04d", out[i-1].Name, m.Name, m.Version)
			}
			return nil, fmt.Errorf("migration %04d_%s: versions must run 0001, 0002, ... without gaps, expected %04d",
				m.Version, m.Name, i+1)
		}
	}
	return out, nil
}

// Latest returns the highest version in all, or zero for an empty set.
func Latest(all []Migration) int {
	if len(all) == 0 {
		return 0
	}
	return all[len(all)-1].Version
}

const createVersionTable = `CREATE TABLE IF NOT EXISTS schema_migrations (
  version    INTEGER PRIMARY KEY,
  name       TEXT NOT NULL,
  applied_at TEXT NOT NULL
)`

// Current returns the highest applied version, zero for an empty database.
// It does not create anything.
func Current(ctx context.Context, db *sql.DB) (int, error) {
	var exists int
	// Both dialects answer this: SQLite through sqlite_master, PostgreSQL
	// through to_regclass. Try the portable query first.
	err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM schema_migrations WHERE 1 = 0`).Scan(&exists)
	if err != nil {
		// No table yet: an empty database.
		return 0, nil //nolint:nilerr // a missing table means version zero
	}
	var v sql.NullInt64
	if err := db.QueryRowContext(ctx, `SELECT MAX(version) FROM schema_migrations`).Scan(&v); err != nil {
		return 0, fmt.Errorf("reading schema version: %w", err)
	}
	return int(v.Int64), nil
}

// Hooks lets a backend wrap the run, for example with an advisory lock that
// keeps two replicas from migrating the same database at once.
type Hooks struct {
	// Lock runs on conn before anything is read and returns the function
	// that releases it.
	Lock func(ctx context.Context, conn *sql.Conn) (unlock func(), err error)
}

// Result reports what a run did.
type Result struct {
	From    int
	To      int
	Applied int
}

// Run applies every migration above the database's version, in order, each in
// its own transaction. It refuses, applying nothing, when the database is at a
// version newer than the newest in all.
func Run(ctx context.Context, db *sql.DB, d Dialect, all []Migration, h Hooks) (Result, error) {
	conn, err := db.Conn(ctx)
	if err != nil {
		return Result{}, fmt.Errorf("migrate: acquiring connection: %w", err)
	}
	defer func() { _ = conn.Close() }()

	if h.Lock != nil {
		unlock, err := h.Lock(ctx, conn)
		if err != nil {
			return Result{}, fmt.Errorf("migrate: locking: %w", err)
		}
		defer unlock()
	}

	if _, err := conn.ExecContext(ctx, createVersionTable); err != nil {
		return Result{}, fmt.Errorf("migrate: creating schema_migrations: %w", err)
	}
	var cur sql.NullInt64
	if err := conn.QueryRowContext(ctx, `SELECT MAX(version) FROM schema_migrations`).Scan(&cur); err != nil {
		return Result{}, fmt.Errorf("migrate: reading schema version: %w", err)
	}
	from := int(cur.Int64)
	known := Latest(all)
	if from > known {
		return Result{From: from, To: from}, &TooNewError{Database: from, Known: known}
	}

	res := Result{From: from, To: from}
	for _, m := range all {
		if m.Version <= from {
			continue
		}
		if err := apply(ctx, conn, d, m); err != nil {
			return res, err
		}
		res.To = m.Version
		res.Applied++
	}
	return res, nil
}

func apply(ctx context.Context, conn *sql.Conn, d Dialect, m Migration) error {
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("migration %04d_%s: begin: %w", m.Version, m.Name, err)
	}
	defer func() { _ = tx.Rollback() }()

	for _, stmt := range Split(m.SQL) {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("migration %04d_%s: %w (statement: %s)", m.Version, m.Name, err, truncate(stmt))
		}
	}
	ins := `INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)`
	if d == Postgres {
		ins = `INSERT INTO schema_migrations (version, name, applied_at) VALUES ($1, $2, $3)`
	}
	if _, err := tx.ExecContext(ctx, ins, m.Version, m.Name, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		return fmt.Errorf("migration %04d_%s: recording version: %w", m.Version, m.Name, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("migration %04d_%s: commit: %w", m.Version, m.Name, err)
	}
	return nil
}

// Split separates a migration into statements on semicolons outside string
// literals, quoted identifiers and comments.
func Split(body string) []string {
	var (
		out   []string
		cur   strings.Builder
		quote byte // ' or " while inside a literal or quoted identifier
		line  bool // inside a -- comment
		block bool // inside a /* */ comment
	)
	flush := func() {
		if s := strings.TrimSpace(cur.String()); s != "" {
			out = append(out, s)
		}
		cur.Reset()
	}
	for i := 0; i < len(body); i++ {
		c := body[i]
		switch {
		case line:
			if c == '\n' {
				line = false
				cur.WriteByte(c)
			}
		case block:
			if c == '*' && i+1 < len(body) && body[i+1] == '/' {
				block = false
				i++
			}
		case quote != 0:
			cur.WriteByte(c)
			if c == quote {
				quote = 0
			}
		case c == '-' && i+1 < len(body) && body[i+1] == '-':
			line = true
			i++
		case c == '/' && i+1 < len(body) && body[i+1] == '*':
			block = true
			i++
		case c == '\'' || c == '"':
			quote = c
			cur.WriteByte(c)
		case c == ';':
			flush()
		default:
			cur.WriteByte(c)
		}
	}
	flush()
	return out
}

func truncate(s string) string {
	const limit = 200
	if len(s) <= limit {
		return s
	}
	return s[:limit] + "..."
}
