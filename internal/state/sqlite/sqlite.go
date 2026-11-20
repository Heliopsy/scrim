// SPDX-License-Identifier: AGPL-3.0-only

// Package sqlite is the SQLite state backend: one local file, one scrim
// process (specs/state-and-scaling "SQLite backend is local and
// single-process").
//
// It uses the pure Go driver modernc.org/sqlite, so builds stay
// CGO_ENABLED=0. The database runs in WAL mode with a busy timeout. Writes
// go through a pool of exactly one connection whose transactions begin
// IMMEDIATE, so the write lock is taken up front and writers queue in Go
// rather than failing with SQLITE_BUSY mid-transaction; reads use a separate
// pool and see the last committed state. An exclusive lock on a sibling
// ".lock" file keeps a second scrim process off the same database, and Open
// refuses a file on a network filesystem unless the weakening setting
// state.sqlite.allow-network-filesystem is set.
package sqlite

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	sqlite3 "modernc.org/sqlite"
	sqlite3lib "modernc.org/sqlite/lib"

	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/state"
	"github.com/heliopsy/scrim/internal/state/migrate"
	"github.com/heliopsy/scrim/internal/state/sqlstate"
)

// Name is the backend name in state.backend.
const Name = "sqlite"

// BusyTimeoutMillis is how long a connection waits on a lock held by another
// connection before failing.
const BusyTimeoutMillis = 5000

//go:embed migrations/*.sql
var migrationFiles embed.FS

// Migrations returns the embedded SQLite migrations in order.
func Migrations() ([]migrate.Migration, error) {
	sub, err := fs.Sub(migrationFiles, "migrations")
	if err != nil {
		return nil, err
	}
	return migrate.Load(sub)
}

// Settings of the SQLite backend.
var (
	PathSetting = config.Register(config.Spec[string]{
		Key:             "state.sqlite.path",
		Default:         "",
		Description:     "SQLite state file. Empty means $XDG_STATE_HOME/scrim/state.db (~/.local/state/scrim/state.db).",
		Flag:            true,
		RestartRequired: true,
	})
	AllowNetworkFSSetting = config.Register(config.Spec[bool]{
		Key: "state.sqlite.allow-network-filesystem",
		Description: "Allows the SQLite state file on a network or shared filesystem (NFS, SMB, sshfs), " +
			"where file locking is unreliable and the database can be corrupted. Use the postgres backend instead.",
		Weakening:       true,
		RestartRequired: true,
	})
)

func init() {
	state.RegisterBackend(Name, func(ctx context.Context, cfg *config.Config) (state.Store, error) {
		s, err := Open(ctx, PathSetting.Get(cfg), Options{AllowNetworkFS: AllowNetworkFSSetting.Get(cfg)})
		if err != nil {
			return nil, err
		}
		return s, nil
	})
}

// Options configures Open.
type Options struct {
	// AllowNetworkFS opens a database on a network filesystem instead of
	// refusing it. Status reports it as a weakened setting.
	AllowNetworkFS bool
	// Faults and Observe are passed to sqlstate; see [sqlstate.Config].
	Faults  sqlstate.Faults
	Observe func(kind string, d time.Duration)
	// detectFS replaces filesystem detection in tests.
	detectFS func(dir string) FSKind
}

// Store is the SQLite state backend.
type Store struct {
	*sqlstate.DB
	path   string
	fs     FSKind
	reader *sql.DB
	writer *sql.DB
	lock   *fileLock
}

var _ state.Store = (*Store)(nil)

// DefaultPath is the state file used when state.sqlite.path is empty.
func DefaultPath() (string, error) {
	dir := os.Getenv("XDG_STATE_HOME")
	if dir == "" || !filepath.IsAbs(dir) {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("state: no XDG_STATE_HOME and no home directory: %w", err)
		}
		dir = filepath.Join(home, ".local", "state")
	}
	return filepath.Join(dir, "scrim", "state.db"), nil
}

// LockedError is returned by Open when another process holds the database.
type LockedError struct {
	Path string
	// PID is the holding process, zero when it could not be read.
	PID int
}

func (e *LockedError) Error() string {
	holder := "another process"
	if e.PID > 0 {
		holder = fmt.Sprintf("process %d", e.PID)
	}
	return fmt.Sprintf("state: SQLite file %s is in use by %s; one scrim process per SQLite file "+
		"(stop the other process, choose another state.sqlite.path, or use the postgres backend)", e.Path, holder)
}

// ErrNetworkFS is wrapped by Open's refusal of a network filesystem.
var ErrNetworkFS = errors.New("state: SQLite file on a network filesystem")

// Open opens, creating if needed, the SQLite database at path (empty for
// [DefaultPath]). It does not migrate; call Migrate.
func Open(ctx context.Context, path string, o Options) (*Store, error) {
	if path == "" {
		var err error
		if path, err = DefaultPath(); err != nil {
			return nil, err
		}
	}
	path, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("state: resolving %q: %w", path, err)
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("state: creating %s: %w", dir, err)
	}
	detect := o.detectFS
	if detect == nil {
		detect = detectFS
	}
	kind := detect(dir)
	if kind.IsNetwork() && !o.AllowNetworkFS {
		return nil, fmt.Errorf("%w: %s is on %s, where SQLite locking is unreliable and the database can be corrupted; "+
			"use state.backend: postgres, move state.sqlite.path to a local disk, or set "+
			"state.sqlite.allow-network-filesystem to accept the risk", ErrNetworkFS, path, kind)
	}

	lock, err := acquireLock(path)
	if err != nil {
		return nil, err
	}
	s := &Store{path: path, fs: kind, lock: lock}
	fail := func(err error) (*Store, error) {
		_ = s.Close()
		return nil, err
	}

	// Create the file with private permissions before the driver does.
	if f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600); err == nil { // #nosec G304 -- configured state path
		_ = f.Close()
	} else {
		return fail(fmt.Errorf("state: creating %s: %w", path, err))
	}

	if s.writer, err = sql.Open("sqlite", dsn(path, true)); err != nil {
		return fail(fmt.Errorf("state: opening %s: %w", path, err))
	}
	s.writer.SetMaxOpenConns(1)
	s.writer.SetMaxIdleConns(1)
	s.writer.SetConnMaxLifetime(0)
	if s.reader, err = sql.Open("sqlite", dsn(path, false)); err != nil {
		return fail(fmt.Errorf("state: opening %s: %w", path, err))
	}
	n := max(4, runtime.NumCPU())
	s.reader.SetMaxOpenConns(n)
	s.reader.SetMaxIdleConns(n)

	var mode string
	if err := s.writer.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&mode); err != nil {
		return fail(fmt.Errorf("state: reading journal mode of %s: %w", path, err))
	}
	if !strings.EqualFold(mode, "wal") {
		return fail(fmt.Errorf("state: %s could not switch to WAL mode (got %q); is the file or its directory read-only?", path, mode))
	}

	s.DB = sqlstate.New(sqlstate.Config{
		Backend:  Name,
		Dialect:  migrate.SQLite,
		Reader:   s.reader,
		Writer:   s.writer,
		IsUnique: isUnique,
		Faults:   o.Faults,
		Observe:  o.Observe,
	})
	return s, nil
}

// dsn applies the pragmas to every connection the pool opens. The writer's
// transactions begin IMMEDIATE.
func dsn(path string, writer bool) string {
	q := url.Values{}
	q.Add("_pragma", fmt.Sprintf("busy_timeout(%d)", BusyTimeoutMillis))
	q.Add("_pragma", "journal_mode(WAL)")
	q.Add("_pragma", "synchronous(NORMAL)")
	q.Add("_pragma", "foreign_keys(1)")
	q.Add("_time_format", "sqlite")
	if writer {
		q.Set("_txlock", "immediate")
	}
	return "file:" + (&url.URL{Path: path}).EscapedPath() + "?" + q.Encode()
}

// Path is the absolute database path.
func (s *Store) Path() string { return s.path }

// Filesystem is what the database directory was detected on.
func (s *Store) Filesystem() FSKind { return s.fs }

// Migrate implements [state.Store].
func (s *Store) Migrate(ctx context.Context) error {
	all, err := Migrations()
	if err != nil {
		return err
	}
	if _, err := migrate.Run(ctx, s.writer, migrate.SQLite, all, migrate.Hooks{}); err != nil {
		if errors.Is(err, migrate.ErrSchemaTooNew) {
			return fmt.Errorf("%w: %s: %w", state.ErrSchemaTooNew, s.path, err)
		}
		return fmt.Errorf("state: migrating %s: %w", s.path, err)
	}
	return nil
}

// SchemaVersion implements [state.Store].
func (s *Store) SchemaVersion(ctx context.Context) (int, error) {
	return migrate.Current(ctx, s.reader)
}

// Close implements [state.Store]. It checkpoints the WAL into the main file
// and releases the process lock.
func (s *Store) Close() error {
	var errs []error
	if s.writer != nil {
		_, _ = s.writer.Exec("PRAGMA wal_checkpoint(TRUNCATE)")
		errs = append(errs, s.writer.Close())
	}
	if s.reader != nil {
		errs = append(errs, s.reader.Close())
	}
	s.lock.release()
	return errors.Join(errs...)
}

func isUnique(err error) bool {
	var se *sqlite3.Error
	if errors.As(err, &se) {
		c := se.Code()
		return c == sqlite3lib.SQLITE_CONSTRAINT_UNIQUE || c == sqlite3lib.SQLITE_CONSTRAINT_PRIMARYKEY
	}
	return false
}
