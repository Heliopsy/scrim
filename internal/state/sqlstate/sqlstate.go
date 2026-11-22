// SPDX-License-Identifier: AGPL-3.0-only

// Package sqlstate implements [state.Store] over database/sql for the SQLite
// and PostgreSQL backends. The two share every query; the backend packages
// supply the connection pools, the dialect hooks and the migrations.
//
// Statements are written with ? placeholders and rebound to $n for
// PostgreSQL. Times are stored as UTC Unix nanoseconds, NULL for the zero
// time, so ordering and range queries are plain integer comparisons on both
// engines. Structured metadata (an agent's labels, a grant's scope, an
// approval's request) is stored as JSON text. No column can hold a secret
// value: the types written here have no field for one.
package sqlstate

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/heliopsy/scrim/internal/audit"
	"github.com/heliopsy/scrim/internal/state"
	"github.com/heliopsy/scrim/internal/state/migrate"
)

// Faults lets tests fail a transaction at a named point. Op names are
// "<method>" before the method's first statement, for example "AppendAudit"
// or "CreateGrant", and "commit" before COMMIT. Production code leaves it nil.
type Faults func(op string) error

// Config describes one backend's database handles and dialect behaviour.
type Config struct {
	// Backend is the state.backend name.
	Backend string
	// Dialect selects placeholder style and dialect-specific SQL.
	Dialect migrate.Dialect
	// Reader serves View transactions; Writer serves Update. They may be
	// the same pool. For SQLite, Writer has one connection, which is the
	// single-writer discipline.
	Reader, Writer *sql.DB
	// IsUnique reports whether err is a unique-constraint violation.
	IsUnique func(error) bool
	// BeforeEmit runs inside an Update before the first outbox insert. The
	// PostgreSQL backend takes a transaction-scoped advisory lock here so
	// outbox IDs become visible in commit order and a reader polling
	// EventsAfter never skips an event committed late, and queues a NOTIFY
	// that PostgreSQL delivers to listening replicas on commit.
	BeforeEmit func(ctx context.Context, tx *sql.Tx) error
	// Scrubber, if set, filters every string argument before it reaches
	// the database: the last line keeping a value that slipped into a
	// reason, target or attribute out of the stored state.
	Scrubber interface{ Scrub(string) string }
	// Faults is the test hook; nil in production.
	Faults Faults
	// Observe, if set, is called after each transaction with its kind
	// ("view" or "update") and duration, for metrics.
	Observe func(kind string, d time.Duration)
}

// DB is a [state.Store] over database/sql. Backend packages embed it and add
// Migrate, SchemaVersion and Close.
type DB struct {
	cfg Config

	hookMu sync.Mutex
	hooks  []func()
	tap    state.AuditTapFunc
}

var _ state.AuditTap = (*DB)(nil)

// SetAuditTap implements [state.AuditTap].
func (d *DB) SetAuditTap(fn state.AuditTapFunc) {
	d.hookMu.Lock()
	defer d.hookMu.Unlock()
	d.tap = fn
}

func (d *DB) tapped() bool {
	d.hookMu.Lock()
	defer d.hookMu.Unlock()
	return d.tap != nil
}

// runTap hands the transaction's audit entries to the tap before commit.
func (d *DB) runTap(ctx context.Context, entries []audit.Entry) (func(bool), error) {
	d.hookMu.Lock()
	tap := d.tap
	d.hookMu.Unlock()
	if tap == nil || len(entries) == 0 {
		return nil, nil
	}
	return tap(ctx, entries)
}

var _ state.CommitHook = (*DB)(nil)

// OnEventCommit implements [state.CommitHook].
func (d *DB) OnEventCommit(fn func()) {
	d.hookMu.Lock()
	defer d.hookMu.Unlock()
	d.hooks = append(d.hooks, fn)
}

func (d *DB) committed() {
	d.hookMu.Lock()
	hooks := append([]func(){}, d.hooks...)
	d.hookMu.Unlock()
	for _, h := range hooks {
		h()
	}
}

// New returns a DB for cfg.
func New(cfg Config) *DB { return &DB{cfg: cfg} }

// Config returns the configuration the DB was built with.
func (d *DB) Config() Config { return d.cfg }

// Backend implements [state.Store].
func (d *DB) Backend() string { return d.cfg.Backend }

// Health implements [state.Store]: a round trip on both pools.
func (d *DB) Health(ctx context.Context) error {
	if err := d.cfg.Reader.PingContext(ctx); err != nil {
		return fmt.Errorf("state %s: %w", d.cfg.Backend, err)
	}
	if d.cfg.Writer != d.cfg.Reader {
		if err := d.cfg.Writer.PingContext(ctx); err != nil {
			return fmt.Errorf("state %s: %w", d.cfg.Backend, err)
		}
	}
	return nil
}

// View implements [state.Store].
func (d *DB) View(ctx context.Context, fn func(state.Tx) error) error {
	start := time.Now()
	defer d.observe("view", start)
	var opts *sql.TxOptions
	if d.cfg.Dialect == migrate.Postgres {
		opts = &sql.TxOptions{ReadOnly: true}
	}
	tx, err := d.cfg.Reader.BeginTx(ctx, opts)
	if err != nil {
		return d.mapErr(err, "begin read transaction")
	}
	defer func() { _ = tx.Rollback() }()
	if err := fn(&Tx{db: d, tx: tx, readOnly: true}); err != nil {
		return err
	}
	return d.mapErr(tx.Commit(), "commit read transaction")
}

// Update implements [state.Store]. A panic in fn rolls back and re-panics.
func (d *DB) Update(ctx context.Context, fn func(state.Tx) error) error {
	start := time.Now()
	defer d.observe("update", start)
	tx, err := d.cfg.Writer.BeginTx(ctx, nil)
	if err != nil {
		return d.mapErr(err, "begin write transaction")
	}
	defer func() { _ = tx.Rollback() }()
	t := &Tx{db: d, tx: tx}
	if err := fn(t); err != nil {
		return err
	}
	done, err := d.runTap(ctx, t.audited)
	if err != nil {
		return err
	}
	committed := false
	if done != nil {
		defer func() { done(committed) }()
	}
	if err := d.fault("commit"); err != nil {
		return err
	}
	if err := d.mapErr(tx.Commit(), "commit"); err != nil {
		return err
	}
	committed = true
	if t.emitted {
		d.committed()
	}
	return nil
}

func (d *DB) observe(kind string, start time.Time) {
	if d.cfg.Observe != nil {
		d.cfg.Observe(kind, time.Since(start))
	}
}

func (d *DB) fault(op string) error {
	if d.cfg.Faults == nil {
		return nil
	}
	return d.cfg.Faults(op)
}

// ErrReadOnly is returned by a mutating method inside View.
var ErrReadOnly = errors.New("state: write in a read-only transaction")

// mapErr wraps a driver error with context, mapping unique violations to
// state.ErrConflict and no rows to state.ErrNotFound. It never includes
// statement arguments, only the operation name.
func (d *DB) mapErr(err error, op string) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, sql.ErrNoRows):
		return state.ErrNotFound
	case d.cfg.IsUnique != nil && d.cfg.IsUnique(err):
		return state.ErrConflict
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return fmt.Errorf("state %s: %s: %w", d.cfg.Backend, op, err)
	}
	return fmt.Errorf("state %s: %s: %w", d.cfg.Backend, op, err)
}

// rebind turns ? placeholders into $1, $2, ... for PostgreSQL. Statements in
// this package never contain a literal question mark.
func (d *DB) rebind(q string) string {
	if d.cfg.Dialect != migrate.Postgres {
		return q
	}
	var b strings.Builder
	n := 0
	for i := 0; i < len(q); i++ {
		if q[i] == '?' {
			n++
			b.WriteByte('$')
			b.WriteString(strconv.Itoa(n))
			continue
		}
		b.WriteByte(q[i])
	}
	return b.String()
}

// Instrument sets the scrubber and the transaction observer of a DB opened
// through the backend registry, whose opener cannot take them. Call it
// before the first transaction.
func (d *DB) Instrument(sc interface{ Scrub(string) string }, observe func(kind string, d time.Duration)) {
	d.cfg.Scrubber = sc
	d.cfg.Observe = observe
}
