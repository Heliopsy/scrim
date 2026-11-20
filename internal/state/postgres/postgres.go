// SPDX-License-Identifier: AGPL-3.0-only

// Package postgres is the PostgreSQL state backend, for shared and
// multi-replica deployments (specs/state-and-scaling).
//
// Connections come from a pgx v5 pool (pgxpool), exposed to the shared
// sqlstate queries through database/sql. Every replica runs the migrations
// at start-up under a session advisory lock, so they never race. Outbox
// writes take a transaction advisory lock, which makes event IDs commit in
// increasing order and lets every replica tail the outbox by ID without
// missing an event that committed late. The same transaction queues a NOTIFY
// on [EventsChannel], which PostgreSQL delivers to every listening session
// when it commits: the events backend uses it to read the outbox at once
// instead of on its next poll.
package postgres

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"

	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/state"
	"github.com/heliopsy/scrim/internal/state/migrate"
	"github.com/heliopsy/scrim/internal/state/sqlstate"
)

// Name is the backend name in state.backend.
const Name = "postgres"

// Advisory lock keys, arbitrary constants in scrim's own key space.
const (
	migrateLockKey int64 = 0x7363_7269_6d00_0001 // "scrim" 1
	eventsLockKey  int64 = 0x7363_7269_6d00_0002 // "scrim" 2
)

// EventsChannel is the LISTEN/NOTIFY channel every outbox write notifies.
// The notification carries no payload: it is a wake-up, the outbox is what
// a listener reads.
const EventsChannel = "scrim_events"

// ListenerApplicationName is the application_name of the connection
// [Store.Listen] opens, so an operator can tell it from pool connections.
const ListenerApplicationName = "scrim-events"

//go:embed migrations/*.sql
var migrationFiles embed.FS

// Migrations returns the embedded PostgreSQL migrations in order.
func Migrations() ([]migrate.Migration, error) {
	sub, err := fs.Sub(migrationFiles, "migrations")
	if err != nil {
		return nil, err
	}
	return migrate.Load(sub)
}

// Settings of the PostgreSQL backend.
var (
	DSNSetting = config.Register(config.Spec[config.SecretRef]{
		Key: "state.postgres.dsn",
		Description: "Reference to the PostgreSQL connection string (postgres://user:pass@host/db?sslmode=verify-full), " +
			"for example env:SCRIM_PG_DSN or file:/run/secrets/scrim-dsn. It holds a password, so it is a reference.",
		RestartRequired: true,
	})
	MaxConnsSetting = config.Register(config.Spec[int]{
		Key:         "state.postgres.max-conns",
		Default:     16,
		Description: "Maximum connections in the PostgreSQL pool.",
		Validate: func(n int) error {
			if n < 1 {
				return errors.New("must be at least 1")
			}
			return nil
		},
		RestartRequired: true,
	})
	ConnectTimeoutSetting = config.Register(config.Spec[time.Duration]{
		Key:             "state.postgres.connect-timeout",
		Default:         15 * time.Second,
		Description:     "How long start-up waits for PostgreSQL to answer before failing.",
		RestartRequired: true,
	})
)

func init() {
	state.RegisterBackend(Name, func(ctx context.Context, cfg *config.Config) (state.Store, error) {
		dsn, ok := cfg.Secret(DSNSetting)
		if !ok {
			return nil, errors.New("state: state.backend is postgres but state.postgres.dsn is not set or not resolved")
		}
		// The Config owns dsn and wipes it when it is replaced.
		return Open(ctx, dsn, Options{
			MaxConns:       MaxConnsSetting.Get(cfg),
			ConnectTimeout: ConnectTimeoutSetting.Get(cfg),
		})
	})
}

// Options configures Open.
type Options struct {
	// MaxConns caps the pool; zero means 16.
	MaxConns int
	// ConnectTimeout bounds the start-up ping; zero means 15s.
	ConnectTimeout time.Duration
	// Scrubber, Faults and Observe are passed to sqlstate; see
	// [sqlstate.Config].
	Scrubber interface{ Scrub(string) string }
	Faults   sqlstate.Faults
	Observe  func(kind string, d time.Duration)
}

// Store is the PostgreSQL state backend.
type Store struct {
	*sqlstate.DB
	pool     *pgxpool.Pool
	db       *sql.DB
	location string
}

var _ state.Store = (*Store)(nil)

// Open connects to the database dsn names and checks it answers. The DSN is
// exposed only to build the pool config and never appears in an error or in
// [Store.Location], which drops the password.
func Open(ctx context.Context, dsn secret.Value, o Options) (*Store, error) {
	if o.MaxConns <= 0 {
		o.MaxConns = 16
	}
	if o.ConnectTimeout <= 0 {
		o.ConnectTimeout = 15 * time.Second
	}
	var (
		pc       *pgxpool.Config
		location string
	)
	err := dsn.Expose(func(b []byte) error {
		var perr error
		pc, perr = pgxpool.ParseConfig(string(b))
		if perr != nil {
			// pgx parse errors can quote the input; never pass them on.
			return errors.New("state: state.postgres.dsn is not a valid PostgreSQL connection string")
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	location = describe(&pc.ConnConfig.Config)
	pc.MaxConns = int32(min(o.MaxConns, 1<<20)) // #nosec G115 -- bounded above
	pc.MaxConnIdleTime = 5 * time.Minute
	pc.MaxConnLifetime = 30 * time.Minute
	pc.ConnConfig.RuntimeParams["application_name"] = "scrim"

	cctx, cancel := context.WithTimeout(ctx, o.ConnectTimeout)
	defer cancel()
	pool, err := pgxpool.NewWithConfig(cctx, pc)
	if err != nil {
		return nil, fmt.Errorf("state: postgres at %s: %w", location, scrubConnErr(err))
	}
	if err := pool.Ping(cctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("state: postgres at %s is unreachable within %s: %w", location, o.ConnectTimeout, scrubConnErr(err))
	}
	db := stdlib.OpenDBFromPool(pool)
	s := &Store{pool: pool, db: db, location: location}
	s.DB = sqlstate.New(sqlstate.Config{
		Backend:  Name,
		Dialect:  migrate.Postgres,
		Reader:   db,
		Writer:   db,
		IsUnique: isUnique,
		BeforeEmit: func(ctx context.Context, tx *sql.Tx) error {
			// NOTIFY is delivered on commit and dropped on rollback; within
			// one transaction PostgreSQL folds identical notifications into
			// one.
			_, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1), pg_notify($2, '')`, eventsLockKey, EventsChannel)
			return err
		},
		Scrubber: o.Scrubber,
		Faults:   o.Faults,
		Observe:  o.Observe,
	})
	return s, nil
}

// Location describes the database without credentials: user@host:port/db.
func (s *Store) Location() string { return s.location }

// Pool returns the pgx pool, for LISTEN/NOTIFY event backends.
func (s *Store) Pool() *pgxpool.Pool { return s.pool }

// Listen opens a dedicated connection, outside the pool, that listens on
// [EventsChannel]. The caller waits on it with WaitForNotification and
// closes it. Errors never carry connection parameters.
func (s *Store) Listen(ctx context.Context) (*pgx.Conn, error) {
	cc := s.pool.Config().ConnConfig.Copy()
	cc.RuntimeParams["application_name"] = ListenerApplicationName
	conn, err := pgx.ConnectConfig(ctx, cc)
	if err != nil {
		return nil, fmt.Errorf("state: postgres at %s: listener: %w", s.location, scrubConnErr(err))
	}
	if _, err := conn.Exec(ctx, "LISTEN "+EventsChannel); err != nil {
		_ = conn.Close(context.WithoutCancel(ctx))
		return nil, fmt.Errorf("state: postgres at %s: LISTEN: %w", s.location, scrubConnErr(err))
	}
	return conn, nil
}

// ScrubError is scrubConnErr for errors from a connection opened by
// [Store.Listen].
func ScrubError(err error) error { return scrubConnErr(err) }

// Migrate implements [state.Store]. Replicas serialise on an advisory lock.
func (s *Store) Migrate(ctx context.Context) error {
	all, err := Migrations()
	if err != nil {
		return err
	}
	_, err = migrate.Run(ctx, s.db, migrate.Postgres, all, migrate.Hooks{
		Lock: func(ctx context.Context, conn *sql.Conn) (func(), error) {
			if _, err := conn.ExecContext(ctx, `SELECT pg_advisory_lock($1)`, migrateLockKey); err != nil {
				return nil, err
			}
			return func() {
				_, _ = conn.ExecContext(context.WithoutCancel(ctx), `SELECT pg_advisory_unlock($1)`, migrateLockKey)
			}, nil
		},
	})
	if errors.Is(err, migrate.ErrSchemaTooNew) {
		return fmt.Errorf("%w: postgres at %s: %w", state.ErrSchemaTooNew, s.location, err)
	}
	if err != nil {
		return fmt.Errorf("state: migrating postgres at %s: %w", s.location, err)
	}
	return nil
}

// SchemaVersion implements [state.Store].
func (s *Store) SchemaVersion(ctx context.Context) (int, error) { return migrate.Current(ctx, s.db) }

// Close implements [state.Store].
func (s *Store) Close() error {
	err := s.db.Close()
	s.pool.Close()
	return err
}

func isUnique(err error) bool {
	var pe *pgconn.PgError
	return errors.As(err, &pe) && pe.Code == "23505"
}

// describe renders a connection config without its password.
func describe(c *pgconn.Config) string {
	u := url.URL{Scheme: "postgres", User: url.User(c.User), Host: fmt.Sprintf("%s:%d", c.Host, c.Port), Path: "/" + c.Database}
	return u.String()
}

// scrubConnErr keeps a connection error's cause but drops any server
// message that could echo connection parameters.
func scrubConnErr(err error) error {
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		return fmt.Errorf("server error %s (%s)", pe.Code, pe.Severity)
	}
	var ce *pgconn.ConnectError
	if errors.As(err, &ce) {
		if inner := errors.Unwrap(ce); inner != nil {
			return fmt.Errorf("connection failed: %w", scrubConnErr(inner))
		}
		return errors.New("connection failed")
	}
	return err
}
