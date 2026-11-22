// SPDX-License-Identifier: AGPL-3.0-only

package dbproxy

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/heliopsy/scrim/internal/secret"
)

// QueryInput is one call of the read-only database tool. It holds no value:
// placeholders in SQL string literals and in Params stand for them.
type QueryInput struct {
	SQL    string
	Params []string
	// MaxRows asks for fewer rows than the limit; zero takes the limit.
	MaxRows int
}

// Limits bound one query.
type Limits struct {
	// Timeout is the statement timeout, also enforced on the call.
	Timeout time.Duration
	// MaxRows is the most rows returned; more mark the result truncated.
	MaxRows int
	// MaxBytes bounds the cell text returned.
	MaxBytes int
}

// Result is what the query returned. Cells are text, NULL is nil; bytes that
// are not UTF-8 are shown as \x and hex.
type Result struct {
	Columns   []string    `json:"columns"`
	Rows      [][]*string `json:"rows"`
	Truncated bool        `json:"truncated,omitempty"`
}

// Substitute returns the value a placeholder stands for, after checking that
// it may be bound toward db. The caller wipes it. Its *RefusedError reaches
// the agent.
type Substitute func(ctx context.Context, db *Database, placeholder string) (secret.Value, error)

// Query runs one read statement on p's database as caller. Placeholders in
// string literals and in in.Params become bound parameters whose values come
// from subst; they never become SQL text. The statement runs in a read-only
// transaction with lim's statement timeout, through p's own login, and the
// transaction is rolled back.
func Query(ctx context.Context, p *Proxy, caller Caller, in QueryInput, lim Limits, subst Substitute) (*Result, error) {
	st, err := prepare(p.DB.Kind, in.SQL, in.Params)
	if err != nil {
		return nil, err
	}
	maxRows := lim.MaxRows
	if in.MaxRows > 0 && in.MaxRows < maxRows {
		maxRows = in.MaxRows
	}
	if maxRows <= 0 {
		maxRows = 1000
	}
	if lim.Timeout <= 0 {
		lim.Timeout = 10 * time.Second
	}
	if lim.MaxBytes <= 0 {
		lim.MaxBytes = 1 << 20
	}
	args, err := bindArgs(ctx, p.DB, st.args, subst)
	defer func() {
		for _, a := range args {
			secret.WipeBytes(a)
		}
	}()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, lim.Timeout+5*time.Second)
	defer cancel()
	switch p.DB.Kind {
	case Postgres:
		return queryPostgres(ctx, p, caller, st.sql, args, maxRows, lim)
	case MySQL:
		return queryMySQL(ctx, p, caller, st.sql, args, maxRows, lim)
	}
	return nil, fmt.Errorf("unknown database kind %q", p.DB.Kind)
}

// bindArgs resolves the placeholders in each parameter text into a byte
// buffer the caller wipes.
func bindArgs(ctx context.Context, db *Database, texts []string, subst Substitute) ([][]byte, error) {
	out := make([][]byte, 0, len(texts))
	for _, t := range texts {
		phs := placeholdersIn(t)
		if len(phs) == 0 {
			out = append(out, []byte(t))
			continue
		}
		var b []byte
		rest := t
		for _, ph := range phs {
			i := strings.Index(rest, ph)
			b = append(b, rest[:i]...)
			v, err := subst(ctx, db, ph)
			if err != nil {
				secret.WipeBytes(b)
				return out, err
			}
			err = v.Expose(func(raw []byte) error {
				nb := append(make([]byte, 0, len(b)+len(raw)+len(rest)), b...)
				nb = append(nb, raw...)
				secret.WipeBytes(b)
				b = nb
				return nil
			})
			v.Wipe()
			if err != nil {
				secret.WipeBytes(b)
				return out, err
			}
			rest = rest[i+len(ph):]
		}
		b = append(b, rest...)
		out = append(out, b)
	}
	return out, nil
}

// cell renders one value.
func cell(v []byte, null bool) *string {
	if null {
		return nil
	}
	var s string
	if utf8.Valid(v) {
		s = string(v)
	} else {
		s = `\x` + hex.EncodeToString(v)
	}
	return &s
}

type collector struct {
	res      *Result
	maxRows  int
	maxBytes int
	bytes    int
}

// add appends a row and reports whether more rows fit.
func (c *collector) add(row []*string) bool {
	if len(c.res.Rows) >= c.maxRows {
		c.res.Truncated = true
		return false
	}
	n := 0
	for _, v := range row {
		if v != nil {
			n += len(*v)
		}
	}
	if c.bytes+n > c.maxBytes {
		c.res.Truncated = true
		return false
	}
	c.bytes += n
	c.res.Rows = append(c.res.Rows, row)
	return true
}

func queryPostgres(ctx context.Context, p *Proxy, caller Caller, query string, args [][]byte, maxRows int, lim Limits) (*Result, error) {
	cfg, err := pgconn.ParseConfig("host=scrim port=5432 sslmode=disable connect_timeout=15")
	if err != nil {
		return nil, fmt.Errorf("pgconn config: %w", err)
	}
	cfg.User, cfg.Password, cfg.TLSConfig, cfg.Fallbacks = p.DB.User, "", nil, nil
	cfg.Database = p.DB.DBName
	if cfg.Database == "" {
		cfg.Database = p.DB.User
	}
	cfg.RuntimeParams = map[string]string{"application_name": "scrim-database-tool"}
	cfg.LookupFunc = func(_ context.Context, host string) ([]string, error) { return []string{host}, nil }
	cfg.DialFunc = func(ctx context.Context, _, _ string) (net.Conn, error) { return p.pipe(ctx, caller), nil }
	conn, err := pgconn.ConnectConfig(ctx, cfg)
	if err != nil {
		return nil, pgPublic(err)
	}
	defer func() { _ = conn.Close(context.WithoutCancel(ctx)) }()
	setup := fmt.Sprintf("BEGIN TRANSACTION READ ONLY; SET LOCAL statement_timeout = %d; SET LOCAL lock_timeout = %d",
		lim.Timeout.Milliseconds(), lim.Timeout.Milliseconds())
	if _, err := conn.Exec(ctx, setup).ReadAll(); err != nil {
		return nil, pgPublic(err)
	}
	rr := conn.ExecParams(ctx, query, args, nil, nil, nil)
	res := &Result{Columns: []string{}, Rows: [][]*string{}}
	for _, f := range rr.FieldDescriptions() {
		res.Columns = append(res.Columns, f.Name)
	}
	col := &collector{res: res, maxRows: maxRows, maxBytes: lim.MaxBytes}
	for rr.NextRow() {
		vals := rr.Values()
		row := make([]*string, len(vals))
		for i, v := range vals {
			row[i] = cell(v, v == nil)
		}
		if !col.add(row) {
			// Closing the connection ends the statement and the transaction;
			// nothing more is read.
			return res, nil
		}
	}
	if _, err := rr.Close(); err != nil {
		return nil, pgPublic(err)
	}
	_, _ = conn.Exec(ctx, "ROLLBACK").ReadAll()
	return res, nil
}

// pgPublic turns a driver error into one the agent may read: the server's
// error code and message (the agent's own statement's error), or a refusal
// the proxy sent, or a fixed text.
func pgPublic(err error) error {
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		msg := pe.Message
		if strings.HasPrefix(msg, "scrim: ") {
			return &RefusedError{Reason: strings.TrimPrefix(msg, "scrim: ")}
		}
		return &QueryError{Code: pe.Code, Message: msg}
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return Refused("the query timed out")
	}
	return &QueryError{Message: "the query failed"}
}

// QueryError is the database's own error for the agent's statement, such as
// a syntax error or the read-only transaction refusing a write. Its message
// is the server's text about the agent's statement; the caller redacts it
// like a result.
type QueryError struct {
	Code    string
	Message string
}

func (e *QueryError) Error() string {
	if e.Code == "" {
		return e.Message
	}
	return e.Message + " (" + e.Code + ")"
}

var (
	mysqlDialOnce sync.Once
	mysqlDials    sync.Map // token -> func(context.Context) net.Conn
)

const mysqlNet = "scrim-database-tool"

func queryMySQL(ctx context.Context, p *Proxy, caller Caller, query string, args [][]byte, maxRows int, lim Limits) (*Result, error) {
	mysqlDialOnce.Do(func() {
		mysql.RegisterDialContext(mysqlNet, func(ctx context.Context, addr string) (net.Conn, error) {
			f, ok := mysqlDials.Load(addr)
			if !ok {
				return nil, errors.New("no such database tool connection")
			}
			return f.(func(context.Context) net.Conn)(ctx), nil
		})
	})
	tok := make([]byte, 16)
	if _, err := rand.Read(tok); err != nil {
		return nil, err
	}
	addr := hex.EncodeToString(tok)
	mysqlDials.Store(addr, func(ctx context.Context) net.Conn { return p.pipe(ctx, caller) })
	defer mysqlDials.Delete(addr)

	cfg := mysql.NewConfig()
	cfg.User, cfg.Net, cfg.Addr = p.DB.User, mysqlNet, addr
	cfg.DBName = p.DB.DBName
	cfg.InterpolateParams, cfg.MultiStatements = false, false
	cfg.Timeout = 15 * time.Second
	connector, err := mysql.NewConnector(cfg)
	if err != nil {
		return nil, err
	}
	db := sql.OpenDB(connector)
	defer func() { _ = db.Close() }()
	db.SetMaxOpenConns(1)
	conn, err := db.Conn(ctx)
	if err != nil {
		return nil, myPublic(err)
	}
	defer func() { _ = conn.Close() }()
	// MySQL bounds SELECT time with max_execution_time (ms), MariaDB with
	// max_statement_time (s); the call's own deadline covers both.
	if _, err := conn.ExecContext(ctx, fmt.Sprintf("SET SESSION max_execution_time = %d", lim.Timeout.Milliseconds())); err != nil {
		_, _ = conn.ExecContext(ctx, fmt.Sprintf("SET SESSION max_statement_time = %g", lim.Timeout.Seconds()))
	}
	tx, err := conn.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, myPublic(err)
	}
	defer func() { _ = tx.Rollback() }()
	anyArgs := make([]any, len(args))
	for i, a := range args {
		anyArgs[i] = a
	}
	rows, err := tx.QueryContext(ctx, query, anyArgs...)
	if err != nil {
		return nil, myPublic(err)
	}
	defer func() { _ = rows.Close() }()
	cols, err := rows.Columns()
	if err != nil {
		return nil, myPublic(err)
	}
	res := &Result{Columns: cols, Rows: [][]*string{}}
	if res.Columns == nil {
		res.Columns = []string{}
	}
	col := &collector{res: res, maxRows: maxRows, maxBytes: lim.MaxBytes}
	raw := make([]sql.RawBytes, len(cols))
	dest := make([]any, len(cols))
	for i := range raw {
		dest[i] = &raw[i]
	}
	for rows.Next() {
		if err := rows.Scan(dest...); err != nil {
			return nil, myPublic(err)
		}
		row := make([]*string, len(cols))
		for i, v := range raw {
			row[i] = cell(v, v == nil)
		}
		if !col.add(row) {
			return res, nil
		}
	}
	if err := rows.Err(); err != nil {
		return nil, myPublic(err)
	}
	return res, nil
}

func myPublic(err error) error {
	var me *mysql.MySQLError
	if errors.As(err, &me) {
		msg := me.Message
		if strings.HasPrefix(msg, "scrim: ") {
			return &RefusedError{Reason: strings.TrimPrefix(msg, "scrim: ")}
		}
		code := fmt.Sprint(me.Number)
		if me.SQLState != [5]byte{} {
			code = string(me.SQLState[:]) + "/" + code
		}
		return &QueryError{Code: code, Message: msg}
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return Refused("the query timed out")
	}
	return &QueryError{Message: "the query failed"}
}
