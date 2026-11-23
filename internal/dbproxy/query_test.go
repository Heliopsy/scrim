// SPDX-License-Identifier: AGPL-3.0-only

package dbproxy

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/testing/dbtest"
)

const valuePH = "⟦scrim:app-token:01a1b2c3d4e5f60718⟧"

// subst resolves valuePH to the fixture's stored secret and refuses every
// other placeholder, like an unbound or unknown credential.
func (f *fixture) subst(_ context.Context, db *Database, ph string) (secret.Value, error) {
	if db != f.db {
		return secret.Value{}, errors.New("wrong database")
	}
	if ph != valuePH {
		return secret.Value{}, Refused("placeholder %s is not a credential bound to this database", ph)
	}
	return secret.FromString(f.value.Value()), nil
}

func (f *fixture) query(t *testing.T, sql string, params ...string) (*Result, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return Query(ctx, f.proxy, Caller{Agent: "test-agent"}, QueryInput{SQL: sql, Params: params},
		Limits{Timeout: 2 * time.Second, MaxRows: 10}, f.subst)
}

func cells(r *Result) [][]string {
	var out [][]string
	for _, row := range r.Rows {
		var o []string
		for _, c := range row {
			if c == nil {
				o = append(o, "NULL")
			} else {
				o = append(o, *c)
			}
		}
		out = append(out, o)
	}
	return out
}

func TestQueryTool(t *testing.T) {
	type db struct {
		srv  *dbtest.Server
		kind Kind
	}
	for _, d := range []db{{pgServer, Postgres}, {mysqlServer, MySQL}, {mariaServer, MySQL}} {
		t.Run(d.srv.Kind, func(t *testing.T) {
			f := newFixture(t, d.srv, d.kind, false)
			marker := "$1"
			if d.kind == MySQL {
				marker = "?"
			}
			count := func() string {
				return f.srv.QueryString(t, "SELECT count(*) FROM "+map[Kind]string{Postgres: "", MySQL: "scrim."}[d.kind]+f.table)
			}
			before := count()

			t.Run("placeholder in a literal", func(t *testing.T) {
				r, err := f.query(t, fmt.Sprintf("SELECT id FROM %s WHERE token = '%s'", f.table, valuePH))
				if err != nil {
					t.Fatal(err)
				}
				if got := cells(r); len(got) != 1 || got[0][0] != "1" {
					t.Fatalf("rows %v, want [[1]]", got)
				}
			})

			t.Run("placeholder in a parameter", func(t *testing.T) {
				r, err := f.query(t, fmt.Sprintf("SELECT id FROM %s WHERE token = %s", f.table, marker), valuePH)
				if err != nil {
					t.Fatal(err)
				}
				if got := cells(r); len(got) != 1 || got[0][0] != "1" {
					t.Fatalf("rows %v, want id 1", got)
				}
			})

			t.Run("the server sees a bound parameter", func(t *testing.T) {
				var q string
				switch {
				case d.kind == Postgres:
					q = fmt.Sprintf("SELECT current_query() FROM %s WHERE token = '%s'", f.table, valuePH)
				case d.srv.Kind == "mariadb":
					t.Skip("MariaDB records no statement text for a prepared statement's execution")
				default:
					q = fmt.Sprintf("SELECT (SELECT SQL_TEXT FROM performance_schema.events_statements_current WHERE THREAD_ID = "+
						"(SELECT THREAD_ID FROM performance_schema.threads WHERE PROCESSLIST_ID = CONNECTION_ID())) "+
						"FROM %s WHERE token = '%s'", f.table, valuePH)
				}
				r, err := f.query(t, q)
				if err != nil {
					t.Fatal(err)
				}
				got := cells(r)
				if len(got) != 1 || !strings.Contains(got[0][0], "token = "+marker) || strings.Contains(got[0][0], f.value.Value()) ||
					strings.Contains(got[0][0], "scrim:") {
					t.Fatalf("the server's statement text is %q, want the parameter marker and neither value nor placeholder", got)
				}
			})

			t.Run("unbound placeholder", func(t *testing.T) {
				_, err := f.query(t, fmt.Sprintf("SELECT id FROM %s WHERE token = '%s'", f.table, ph2))
				var re *RefusedError
				if !errors.As(err, &re) || !strings.Contains(re.Reason, "not a credential bound") {
					t.Fatalf("want a refusal, got %v", err)
				}
			})

			t.Run("writes refused before they are sent", func(t *testing.T) {
				for _, q := range []string{
					fmt.Sprintf("INSERT INTO %s VALUES (70, 'x')", f.table),
					fmt.Sprintf("UPDATE %s SET token = 'x'", f.table),
					fmt.Sprintf("DELETE FROM %s", f.table),
					"CREATE TABLE evil (a int)",
					fmt.Sprintf("DROP TABLE %s", f.table),
					fmt.Sprintf("SELECT 1; DELETE FROM %s", f.table),
				} {
					_, err := f.query(t, q)
					var re *RefusedError
					if !errors.As(err, &re) {
						t.Errorf("%q: want a refusal, got %v", q, err)
					}
				}
			})

			t.Run("writes inside functions stopped by the read-only transaction", func(t *testing.T) {
				qs := []string{fmt.Sprintf("SELECT %s()", f.fn)}
				if d.kind == Postgres {
					qs = append(qs, "SELECT nextval('s_"+strings.TrimPrefix(f.table, "t_")+"')")
				}
				for _, q := range qs {
					_, err := f.query(t, q)
					var qe *QueryError
					if !errors.As(err, &qe) || !strings.Contains(strings.ToLower(qe.Message), "read") {
						t.Errorf("%q: want the read-only transaction's error, got %v", q, err)
					}
				}
			})

			if got := count(); got != before {
				t.Fatalf("rows %s after the refused writes, want %s", got, before)
			}

			t.Run("row limit", func(t *testing.T) {
				q := "WITH RECURSIVE r(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM r WHERE n < 50) SELECT n FROM r"
				r, err := f.query(t, q)
				if err != nil {
					t.Fatal(err)
				}
				if len(r.Rows) != 10 || !r.Truncated {
					t.Fatalf("%d rows, truncated %v; want 10, true", len(r.Rows), r.Truncated)
				}
			})

			t.Run("statement timeout", func(t *testing.T) {
				q := "SELECT pg_sleep(20)"
				if d.kind == MySQL {
					q = "SELECT SLEEP(20)"
				}
				start := time.Now()
				_, _ = f.query(t, q)
				if took := time.Since(start); took > 10*time.Second {
					t.Fatalf("a 20 s statement ran %s under a 2 s timeout", took)
				}
			})

			t.Run("the password never comes back", func(t *testing.T) {
				f.srv.Exec(t, fmt.Sprintf("INSERT INTO %s%s VALUES (60, '%s')",
					map[Kind]string{Postgres: "", MySQL: "scrim."}[d.kind], f.table, f.password.Value()))
				r, err := f.query(t, fmt.Sprintf("SELECT token FROM %s WHERE id = 60", f.table))
				if err == nil {
					f.noPassword(t, "tool result", []byte(fmt.Sprint(cells(r))))
					t.Fatal("the row holding the password was returned")
				}
				f.noPassword(t, "tool error", []byte(err.Error()))
			})
		})
	}
}
