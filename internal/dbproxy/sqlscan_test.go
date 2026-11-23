// SPDX-License-Identifier: AGPL-3.0-only

package dbproxy

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

const ph = "⟦scrim:app-token:01a1b2c3d4e5f60718⟧"
const ph2 = "⟦scrim:other:01ffeeddccbbaa9988⟧"

func TestPrepareLiteralsBecomeParameters(t *testing.T) {
	cases := []struct {
		kind   Kind
		sql    string
		params []string
		want   string
		args   []string
	}{
		{Postgres, "SELECT id FROM t WHERE token = '" + ph + "'", nil,
			"SELECT id FROM t WHERE token = $1", []string{ph}},
		{Postgres, "SELECT id FROM t WHERE a = $1 AND token = 'x-" + ph + "-''y' AND b = '" + ph2 + "';", []string{"1"},
			"SELECT id FROM t WHERE a = $1 AND token = $2 AND b = $3", []string{"1", "x-" + ph + "-'y", ph2}},
		{Postgres, "SELECT '" + ph + "'::text -- a comment '" + ph2 + "'\n", nil,
			"SELECT $1::text -- a comment '" + ph2 + "'", []string{ph}},
		{MySQL, "SELECT id FROM t WHERE a = ? AND token = '" + ph + "' AND b = ?", []string{"1", "2"},
			"SELECT id FROM t WHERE a = ? AND token = ? AND b = ?", []string{"1", ph, "2"}},
		{MySQL, `SELECT id FROM t WHERE token = "` + ph + `" # trailing`, nil,
			"SELECT id FROM t WHERE token = ? # trailing", []string{ph}},
		{MySQL, "SELECT 1 --x\n", nil, "SELECT 1 --x", nil},
		{Postgres, "WITH x AS (SELECT 1) SELECT * FROM x", nil, "WITH x AS (SELECT 1) SELECT * FROM x", nil},
		{Postgres, "SELECT $$it's " + "text$$, $tag$a$tag$", nil, "SELECT $$it's text$$, $tag$a$tag$", nil},
	}
	for _, c := range cases {
		st, err := prepare(c.kind, c.sql, c.params)
		if err != nil {
			t.Fatalf("%s %q: %v", c.kind, c.sql, err)
		}
		if st.sql != c.want || !slices.Equal(st.args, c.args) {
			t.Errorf("%s %q:\n got %q %q\nwant %q %q", c.kind, c.sql, st.sql, st.args, c.want, c.args)
		}
		if strings.Contains(st.sql, "scrim:app-token") && !strings.Contains(c.want, "scrim:app-token") {
			t.Errorf("placeholder left in SQL text: %q", st.sql)
		}
	}
}

func TestPrepareRefuses(t *testing.T) {
	cases := []struct {
		kind Kind
		sql  string
		args []string
		why  string
	}{
		{Postgres, "INSERT INTO t VALUES (1)", nil, "INSERT"},
		{Postgres, "update t set a = 1", nil, "UPDATE"},
		{Postgres, "DELETE FROM t", nil, "DELETE"},
		{Postgres, "CREATE TABLE x (a int)", nil, "CREATE"},
		{Postgres, "DROP TABLE t", nil, "DROP"},
		{Postgres, "TRUNCATE t", nil, "TRUNCATE"},
		{Postgres, "WITH d AS (DELETE FROM t RETURNING *) SELECT * FROM d", nil, "DELETE"},
		{Postgres, "SELECT * INTO new_t FROM t", nil, "INTO"},
		{Postgres, "SELECT * FROM t FOR UPDATE", nil, "UPDATE"},
		{Postgres, "SELECT 1; DROP TABLE t", nil, "one statement"},
		{Postgres, "SELECT 1; SELECT 2", nil, "one statement"},
		{Postgres, "COPY t TO PROGRAM 'x'", nil, "COPY"},
		{Postgres, "SET ROLE admin", nil, "SET"},
		{Postgres, "", nil, "empty"},
		{Postgres, "SELECT " + ph, nil, "inside a string literal"},
		{Postgres, `SELECT 1 AS "` + ph + `"`, nil, "quoted identifier"},
		{Postgres, "SELECT E'" + ph + "'", nil, "plain string literal"},
		{Postgres, "SELECT $x$" + ph + "$x$", nil, "dollar-quoted"},
		{Postgres, "SELECT $2", []string{"a"}, "$2"},
		{Postgres, "SELECT 'unterminated", nil, "unterminated"},
		{MySQL, "SELECT * FROM t INTO OUTFILE '/tmp/x'", nil, "INTO"},
		{MySQL, "SELECT 1 /*! ; DROP TABLE t */", nil, "executable comments"},
		{MySQL, "REPLACE INTO t VALUES (1)", nil, "REPLACE"},
		{MySQL, "SELECT ?", nil, "markers"},
		{MySQL, "SELECT '" + ph + "\\n'", nil, "backslash"},
		{MySQL, "SELECT _utf8mb4'" + ph + "'", nil, "plain string literal"},
		{MySQL, "SELECT 1 --x; DROP TABLE t", nil, "one statement"},
		{MySQL, "DO SLEEP(1)", nil, "DO"},
	}
	for _, c := range cases {
		_, err := prepare(c.kind, c.sql, c.args)
		var re *RefusedError
		if !errors.As(err, &re) {
			t.Errorf("%s %q: want a refusal, got %v", c.kind, c.sql, err)
			continue
		}
		if !strings.Contains(re.Reason, c.why) {
			t.Errorf("%s %q: refusal %q does not mention %q", c.kind, c.sql, re.Reason, c.why)
		}
	}
}

func FuzzPrepareNeverLeavesPlaceholderLiteral(f *testing.F) {
	f.Add("SELECT '" + ph + "'")
	f.Add("SELECT \"" + ph + "\" FROM t WHERE x = '" + ph2 + "'")
	f.Add("SELECT $$" + ph + "$$")
	f.Fuzz(func(t *testing.T, sql string) {
		for _, k := range []Kind{Postgres, MySQL} {
			st, err := prepare(k, sql, nil)
			if err != nil {
				continue
			}
			// A placeholder may survive only inside a comment, which the
			// server ignores; never in a literal the server would read.
			stripped := stripComments(k, st.sql)
			if strings.Contains(stripped, "⟦scrim:") {
				t.Fatalf("%s: placeholder outside a comment survived: %q -> %q", k, sql, st.sql)
			}
		}
	})
}

// stripComments removes -- and /* */ comments with a scanner of its own, for
// the fuzz check above.
func stripComments(k Kind, s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		switch {
		case s[i] == '\'' || s[i] == '"' || s[i] == '`':
			q := s[i]
			j := i + 1
			for j < len(s) {
				if s[j] == '\\' && k == MySQL {
					j += 2
					continue
				}
				if s[j] == q {
					if j+1 < len(s) && s[j+1] == q {
						j += 2
						continue
					}
					break
				}
				j++
			}
			b.WriteString(s[i:min(j+1, len(s))])
			i = j + 1
		case strings.HasPrefix(s[i:], "--") || (k == MySQL && s[i] == '#'):
			j := strings.IndexByte(s[i:], '\n')
			if j < 0 {
				return b.String()
			}
			i += j
		case strings.HasPrefix(s[i:], "/*"):
			j := strings.Index(s[i+2:], "*/")
			if j < 0 {
				return b.String()
			}
			i += j + 4
		default:
			b.WriteByte(s[i])
			i++
		}
	}
	return b.String()
}
