// SPDX-License-Identifier: AGPL-3.0-only

package dbproxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/heliopsy/scrim/internal/leak"
	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/testing/dbtest"
	"github.com/heliopsy/scrim/internal/testing/podtest"
)

var (
	pgServer    = dbtest.Postgres()
	mysqlServer = dbtest.MySQL()
	mariaServer = dbtest.MariaDB()
)

func TestMain(m *testing.M) {
	code := m.Run()
	pgServer.Stop()
	mysqlServer.Stop()
	mariaServer.Stop()
	os.Exit(code)
}

// recorder keeps every byte a client read from the proxy, so a test can look
// for the password in all of it.
type recorder struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (r *recorder) wrap(c net.Conn) net.Conn { return &recConn{Conn: c, r: r} }

func (r *recorder) bytes() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return bytes.Clone(r.buf.Bytes())
}

type recConn struct {
	net.Conn
	r *recorder
}

func (c *recConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.r.mu.Lock()
	c.r.buf.Write(p[:n])
	c.r.mu.Unlock()
	return n, err
}

// fixture is one database user behind a proxy.
type fixture struct {
	srv      *dbtest.Server
	db       *Database
	proxy    *Proxy
	addr     string // TCP listener
	sock     string // Unix socket
	user     string
	password leak.Seed // the database password
	value    leak.Seed // a secret stored in the table, queried by placeholder
	table    string
	fn       string
	refuse   error
	seen     []string
	mu       sync.Mutex
}

func (f *fixture) checker() *leak.Checker { return leak.NewChecker([]leak.Seed{f.password}) }

func (f *fixture) noPassword(t *testing.T, what string, b []byte) {
	t.Helper()
	if fs := f.checker().CheckText(1, string(b)); len(fs) > 0 {
		t.Fatalf("%s: the database password reached the client: %+v", what, fs)
	}
}

func (f *fixture) setRefuse(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.refuse = err
}

func (f *fixture) authorize(_ context.Context, db *Database, c net.Conn) (Caller, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, c.RemoteAddr().Network())
	if f.refuse != nil {
		return Caller{}, f.refuse
	}
	return Caller{Agent: "test-agent"}, nil
}

func newFixture(t *testing.T, srv *dbtest.Server, kind Kind, md5 bool) *fixture {
	t.Helper()
	srv.Start(t)
	id := podtest.RandHex(4)
	f := &fixture{srv: srv, user: "agent_" + id, table: "t_" + id, fn: "f_" + id,
		password: leak.Generate(leak.KindDBPassword), value: leak.Generate(leak.KindAPIKey)}
	pw := f.password.Value()
	switch srv.Kind {
	case "postgres":
		enc := "scram-sha-256"
		if md5 {
			enc = "md5"
		}
		srv.Exec(t,
			fmt.Sprintf("SET password_encryption = '%s'; CREATE ROLE %s LOGIN PASSWORD '%s'", enc, f.user, pw),
			fmt.Sprintf("CREATE TABLE %s (id int PRIMARY KEY, token text)", f.table),
			fmt.Sprintf("INSERT INTO %s VALUES (1, '%s'), (2, 'other')", f.table, f.value.Value()),
			fmt.Sprintf("GRANT SELECT, INSERT, UPDATE, DELETE ON %s TO %s", f.table, f.user),
			fmt.Sprintf("CREATE SEQUENCE s_%s", id),
			fmt.Sprintf("GRANT USAGE, UPDATE ON SEQUENCE s_%s TO %s", id, f.user),
			fmt.Sprintf("CREATE FUNCTION %s() RETURNS int LANGUAGE sql VOLATILE AS 'INSERT INTO %s VALUES (99, ''w'') RETURNING id'", f.fn, f.table),
			fmt.Sprintf("GRANT CREATE ON SCHEMA public TO %s", f.user),
		)
		if md5 {
			if got := srv.QueryString(t, "SELECT left(rolpassword, 3) FROM pg_authid WHERE rolname = $1", f.user); got != "md5" {
				t.Fatalf("role password is not md5 (%s)", got)
			}
		}
	case "mysql", "mariadb":
		plugin := "caching_sha2_password"
		if srv.Kind == "mariadb" {
			plugin = "mysql_native_password"
		}
		create := fmt.Sprintf("CREATE USER '%s'@'%%' IDENTIFIED WITH %s BY '%s'", f.user, plugin, pw)
		if srv.Kind == "mariadb" {
			create = fmt.Sprintf("CREATE USER '%s'@'%%' IDENTIFIED VIA mysql_native_password USING PASSWORD('%s')", f.user, pw)
		}
		srv.Exec(t, create,
			fmt.Sprintf("CREATE TABLE scrim.%s (id int PRIMARY KEY, token text)", f.table),
			fmt.Sprintf("INSERT INTO scrim.%s VALUES (1, '%s'), (2, 'other')", f.table, f.value.Value()),
			fmt.Sprintf("GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, DROP ON scrim.* TO '%s'@'%%'", f.user),
			fmt.Sprintf("CREATE FUNCTION scrim.%s() RETURNS INT MODIFIES SQL DATA BEGIN INSERT INTO scrim.%s VALUES (99, 'w'); RETURN 1; END", f.fn, f.table),
			fmt.Sprintf("GRANT EXECUTE ON FUNCTION scrim.%s TO '%s'@'%%'", f.fn, f.user),
		)
		if srv.Kind == "mysql" {
			srv.Exec(t, fmt.Sprintf("GRANT SELECT ON performance_schema.* TO '%s'@'%%'", f.user))
		}
	}
	f.db = &Database{
		Name: "app", Kind: kind, Address: srv.Addr, User: f.user, DBName: "scrim", TLS: TLSVerifyFull,
		TLSConfig: &tls.Config{RootCAs: srv.CertPool(), MinVersion: tls.VersionTLS12},
		Password: func(context.Context) (secret.Value, error) {
			return secret.FromString(pw), nil
		},
	}
	f.proxy = &Proxy{DB: f.db, Authorize: f.authorize}
	f.serve(t)
	return f
}

func (f *fixture) serve(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp("", "scrim-db")
	if err != nil {
		t.Fatal(err)
	}
	f.sock = filepath.Join(dir, ".s.PGSQL.5432")
	uln, err := net.Listen("unix", f.sock)
	if err != nil {
		t.Fatal(err)
	}
	f.addr = ln.Addr().String()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); _ = f.proxy.Serve(ctx, ln) }()
	go func() { defer wg.Done(); _ = f.proxy.Serve(ctx, uln) }()
	t.Cleanup(func() {
		cancel()
		wg.Wait()
		_ = os.RemoveAll(dir)
	})
}

// pgClient connects to the proxy as an agent would: no password, TLS
// preferred (the proxy declines it), recording what it reads.
func (f *fixture) pgClient(t *testing.T, rec *recorder, viaSocket bool) (*pgconn.PgConn, error) {
	t.Helper()
	host, port, _ := net.SplitHostPort(f.addr)
	dsn := fmt.Sprintf("host=%s port=%s user=agent dbname=scrim sslmode=prefer connect_timeout=20", host, port)
	if viaSocket {
		dsn = fmt.Sprintf("host=%s port=5432 user=agent dbname=scrim connect_timeout=20", filepath.Dir(f.sock))
	}
	cfg, err := pgconn.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Password = ""
	d := &net.Dialer{}
	cfg.DialFunc = func(ctx context.Context, network, addr string) (net.Conn, error) {
		c, err := d.DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		return rec.wrap(c), nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return pgconn.ConnectConfig(ctx, cfg)
}

func pgQuery(t *testing.T, c *pgconn.PgConn, q string) ([][]string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	res, err := c.Exec(ctx, q).ReadAll()
	if err != nil {
		return nil, err
	}
	var rows [][]string
	for _, r := range res {
		if r.Err != nil {
			return nil, r.Err
		}
		for _, row := range r.Rows {
			var out []string
			for _, v := range row {
				out = append(out, string(v))
			}
			rows = append(rows, out)
		}
	}
	return rows, nil
}

func TestPostgresProxy(t *testing.T) {
	for _, md5 := range []bool{false, true} {
		name := "scram"
		if md5 {
			name = "md5"
		}
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, pgServer, Postgres, md5)
			for _, sock := range []bool{false, true} {
				rec := &recorder{}
				c, err := f.pgClient(t, rec, sock)
				if err != nil {
					t.Fatalf("connecting through the proxy (socket %v): %v", sock, err)
				}
				rows, err := pgQuery(t, c, "SELECT current_user, (SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid())")
				if err != nil {
					t.Fatal(err)
				}
				if rows[0][0] != f.user || rows[0][1] != "t" {
					t.Fatalf("session is %v, want user %s over TLS", rows[0], f.user)
				}
				// The proxy is the agent's own session, not read-only.
				if _, err := pgQuery(t, c, fmt.Sprintf("INSERT INTO %s VALUES (%d, 'via proxy')", f.table, 10+boolInt(sock))); err != nil {
					t.Fatalf("insert through the proxy: %v", err)
				}
				_ = c.Close(context.Background())
				f.noPassword(t, "postgres session", rec.bytes())
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			if len(f.seen) != 2 || f.seen[0] != "tcp" || f.seen[1] != "unix" {
				t.Fatalf("authorizer saw %v, want tcp then unix", f.seen)
			}
		})
	}
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func TestPostgresProxyRefusals(t *testing.T) {
	f := newFixture(t, pgServer, Postgres, false)

	t.Run("not authorized", func(t *testing.T) {
		f.setRefuse(Refused("database app: denied by policy (no rule matches)"))
		defer f.setRefuse(nil)
		_, err := f.pgClient(t, &recorder{}, false)
		if err == nil || !strings.Contains(err.Error(), "denied by policy") {
			t.Fatalf("want the policy refusal, got %v", err)
		}
	})

	t.Run("password in a result closes the session", func(t *testing.T) {
		f.srv.Exec(t, fmt.Sprintf("INSERT INTO %s VALUES (50, 'prefix %s suffix')", f.table, f.password.Value()))
		rec := &recorder{}
		c, err := f.pgClient(t, rec, false)
		if err != nil {
			t.Fatal(err)
		}
		_, err = pgQuery(t, c, fmt.Sprintf("SELECT token FROM %s WHERE id = 50", f.table))
		if err == nil {
			t.Fatal("the row with the password was delivered")
		}
		f.noPassword(t, "leaking row", rec.bytes())
	})

	t.Run("server certificate not trusted", func(t *testing.T) {
		db := *f.db
		db.TLSConfig = &tls.Config{RootCAs: x509.NewCertPool(), MinVersion: tls.VersionTLS12}
		p := &Proxy{DB: &db, Authorize: f.authorize}
		_, err := pipeConnect(t, p)
		if err == nil || !strings.Contains(err.Error(), "does not verify") {
			t.Fatalf("want a verification refusal, got %v", err)
		}
	})

	t.Run("server certificate for another host", func(t *testing.T) {
		db := *f.db
		db.TLSConfig = &tls.Config{RootCAs: f.srv.CertPool(), ServerName: "db.example.com", MinVersion: tls.VersionTLS12}
		p := &Proxy{DB: &db, Authorize: f.authorize}
		_, err := pipeConnect(t, p)
		if err == nil || !strings.Contains(err.Error(), "does not name the host") {
			t.Fatalf("want a host name refusal, got %v", err)
		}
	})

	t.Run("wrong password from the store", func(t *testing.T) {
		db := *f.db
		db.Password = func(context.Context) (secret.Value, error) { return secret.FromString("not-the-password"), nil }
		p := &Proxy{DB: &db, Authorize: f.authorize}
		_, err := pipeConnect(t, p)
		if err == nil || !strings.Contains(err.Error(), "refused scrim's login") {
			t.Fatalf("want the server's refusal, got %v", err)
		}
	})
}

// pipeConnect logs a pgconn client in through p over an in-memory pipe.
func pipeConnect(t *testing.T, p *Proxy) (*pgconn.PgConn, error) {
	t.Helper()
	cfg, err := pgconn.ParseConfig("host=scrim port=5432 user=agent dbname=scrim sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	cfg.LookupFunc = func(_ context.Context, h string) ([]string, error) { return []string{h}, nil }
	cfg.DialFunc = func(ctx context.Context, _, _ string) (net.Conn, error) {
		a, b := net.Pipe()
		go p.ServeConn(ctx, b)
		return a, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	c, err := pgconn.ConnectConfig(ctx, cfg)
	if err == nil {
		t.Cleanup(func() { _ = c.Close(context.Background()) })
	}
	return c, err
}

// mysqlClient connects through the proxy with go-sql-driver, sending a
// placeholder as its password (ignored), recording what it reads.
func (f *fixture) mysqlClient(t *testing.T, rec *recorder) *sql.DB {
	t.Helper()
	netName := "rec-" + podtest.RandHex(4)
	mysql.RegisterDialContext(netName, func(ctx context.Context, addr string) (net.Conn, error) {
		var d net.Dialer
		c, err := d.DialContext(ctx, "tcp", addr)
		if err != nil {
			return nil, err
		}
		return rec.wrap(c), nil
	})
	cfg := mysql.NewConfig()
	cfg.User, cfg.Passwd, cfg.Net, cfg.Addr, cfg.DBName = "agent", "⟦scrim:app-db:01a1b2c3d4e5f60718⟧", netName, f.addr, "scrim"
	cfg.AllowNativePasswords = true
	c, err := mysql.NewConnector(cfg)
	if err != nil {
		t.Fatal(err)
	}
	db := sql.OpenDB(c)
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestMySQLProxy(t *testing.T) {
	for _, srv := range []*dbtest.Server{mysqlServer, mariaServer} {
		t.Run(srv.Kind, func(t *testing.T) {
			f := newFixture(t, srv, MySQL, false)
			// Twice: MySQL's first caching_sha2_password login is the full
			// exchange (password over TLS), the second the fast one.
			for i := range 2 {
				rec := &recorder{}
				db := f.mysqlClient(t, rec)
				var user, cipher, name string
				if err := db.QueryRow("SELECT CURRENT_USER()").Scan(&user); err != nil {
					t.Fatalf("login %d through the proxy: %v", i, err)
				}
				if !strings.HasPrefix(user, f.user+"@") {
					t.Fatalf("session user %q, want %s", user, f.user)
				}
				if err := db.QueryRow("SHOW SESSION STATUS LIKE 'Ssl_cipher'").Scan(&name, &cipher); err != nil || cipher == "" {
					t.Fatalf("the upstream session is not TLS: %q %v", cipher, err)
				}
				if _, err := db.Exec(fmt.Sprintf("INSERT INTO %s VALUES (?, 'via proxy')", f.table), 10+i); err != nil {
					t.Fatalf("prepared insert through the proxy: %v", err)
				}
				_ = db.Close()
				f.noPassword(t, srv.Kind+" session", rec.bytes())
			}

			t.Run("password in a result closes the session", func(t *testing.T) {
				f.srv.Exec(t, fmt.Sprintf("INSERT INTO scrim.%s VALUES (50, 'prefix %s suffix')", f.table, f.password.Value()))
				rec := &recorder{}
				db := f.mysqlClient(t, rec)
				var tok string
				if err := db.QueryRow(fmt.Sprintf("SELECT token FROM %s WHERE id = 50", f.table)).Scan(&tok); err == nil {
					t.Fatal("the row with the password was delivered")
				}
				f.noPassword(t, "leaking row", rec.bytes())
			})

			t.Run("not authorized", func(t *testing.T) {
				f.setRefuse(Refused("database app: denied by policy (no rule matches)"))
				defer f.setRefuse(nil)
				db := f.mysqlClient(t, &recorder{})
				err := db.Ping()
				if err == nil || !strings.Contains(err.Error(), "denied by policy") {
					t.Fatalf("want the policy refusal, got %v", err)
				}
			})
		})
	}
}

func TestMySQLFullAuthNeedsTLS(t *testing.T) {
	f := newFixture(t, mysqlServer, MySQL, false)
	f.db.TLS, f.db.TLSConfig = TLSInsecurePlaintext, nil
	db := f.mysqlClient(t, &recorder{})
	err := db.Ping()
	if err == nil || !strings.Contains(err.Error(), "only over TLS") {
		t.Fatalf("want a refusal of full authentication without TLS, got %v", err)
	}
}

func TestMySQLChangeUserRefused(t *testing.T) {
	f := newFixture(t, mariaServer, MySQL, false)
	c, err := net.Dial("tcp", f.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(30 * time.Second))
	if _, _, err := myRead(c); err != nil {
		t.Fatal(err)
	}
	resp := binary.LittleEndian.AppendUint32(nil, myProtocol41|mySecureConnection|myPluginAuth|myLongPassword)
	resp = binary.LittleEndian.AppendUint32(resp, 1<<24)
	resp = append(resp, 33)
	resp = append(resp, make([]byte, 23)...)
	resp = append(resp, "agent"...)
	resp = append(resp, 0, 0)
	resp = append(resp, myAgentPlugin...)
	resp = append(resp, 0)
	if err := myWrite(c, 1, resp); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := myRead(c); err != nil || ok[0] != 0 {
		t.Fatalf("login: %v %x", err, ok)
	}
	if err := myWrite(c, 0, append([]byte{myComChangeUser}, "root\x00"...)); err != nil {
		t.Fatal(err)
	}
	_, pk, err := myRead(c)
	if err != nil {
		t.Fatal(err)
	}
	if pk[0] != 0xff || !strings.Contains(string(pk), "changing the user") {
		t.Fatalf("COM_CHANGE_USER was not refused: %q", pk)
	}
	// The session still works as the configured user.
	if err := myWrite(c, 0, append([]byte{0x03}, "SELECT CURRENT_USER()"...)); err != nil {
		t.Fatal(err)
	}
	var all []byte
	for range 5 {
		_, pk, err := myRead(c)
		if err != nil {
			t.Fatal(err)
		}
		all = append(all, pk...)
		if bytes.Contains(all, []byte(f.user)) {
			return
		}
	}
	t.Fatalf("session user not %s: %q", f.user, all)
}
