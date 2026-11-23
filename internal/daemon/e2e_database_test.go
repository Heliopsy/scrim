// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"context"
	"fmt"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/heliopsy/scrim/internal/agenttools"
	"github.com/heliopsy/scrim/internal/leak"
	"github.com/heliopsy/scrim/internal/localapi"
	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores"
	"github.com/heliopsy/scrim/internal/testing/dbtest"
	"github.com/heliopsy/scrim/internal/testing/fakeprovider"
	"github.com/heliopsy/scrim/internal/testing/podtest"
)

var dbtestPostgres = dbtest.Postgres()

// TestDatabaseProxyAndToolRealDataPlane runs the daemon on the real data
// plane with a PostgreSQL database configured: an agent connects to the
// local proxy without a password and is logged in as the configured user
// over verified TLS; the read-only tool finds a row by the placeholder of a
// credential bound to the database host and returns the row with the value
// redacted back to its placeholder; a write and an unbound host are refused;
// neither the database password nor the secret appears in anything the
// agent received or in the log. The password of "app" is a store reference
// (files://db-password): it is read through the file store, is in the
// redaction set, and a rotated value is used by the next login.
func TestDatabaseProxyAndToolRealDataPlane(t *testing.T) {
	bin := realDataPlane(t)
	dbtestPostgres.Start(t)
	up := httptestServer(t)
	token := seed(t, "sk-db-")
	pw := leak.Generate(leak.KindDBPassword)
	id := podtest.RandHex(4)
	user, table := "agent_"+id, "t_"+id
	dbtestPostgres.Exec(t,
		fmt.Sprintf("CREATE ROLE %s LOGIN PASSWORD '%s'", user, pw.Value()),
		fmt.Sprintf("CREATE TABLE %s (id int PRIMARY KEY, token text)", table),
		fmt.Sprintf("INSERT INTO %s VALUES (1, '%s'), (2, 'other')", table, token),
		fmt.Sprintf("GRANT SELECT, INSERT ON %s TO %s", table, user))

	h := newHarness(t, token)
	dir := h.dir
	if err := os.WriteFile(filepath.Join(dir, "db-ca.pem"), dbtestPostgres.CAPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "db-pw"), []byte(pw.Value()), 0o600); err != nil {
		t.Fatal(err)
	}
	storeRoot := filepath.Join(dir, "store")
	if err := os.MkdirAll(storeRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(storeRoot, "db-password"), []byte(pw.Value()), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "rules.yaml"), []byte(`default: deny
rules:
  - name: databases-for-agents
    decision: allow
    when: op == "database.auth" && agent.known && dest.path in ["/app", "/byname"]
  - name: inject-known
    decision: allow
    when: op == "inject" && agent.known
`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(dir, "config.yaml")
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	host, port, _ := net.SplitHostPort(dbtestPostgres.Addr)
	cfg := strings.Replace(string(raw), "hosts: [api.acme.test]", "hosts: [api.acme.test, "+host+"]", 1)
	cfg = strings.Replace(cfg, "stores:\n", "stores:\n  files:\n    kind: file\n    root: "+storeRoot+"\n", 1)
	db := func(name, addr, password string) string {
		return fmt.Sprintf("  %s:\n    kind: postgres\n    address: %s\n    user: %s\n    password: %s\n    database: scrim\n"+
			"    listen: 127.0.0.1:0\n    tls-ca: %s\n    tls-server-name: localhost\n    query-timeout: 5s\n",
			name, addr, user, password, filepath.Join(dir, "db-ca.pem"))
	}
	cfg += "databases:\n" + db("app", dbtestPostgres.Addr, "files://db-password") +
		db("byname", "localhost:"+port, "file:"+filepath.Join(dir, "db-pw"))
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	d := h.startReal(t, ctx, bin, up)
	addr := d.Addrs().Databases["app"]
	if addr == "" {
		t.Fatalf("no listener for database app in %+v", d.Addrs())
	}
	rotated := leak.Generate(leak.KindDBPassword)
	checker := leak.NewChecker([]leak.Seed{pw, rotated, leak.NewSeed("acme", leak.KindAPIKey, token)})
	noLeak := func(what, text string) {
		t.Helper()
		if fs := checker.CheckText(1, text); len(fs) > 0 {
			t.Fatalf("%s leaked: %+v", what, fs)
		}
	}

	// The proxy: no password, scrim logs in with the password from the
	// file store.
	lh, lp, _ := net.SplitHostPort(addr)
	login := func(what string) {
		t.Helper()
		pc, err := pgconn.Connect(ctx, fmt.Sprintf("host=%s port=%s user=anyone dbname=scrim sslmode=disable", lh, lp))
		if err != nil {
			t.Fatalf("proxy login (%s): %v\n%s", what, err, h.logs.String())
		}
		defer func() { _ = pc.Close(ctx) }()
		res, err := pc.Exec(ctx, "SELECT current_user, (SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid())").ReadAll()
		if err != nil || len(res) != 1 || len(res[0].Rows) != 1 {
			t.Fatalf("query through the proxy (%s): %v", what, err)
		}
		if got := res[0].Rows[0]; string(got[0]) != user || string(got[1]) != "t" {
			t.Fatalf("proxy session %q (%s), want %s over TLS", got, what, user)
		}
	}
	// The store's password is in the redaction set before any login.
	redacted := func(what string, v leak.Seed) {
		t.Helper()
		deadline := time.Now().Add(10 * time.Second)
		for {
			red, err := d.redact(ctx, []byte("password "+v.Value()+"\n"))
			// The store reference is what matched, not a pattern detector.
			fromStore := false
			for _, r := range red.Refs {
				fromStore = fromStore || strings.HasPrefix(r, "files://db-password")
			}
			if err == nil && fromStore && len(checker.CheckText(1, string(red.Text))) == 0 {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("%s: database password not redacted by its store reference (refs %v): %v", what, red.Refs, err)
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	redacted("store reference", pw)
	login("store reference")

	// The tool, by placeholder.
	ph := d.builder.PlaceholderFor(stores.Ref{Scheme: "testenv", Path: "SCRIMTEST_TOKEN"})
	if !strings.HasPrefix(ph, "⟦scrim:acme:") {
		t.Fatalf("placeholder %q", ph)
	}
	c := localapi.NewClient(d.Addrs().AgentAPI, secret.Value{})
	defer c.Close()
	out, err := c.DatabaseQuery(ctx, localapi.DatabaseQueryInput{Database: "app",
		SQL: fmt.Sprintf("SELECT id, token, current_query() AS q FROM %s WHERE token = '%s'", table, ph)})
	if err != nil {
		t.Fatalf("database_query: %v\n%s", err, h.logs.String())
	}
	if len(out.Rows) != 1 || *out.Rows[0][0] != "1" || *out.Rows[0][1] != ph || !strings.Contains(*out.Rows[0][2], "token = $1") {
		t.Fatalf("database_query rows %v", out.Rows)
	}
	noLeak("tool result", fmt.Sprint(out))

	// A write, an unbound host, and the server echoing a bound value.
	_, err = c.DatabaseQuery(ctx, localapi.DatabaseQueryInput{Database: "app", SQL: "DELETE FROM " + table})
	if agenttools.CodeOf(err) != agenttools.CodeForbidden {
		t.Fatalf("delete: want forbidden, got %v", err)
	}
	_, err = c.DatabaseQuery(ctx, localapi.DatabaseQueryInput{Database: "byname",
		SQL: fmt.Sprintf("SELECT id FROM %s WHERE token = '%s'", table, ph)})
	if agenttools.CodeOf(err) != agenttools.CodeForbidden || !strings.Contains(err.Error(), "not bound to localhost") {
		t.Fatalf("unbound host: want forbidden, got %v", err)
	}
	_, err = c.DatabaseQuery(ctx, localapi.DatabaseQueryInput{Database: "app", SQL: "SELECT $1::int", Params: []string{ph}})
	if err == nil {
		t.Fatal("casting the secret to int succeeded")
	}
	noLeak("database error", err.Error())
	if !strings.Contains(err.Error(), "⟦scrim:acme:") {
		t.Logf("database error without the placeholder: %v", err)
	}

	if got := dbtestPostgres.QueryString(t, "SELECT count(*) FROM "+table); got != "2" {
		t.Fatalf("%s rows after the refused write, want 2", got)
	}
	// Rotation, last because it leaves the file: password of byname stale:
	// the role and the store get a new password; after the store refreshes,
	// the next login uses it and both values stay redacted.
	dbtestPostgres.Exec(t, fmt.Sprintf("ALTER ROLE %s PASSWORD '%s'", user, rotated.Value()))
	if err := os.WriteFile(filepath.Join(storeRoot, "db-password"), []byte(rotated.Value()), 0o600); err != nil {
		t.Fatal(err)
	}
	r, err := d.refresherFor(stores.Ref{Scheme: "files", Path: "db-password"})
	if err != nil {
		t.Fatal(err)
	}
	if err := r.RefreshNow(ctx); err != nil {
		t.Fatal(err)
	}
	login("rotated")
	redacted("rotated", rotated)
	redacted("retained after rotation", pw)
	noLeak("log", h.logs.String())
}

func httptestServer(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(fakeprovider.New(fakeprovider.Options{}))
	t.Cleanup(srv.Close)
	return srv.URL
}
