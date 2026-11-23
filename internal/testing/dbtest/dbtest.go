// SPDX-License-Identifier: AGPL-3.0-only

// Package dbtest gives tests PostgreSQL, MySQL and MariaDB servers that
// speak TLS with a certificate from a CA the test holds, so a client can
// verify the server the way scrim's database proxy does. The first
// [Server.Start] runs a throwaway container with rootless podman, named
// "<prefix>-<kind>-<random>" (prefix as in podtest), memory-limited;
// [Server.Stop] removes it with its anonymous volumes. Without podman every
// caller skips with the reason; SCRIM_TEST_PODMAN=0 skips without trying and
// SCRIM_TEST_PODMAN=1 turns the skip into a failure (CI). A package using it
// calls Stop from TestMain after m.Run.
package dbtest

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
	_ "github.com/jackc/pgx/v5/stdlib" // the pgx database/sql driver

	"github.com/heliopsy/scrim/internal/testing/podtest"
)

// Images started when the matching variable (SCRIM_TEST_POSTGRES_IMAGE,
// SCRIM_TEST_MYSQL_IMAGE, SCRIM_TEST_MARIADB_IMAGE) is unset. MySQL covers
// caching_sha2_password (its default and only password plugin since 9.0),
// MariaDB mysql_native_password.
const (
	PostgresImage = "docker.io/library/postgres:19.0-alpine3.24"
	MySQLImage    = "docker.io/library/mysql:9.7.4"
	MariaDBImage  = "docker.io/library/mariadb:13.0.2"
)

// Server is one database container.
type Server struct {
	// Kind is postgres, mysql or mariadb.
	Kind string
	// Addr is host:port of the server, published on 127.0.0.1.
	Addr string
	// Admin is the administrator's password (user scrim on PostgreSQL,
	// root on MySQL and MariaDB). Test-generated.
	Admin string
	// CAPEM is the CA that issued the server's certificate, which names
	// localhost and 127.0.0.1.
	CAPEM []byte

	once sync.Once
	skip string
	name string
	db   *sql.DB
}

// Postgres is a PostgreSQL server whose host connections use md5 in
// pg_hba.conf, so a role with a SCRAM password logs in with SCRAM and one
// with an md5 password with md5. Database and admin user are "scrim".
func Postgres() *Server { return &Server{Kind: "postgres"} }

// MySQL is a MySQL server with database "scrim".
func MySQL() *Server { return &Server{Kind: "mysql"} }

// MariaDB is a MariaDB server with database "scrim".
func MariaDB() *Server { return &Server{Kind: "mariadb"} }

// Start starts the server on first use and skips t (or fails it under
// SCRIM_TEST_PODMAN=1) when it cannot.
func (s *Server) Start(t testing.TB) {
	t.Helper()
	s.once.Do(s.setup)
	if s.Addr == "" {
		if os.Getenv("SCRIM_TEST_PODMAN") == "1" {
			t.Fatal(s.Kind + " unavailable but SCRIM_TEST_PODMAN=1 requires it: " + s.skip)
		}
		t.Skip(s.Kind + " unavailable: " + s.skip)
	}
}

// CertPool returns a pool holding CAPEM.
func (s *Server) CertPool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AppendCertsFromPEM(s.CAPEM)
	return p
}

// Exec runs statements as the administrator, failing t on an error.
func (s *Server) Exec(t testing.TB, stmts ...string) {
	t.Helper()
	for _, q := range stmts {
		if _, err := s.db.Exec(q); err != nil {
			t.Fatalf("%s: %q: %v", s.Kind, q, err)
		}
	}
}

// QueryString returns the first column of the first row of q, run as the
// administrator.
func (s *Server) QueryString(t testing.TB, q string, args ...any) string {
	t.Helper()
	var v sql.NullString
	if err := s.db.QueryRow(q, args...).Scan(&v); err != nil {
		t.Fatalf("%s: %q: %v", s.Kind, q, err)
	}
	return v.String
}

// Stop removes the container, if one was started.
func (s *Server) Stop() {
	if s.db != nil {
		_ = s.db.Close()
	}
	if s.name != "" {
		_ = exec.Command("podman", "rm", "-f", "-v", s.name).Run()
	}
}

// The driver logs failed pings while a server starts; tests read errors.
func init() { _ = mysql.SetLogger(log.New(io.Discard, "", 0)) }

func (s *Server) setup() {
	if os.Getenv("SCRIM_TEST_PODMAN") == "0" {
		s.skip = "SCRIM_TEST_PODMAN=0"
		return
	}
	if _, err := exec.LookPath("podman"); err != nil {
		s.skip = "podman not found"
		return
	}
	caPEM, certPEM, keyPEM, err := issue()
	if err != nil {
		s.skip = "generating certificates: " + err.Error()
		return
	}
	s.CAPEM = caPEM
	s.Admin = podtest.RandHex(12)
	s.name = podtest.Prefix() + "-" + s.Kind + "-" + podtest.RandHex(4)
	var image, port, script string
	env := []string{"-e", "TLS_CA=" + string(caPEM), "-e", "TLS_CERT=" + string(certPEM), "-e", "TLS_KEY=" + string(keyPEM)}
	write := `mkdir -p /tls && printf '%s' "$TLS_CA" > /tls/ca.pem && printf '%s' "$TLS_CERT" > /tls/server.crt && printf '%s' "$TLS_KEY" > /tls/server.key && `
	switch s.Kind {
	case "postgres":
		image, port = envOr("SCRIM_TEST_POSTGRES_IMAGE", PostgresImage), "5432"
		env = append(env, "-e", "POSTGRES_USER=scrim", "-e", "POSTGRES_DB=scrim", "-e", "POSTGRES_PASSWORD="+s.Admin,
			"-e", "POSTGRES_HOST_AUTH_METHOD=md5")
		script = write + `chown -R postgres:postgres /tls && chmod 600 /tls/server.key && ` +
			`exec docker-entrypoint.sh postgres -c ssl=on -c ssl_cert_file=/tls/server.crt -c ssl_key_file=/tls/server.key ` +
			`-c fsync=off -c synchronous_commit=off -c full_page_writes=off`
	case "mysql":
		image, port = envOr("SCRIM_TEST_MYSQL_IMAGE", MySQLImage), "3306"
		env = append(env, "-e", "MYSQL_ROOT_PASSWORD="+s.Admin, "-e", "MYSQL_DATABASE=scrim")
		// Under /etc/mysql: a host AppArmor profile for /usr/sbin/mysqld
		// (Ubuntu runners have one) confines the container's mysqld too and
		// lets it read only there.
		script = strings.ReplaceAll(write, "/tls", "/etc/mysql/tls") + `chown -R mysql:mysql /etc/mysql/tls && chmod 600 /etc/mysql/tls/server.key && ` +
			`exec docker-entrypoint.sh mysqld --ssl-ca=/etc/mysql/tls/ca.pem --ssl-cert=/etc/mysql/tls/server.crt --ssl-key=/etc/mysql/tls/server.key ` +
			`--innodb-buffer-pool-size=64M --performance-schema=ON --skip-log-bin --host-cache-size=0 --max-connect-errors=1000000`
	case "mariadb":
		image, port = envOr("SCRIM_TEST_MARIADB_IMAGE", MariaDBImage), "3306"
		env = append(env, "-e", "MARIADB_ROOT_PASSWORD="+s.Admin, "-e", "MARIADB_DATABASE=scrim")
		script = write + `chown -R mysql:mysql /tls && chmod 600 /tls/server.key && ` +
			`exec docker-entrypoint.sh mariadbd --ssl-ca=/tls/ca.pem --ssl-cert=/tls/server.crt --ssl-key=/tls/server.key ` +
			`--innodb-buffer-pool-size=64M --host-cache-size=0 --max-connect-errors=1000000`
	default:
		s.skip = "unknown kind " + s.Kind
		return
	}
	args := []string{"run", "-d", "--rm", "--name", s.name, "--memory", "1g", "--memory-swap", "1g",
		"-p", "127.0.0.1::" + port, "--entrypoint", "sh"}
	args = append(args, env...)
	args = append(args, image, "-c", script)
	if out, err := exec.Command("podman", args...).CombinedOutput(); err != nil {
		s.skip = fmt.Sprintf("podman run %s failed: %v: %s", image, err, strings.TrimSpace(string(out)))
		s.name = ""
		return
	}
	hp, err := exec.Command("podman", "port", s.name, port+"/tcp").Output()
	if err != nil {
		s.Stop()
		s.skip = fmt.Sprintf("podman port %s: %v", s.name, err)
		return
	}
	addr := strings.TrimSpace(strings.Split(string(hp), "\n")[0])
	if err := s.connect(addr); err != nil {
		logs, _ := exec.Command("podman", "logs", "--tail", "30", s.name).CombinedOutput()
		s.Stop()
		s.skip = fmt.Sprintf("%s in %s never became ready: %v\n%s", s.Kind, s.name, err, bytes.TrimSpace(logs))
		return
	}
	s.Addr = addr
}

// connect waits for the server. MySQL's entrypoint runs a temporary server
// first, and the readiness attempts count as connection errors, so the
// servers run with the host cache off (otherwise they block the host). The
// temporary server answers without TLS while it loads its initial data,
// which takes minutes on a small CI runner.
func (s *Server) connect(addr string) error {
	var (
		db  *sql.DB
		err error
	)
	host, port, _ := net.SplitHostPort(addr)
	switch s.Kind {
	case "postgres":
		db, err = sql.Open("pgx", fmt.Sprintf("host=%s port=%s user=scrim dbname=scrim password=%s sslmode=require", host, port, s.Admin))
	default:
		name := "dbtest-" + s.name
		if err := mysql.RegisterTLSConfig(name, &tls.Config{RootCAs: s.CertPool(), ServerName: "localhost", MinVersion: tls.VersionTLS12}); err != nil {
			return err
		}
		cfg := mysql.NewConfig()
		cfg.User, cfg.Passwd, cfg.Net, cfg.Addr, cfg.DBName, cfg.TLSConfig = "root", s.Admin, "tcp", addr, "scrim", name
		cfg.MultiStatements = true
		c, cerr := mysql.NewConnector(cfg)
		if cerr != nil {
			return cerr
		}
		db = sql.OpenDB(c)
	}
	if err != nil {
		return err
	}
	deadline := time.Now().Add(300 * time.Second)
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		err = db.PingContext(ctx)
		cancel()
		if err == nil {
			s.db = db
			return nil
		}
		if time.Now().After(deadline) {
			_ = db.Close()
			return err
		}
		time.Sleep(500 * time.Millisecond)
	}
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// issue makes a CA and a server certificate for localhost and 127.0.0.1.
func issue() (caPEM, certPEM, keyPEM []byte, err error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}
	now := time.Now()
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "dbtest CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}
	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "localhost"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, caKey)
	if err != nil {
		return nil, nil, nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), nil
}
