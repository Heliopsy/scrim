// SPDX-License-Identifier: AGPL-3.0-only

package dbproxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/secret"
)

// CollectionKey is the configuration collection of databases.
const CollectionKey = "databases"

var fields = []string{"kind", "address", "user", "password", "database", "listen", "listen-permissions",
	"tls", "tls-ca", "tls-server-name", "connect-timeout", "tool", "query-timeout", "query-max-rows"}

// Databases is the `databases` collection.
var Databases = config.RegisterCollection(config.CollectionSpec{
	Key: CollectionKey,
	Description: "Databases the auth proxies and the read-only database tool reach, by name: `kind` (postgres or mysql), " +
		"`address` (host:port of the server), `user` and `password` (a reference) scrim logs in with, optional `database` " +
		"(the only database the agent gets; default the one its client asks for), `listen` (unix:/path or host:port; default a " +
		"Unix socket under $XDG_RUNTIME_DIR/scrim/db/<name>), `listen-permissions` (octal, default 0600), `tls` (verify-full, " +
		"the default, or insecure-plaintext, which weakens the protection of the session and the server's identity), `tls-ca` " +
		"(PEM file; default the system roots), `tls-server-name`, `connect-timeout`, `tool` (false turns the read-only " +
		"database tool off for this database), `query-timeout` (default 10s) and `query-max-rows` (default 1000).",
	SecretFields:     []string{"password"},
	RequireReference: false,
	RequiredFields:   []string{"kind", "address", "user", "password"},
	RestartRequired:  true,
	Validate: func(inst config.Instance) error {
		_, err := specOf(inst, nil)
		return err
	},
})

// Spec is one configured database with its listener and tool settings.
type Spec struct {
	DB *Database
	// Listen is the address the proxy listens on: "unix:/path" or
	// "host:port".
	Listen string
	// ListenMode is the Unix socket's permission bits.
	ListenMode os.FileMode
	// Tool says whether the read-only database tool serves this database.
	Tool bool
	// Limits bound the tool's queries.
	Limits Limits
	// PasswordKey is the configuration key of the password, for
	// Config.SecretAt.
	PasswordKey string
	// PasswordRef is the configured reference, for policy and audit (a
	// store reference names the secret; other forms name no secret).
	PasswordRef config.SecretRef
}

// DefaultSocketDir is where the default Unix sockets go:
// $XDG_RUNTIME_DIR/scrim/db/<name>, or a per-user directory under the
// temporary directory.
func DefaultSocketDir(name string) string {
	if dir := os.Getenv("XDG_RUNTIME_DIR"); dir != "" {
		return filepath.Join(dir, "scrim", "db", name)
	}
	return filepath.Join(os.TempDir(), "scrim-"+strconv.Itoa(os.Getuid()), "db", name)
}

// DefaultListen is the default listener of a database: a Unix socket named
// the way its clients look for one (psql -h <dir>; mysql --socket <path>).
func DefaultListen(name string, kind Kind) string {
	if kind == MySQL {
		return "unix:" + filepath.Join(DefaultSocketDir(name), "mysql.sock")
	}
	return "unix:" + filepath.Join(DefaultSocketDir(name), ".s.PGSQL.5432")
}

// Specs reads every configured database. Each Database's Password reads the
// current configuration through current, so a reload's new password is used
// for the next login.
func Specs(cfg *config.Config, current func() *config.Config) ([]Spec, error) {
	var out []Spec
	for _, inst := range Databases.Get(cfg) {
		s, err := specOf(inst, current)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, nil
}

func specOf(inst config.Instance, current func() *config.Config) (Spec, error) {
	where := func(f string) string { return inst.Key(CollectionKey, f) }
	for k := range inst.Fields {
		if !slices.Contains(fields, k) {
			return Spec{}, fmt.Errorf("%s.%s: unknown field %s", CollectionKey, inst.Name, k)
		}
	}
	db := &Database{Name: inst.Name, Kind: Kind(inst.String("kind")), Address: inst.String("address"), User: inst.String("user"),
		DBName: inst.String("database"), TLS: inst.String("tls")}
	if db.Kind != Postgres && db.Kind != MySQL {
		return Spec{}, fmt.Errorf("%s: must be postgres or mysql", where("kind"))
	}
	if h, p, err := net.SplitHostPort(db.Address); err != nil || h == "" || p == "" {
		return Spec{}, fmt.Errorf("%s: must be host:port", where("address"))
	}
	if db.User == "" {
		return Spec{}, fmt.Errorf("%s: must name the user scrim logs in as", where("user"))
	}
	switch db.TLS {
	case "":
		db.TLS = TLSVerifyFull
	case TLSVerifyFull, TLSInsecurePlaintext:
	default:
		return Spec{}, fmt.Errorf("%s: must be %s or %s", where("tls"), TLSVerifyFull, TLSInsecurePlaintext)
	}
	if db.TLS == TLSVerifyFull {
		tc := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: inst.String("tls-server-name")}
		if ca := inst.String("tls-ca"); ca != "" {
			pem, err := os.ReadFile(ca) // #nosec G304 -- an operator-configured path
			if err != nil {
				return Spec{}, fmt.Errorf("%s: %w", where("tls-ca"), err)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(pem) {
				return Spec{}, fmt.Errorf("%s: %s holds no PEM certificate", where("tls-ca"), ca)
			}
			tc.RootCAs = pool
		}
		db.TLSConfig = tc
	}
	var err error
	if db.ConnectTimeout, err = duration(inst, "connect-timeout", 15*time.Second); err != nil {
		return Spec{}, fmt.Errorf("%s: %w", where("connect-timeout"), err)
	}
	s := Spec{DB: db, Listen: inst.String("listen"), ListenMode: 0o600, Tool: true, PasswordKey: where("password")}
	s.PasswordRef = config.SecretRef(inst.String("password"))
	if s.Listen == "" {
		s.Listen = DefaultListen(inst.Name, db.Kind)
	} else if err := validListen(s.Listen); err != nil {
		return Spec{}, fmt.Errorf("%s: %w", where("listen"), err)
	}
	if v, ok := inst.Field("listen-permissions"); ok {
		m, err := strconv.ParseUint(fmt.Sprint(v), 8, 32)
		if err != nil || m > 0o777 {
			return Spec{}, fmt.Errorf("%s: must be octal permission bits such as 0600", where("listen-permissions"))
		}
		s.ListenMode = os.FileMode(m)
	}
	if v, ok := inst.Field("tool"); ok {
		b, err := strconv.ParseBool(fmt.Sprint(v))
		if err != nil {
			return Spec{}, fmt.Errorf("%s: must be true or false", where("tool"))
		}
		s.Tool = b
	}
	if s.Limits.Timeout, err = duration(inst, "query-timeout", 10*time.Second); err != nil {
		return Spec{}, fmt.Errorf("%s: %w", where("query-timeout"), err)
	}
	s.Limits.MaxRows = 1000
	if v, ok := inst.Field("query-max-rows"); ok {
		n, err := strconv.Atoi(fmt.Sprint(v))
		if err != nil || n < 1 || n > 100000 {
			return Spec{}, fmt.Errorf("%s: must be 1 to 100000", where("query-max-rows"))
		}
		s.Limits.MaxRows = n
	}
	s.Limits.MaxBytes = 1 << 20
	key := s.PasswordKey
	db.Password = func(context.Context) (secret.Value, error) { return currentPassword(current, key) }
	return s, nil
}

// currentPassword copies the resolved password out of the current
// configuration; the caller wipes the copy, never the configuration's value.
func currentPassword(current func() *config.Config, key string) (secret.Value, error) {
	if current == nil {
		return secret.Value{}, errors.New("no configuration")
	}
	cfg := current()
	if cfg == nil {
		return secret.Value{}, errors.New("no configuration")
	}
	v, ok := cfg.SecretAt(key)
	if !ok || v.IsZero() {
		return secret.Value{}, fmt.Errorf("%s is not resolved", key)
	}
	var out secret.Value
	err := v.Expose(func(b []byte) error { out = secret.New(b); return nil })
	return out, err
}

func duration(inst config.Instance, f string, def time.Duration) (time.Duration, error) {
	v, ok := inst.Field(f)
	if !ok {
		return def, nil
	}
	d, err := time.ParseDuration(fmt.Sprint(v))
	if err != nil || d <= 0 {
		return 0, errors.New("must be a positive duration such as 10s")
	}
	return d, nil
}

func validListen(s string) error {
	if p, ok := strings.CutPrefix(s, "unix:"); ok {
		if !filepath.IsAbs(p) {
			return errors.New("a Unix socket path must be absolute")
		}
		return nil
	}
	h, p, err := net.SplitHostPort(s)
	if err != nil || p == "" {
		return errors.New("must be unix:/path or host:port")
	}
	if ip := net.ParseIP(h); h != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return errors.New("a TCP listener must be on a loopback address; agents elsewhere reach it through the edge forwarder")
	}
	return nil
}
