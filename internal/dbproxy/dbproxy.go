// SPDX-License-Identifier: AGPL-3.0-only

// Package dbproxy holds scrim's database auth proxies and the read-only
// database tool (specs/credential-injection "Database auth proxies" and
// "Read-only database tool", design D5).
//
// A [Proxy] serves one configured database on any listener: a Unix socket,
// a loopback TCP port, or a connection an edge forwarder hands it
// ([Proxy.ServeConn]). It accepts the agent's connection without a
// password, asks its [Authorizer] whether this caller may use the database,
// then logs in to the real server itself with the credential from the store
// (SCRAM-SHA-256, MD5 or, over TLS only, a cleartext password for
// PostgreSQL; caching_sha2_password or mysql_native_password for MySQL),
// over TLS with certificate and host name verification unless the database
// is configured as insecure-plaintext. Only then is the protocol relayed.
// The password never crosses the agent's side of the proxy: the agent's
// handshake is answered by scrim, and every message the server sends back is
// checked for the password's bytes, which close the connection instead of
// reaching the agent.
//
// The read-only database tool ([Querier]) runs one statement through the
// same proxy machinery over an in-memory connection: placeholders inside
// string literals become bound parameters carrying the real values, the
// statement runs in a read-only transaction with a statement timeout and a
// row limit, and anything that is not a single read is refused before it
// is sent.
package dbproxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/heliopsy/scrim/internal/secret"
)

// Kind is the database protocol.
type Kind string

// Supported kinds.
const (
	Postgres Kind = "postgres"
	MySQL    Kind = "mysql"
)

// TLS modes toward the real database.
const (
	// TLSVerifyFull requires TLS and verifies the server certificate and
	// host name. The default.
	TLSVerifyFull = "verify-full"
	// TLSInsecurePlaintext connects without TLS. The login still never
	// sends the password in clear (SCRAM, MD5, scrambles), but the session
	// and the server's identity are unprotected.
	TLSInsecurePlaintext = "insecure-plaintext"
)

// Database is one configured database. It holds no value: the password is
// fetched per connection through Password.
type Database struct {
	// Name is the configuration name (databases.<name>).
	Name string
	Kind Kind
	// Address is host:port of the real server.
	Address string
	// User is the user scrim logs in as.
	User string
	// DBName, when set, is the only database the agent gets; otherwise the
	// database the agent's client asks for is used.
	DBName string
	// TLS is the mode, TLSVerifyFull or TLSInsecurePlaintext.
	TLS string
	// TLSConfig verifies the server; it is cloned per connection. Nil with
	// TLSVerifyFull uses the system roots and Address's host name.
	TLSConfig *tls.Config
	// Password returns the credential. The caller wipes it.
	Password func(ctx context.Context) (secret.Value, error)
	// ConnectTimeout bounds dialling and logging in upstream; zero takes 15s.
	ConnectTimeout time.Duration
}

// Host is the host part of Address, what host bindings and policy match.
func (d *Database) Host() string {
	h, _, err := net.SplitHostPort(d.Address)
	if err != nil {
		return d.Address
	}
	return h
}

func (d *Database) timeout() time.Duration {
	if d.ConnectTimeout > 0 {
		return d.ConnectTimeout
	}
	return 15 * time.Second
}

func (d *Database) tlsConfig() *tls.Config {
	var c *tls.Config
	if d.TLSConfig != nil {
		c = d.TLSConfig.Clone()
	} else {
		c = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	if c.ServerName == "" {
		c.ServerName = d.Host()
	}
	return c
}

func (d *Database) useTLS() bool { return d.TLS != TLSInsecurePlaintext }

// Caller is who a connection belongs to, as the authorizer established it.
// It is metadata for logs.
type Caller struct {
	// Agent is the agent's principal, empty for an unknown caller.
	Agent string
}

// RefusedError is a refusal the agent may read: fixed text, names and
// references only.
type RefusedError struct{ Reason string }

func (e *RefusedError) Error() string { return e.Reason }

// Refused returns a *RefusedError.
func Refused(format string, args ...any) error {
	return &RefusedError{Reason: fmt.Sprintf(format, args...)}
}

// Authorizer decides whether the client on conn may use db. conn is the
// agent's connection, for peer credentials. A *RefusedError's reason is
// sent to the client; any other error is reported as a generic refusal.
type Authorizer func(ctx context.Context, db *Database, conn net.Conn) (Caller, error)

// Proxy serves one database.
type Proxy struct {
	DB        *Database
	Authorize Authorizer
	Log       *slog.Logger

	mu    sync.Mutex
	conns map[net.Conn]struct{}
}

func (p *Proxy) log() *slog.Logger {
	if p.Log == nil {
		return slog.New(slog.DiscardHandler)
	}
	return p.Log
}

// Serve accepts connections on ln until it is closed or ctx ends, and
// closes every connection it accepted before returning.
func (p *Proxy) Serve(ctx context.Context, ln net.Listener) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	var wg sync.WaitGroup
	defer func() {
		p.closeAll()
		wg.Wait()
	}()
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				time.Sleep(50 * time.Millisecond)
				continue
			}
			return err
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			p.ServeConn(ctx, c)
		}()
	}
}

func (p *Proxy) track(c net.Conn, on bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.conns == nil {
		p.conns = map[net.Conn]struct{}{}
	}
	if on {
		p.conns[c] = struct{}{}
	} else {
		delete(p.conns, c)
	}
}

func (p *Proxy) closeAll() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for c := range p.conns {
		_ = c.Close()
	}
}

// ServeConn serves one client connection and closes it. An edge forwarder
// or any other listener hands connections in here.
func (p *Proxy) ServeConn(ctx context.Context, c net.Conn) {
	p.serve(ctx, c, nil)
}

func (p *Proxy) serve(ctx context.Context, c net.Conn, preset *Caller) {
	p.track(c, true)
	defer func() {
		p.track(c, false)
		_ = c.Close()
	}()
	var err error
	switch p.DB.Kind {
	case Postgres:
		err = p.servePostgres(ctx, c, preset)
	case MySQL:
		err = p.serveMySQL(ctx, c, preset)
	default:
		err = fmt.Errorf("unknown database kind %q", p.DB.Kind)
	}
	if err != nil && !isClosed(err) {
		p.log().Info("database session ended", "database", p.DB.Name, "error", err)
	}
}

// pipe returns the client end of an in-memory connection served as caller,
// without asking the authorizer again: the read-only tool authorized it.
func (p *Proxy) pipe(ctx context.Context, caller Caller) net.Conn {
	client, server := net.Pipe()
	// The dial context ends when the driver's connect returns; the session
	// lives until the driver closes its end.
	go p.serve(context.WithoutCancel(ctx), server, &caller)
	return client
}

// authorize runs the authorizer, or takes the preset caller.
func (p *Proxy) authorize(ctx context.Context, c net.Conn, preset *Caller) (Caller, error) {
	if preset != nil {
		return *preset, nil
	}
	if p.Authorize == nil {
		return Caller{}, Refused("database %s: no authorizer configured", p.DB.Name)
	}
	caller, err := p.Authorize(ctx, p.DB, c)
	if err != nil {
		var re *RefusedError
		if errors.As(err, &re) {
			return Caller{}, re
		}
		p.log().Warn("database authorization failed", "database", p.DB.Name, "error", err)
		return Caller{}, Refused("database %s: the connection could not be authorized", p.DB.Name)
	}
	return caller, nil
}

// publicMessage is what the client reads about err: a refusal's reason, or a
// fixed text.
func publicMessage(db *Database, err error) string {
	var re *RefusedError
	if errors.As(err, &re) {
		return "scrim: " + re.Reason
	}
	var ue *upstreamError
	if errors.As(err, &ue) {
		return "scrim: database " + db.Name + ": " + ue.public()
	}
	return "scrim: database " + db.Name + ": the connection to the server failed"
}

// upstreamError is a login failure the server reported. Its message is the
// server's text, already checked against the password.
type upstreamError struct {
	code string
	msg  string
}

func (e *upstreamError) Error() string { return "server refused the login: " + e.code + " " + e.msg }

func (e *upstreamError) public() string {
	if e.msg == "" {
		return "the server refused scrim's login (" + e.code + ")"
	}
	return "the server refused scrim's login: " + e.msg
}

// guard holds the password for the life of a connection and reports
// whether a server message carries it.
type guard struct{ pw secret.Value }

// contains reports whether b holds the password. An empty password guards
// nothing.
func (g guard) contains(b []byte) bool {
	found := false
	_ = g.pw.Expose(func(pw []byte) error {
		found = len(pw) > 0 && bytes.Contains(b, pw)
		return nil
	})
	return found
}

// sanitize returns s, or a fixed text when s holds the password.
func (g guard) sanitize(s string) string {
	if g.contains([]byte(s)) {
		return "(message withheld)"
	}
	return s
}

// errLeak closes a connection whose server sent the password.
var errLeak = errors.New("the server sent the database password; the connection was closed")

// leakNotice is what the client is told before such a connection closes.
const leakNotice = "scrim: the server sent the database password; the session was closed"

func isClosed(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, net.ErrClosed) || errors.Is(err, context.Canceled) {
		return true
	}
	s := err.Error()
	return strings.Contains(s, "EOF") || strings.Contains(s, "use of closed") ||
		strings.Contains(s, "broken pipe") || strings.Contains(s, "connection reset")
}

// relay copies both directions until either side ends, then closes both.
// up→client goes through fromServer, which checks every message.
func relay(client, server net.Conn, toServer, fromServer func() error) error {
	errc := make(chan error, 2)
	go func() { errc <- toServer() }()
	go func() { errc <- fromServer() }()
	err := <-errc
	_ = client.Close()
	_ = server.Close()
	if second := <-errc; err == nil {
		err = second
	}
	return err
}

// deadline sets a handshake deadline on c from ctx and d, and returns a
// function clearing it.
func deadline(ctx context.Context, c net.Conn, d time.Duration) func() {
	t := time.Now().Add(d)
	if dl, ok := ctx.Deadline(); ok && dl.Before(t) {
		t = dl
	}
	_ = c.SetDeadline(t)
	stop := context.AfterFunc(ctx, func() { _ = c.SetDeadline(time.Unix(1, 0)) })
	return func() {
		stop()
		_ = c.SetDeadline(time.Time{})
	}
}

func dial(ctx context.Context, db *Database) (net.Conn, error) {
	d := net.Dialer{Timeout: db.timeout(), KeepAlive: 30 * time.Second}
	c, err := d.DialContext(ctx, "tcp", db.Address)
	if err != nil {
		return nil, fmt.Errorf("connecting to %s: %w", db.Address, err)
	}
	return c, nil
}
