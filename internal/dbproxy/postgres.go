// SPDX-License-Identifier: AGPL-3.0-only

package dbproxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5/pgproto3"

	"github.com/heliopsy/scrim/internal/secret"
)

// maxPGMessage bounds one server message the proxy buffers to check it.
const maxPGMessage = 256 << 20

// PostgreSQL authentication request codes.
const (
	pgAuthOK           = 0
	pgAuthCleartext    = 3
	pgAuthMD5          = 5
	pgAuthSASL         = 10
	pgAuthSASLContinue = 11
	pgAuthSASLFinal    = 12
)

// servePostgres answers the client's startup itself, logs in upstream and
// relays. The client never gets an authentication request: scrim replies
// AuthenticationOk once its own login succeeded.
func (p *Proxy) servePostgres(ctx context.Context, c net.Conn, preset *Caller) error {
	clear := deadline(ctx, c, 2*p.DB.timeout())
	defer clear()
	be := pgproto3.NewBackend(c, c)
	var (
		params  map[string]string
		version uint32
	)
	for params == nil {
		msg, err := be.ReceiveStartupMessage()
		if err != nil {
			return err
		}
		switch m := msg.(type) {
		case *pgproto3.SSLRequest, *pgproto3.GSSEncRequest:
			// The agent's side is local; encryption is between scrim and
			// the server.
			if _, err := c.Write([]byte{'N'}); err != nil {
				return err
			}
		case *pgproto3.CancelRequest:
			return nil
		case *pgproto3.StartupMessage:
			params, version = maps.Clone(m.Parameters), m.ProtocolVersion
			if params == nil {
				params = map[string]string{}
			}
		}
	}
	fail := func(code string, err error) error {
		be.Send(&pgproto3.ErrorResponse{Severity: "FATAL", SeverityUnlocalized: "FATAL", Code: code, Message: publicMessage(p.DB, err)})
		_ = be.Flush()
		return err
	}
	caller, err := p.authorize(ctx, c, preset)
	if err != nil {
		return fail("28000", err)
	}
	pw, err := p.DB.Password(ctx)
	if err != nil {
		p.log().Warn("database credential unavailable", "database", p.DB.Name, "error", err)
		return fail("08006", Refused("database %s: the credential is not available", p.DB.Name))
	}
	defer pw.Wipe()
	g := guard{pw: pw}
	up, err := p.loginPostgres(ctx, params, g)
	if err != nil {
		code := "08006"
		var ue *upstreamError
		if errors.As(err, &ue) {
			code = ue.code
		}
		return fail(code, err)
	}
	defer func() { _ = up.conn.Close() }()

	var unknown []string
	for k := range params {
		if strings.HasPrefix(k, "_pq_.") {
			unknown = append(unknown, k)
		}
	}
	if version != pgproto3.ProtocolVersion30 || len(unknown) > 0 {
		slices.Sort(unknown)
		be.Send(&pgproto3.NegotiateProtocolVersion{NewestMinorProtocol: 0, UnrecognizedOptions: unknown})
	}
	be.Send(&pgproto3.AuthenticationOk{})
	for _, k := range slices.Sorted(maps.Keys(up.params)) {
		be.Send(&pgproto3.ParameterStatus{Name: k, Value: g.sanitize(up.params[k])})
	}
	if up.key != nil {
		be.Send(&pgproto3.BackendKeyData{ProcessID: up.pid, SecretKey: up.key})
	}
	be.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
	if err := be.Flush(); err != nil {
		return err
	}
	clear()
	p.log().Debug("database session opened", "database", p.DB.Name, "agent", caller.Agent)
	return relay(c, up.conn,
		func() error { _, err := io.Copy(up.conn, c); return err },
		func() error { return pgFromServer(up.r, c, g) })
}

type pgUpstream struct {
	conn   net.Conn
	r      *bufio.Reader
	params map[string]string
	pid    uint32
	key    []byte
}

// loginPostgres connects to the server, over TLS unless the database is
// insecure-plaintext, and logs in as the configured user.
func (p *Proxy) loginPostgres(ctx context.Context, clientParams map[string]string, g guard) (_ *pgUpstream, err error) {
	db := p.DB
	conn, err := dial(ctx, db)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			_ = conn.Close()
		}
	}()
	clear := deadline(ctx, conn, db.timeout())
	defer clear()
	isTLS := false
	if db.useTLS() {
		var req [8]byte
		binary.BigEndian.PutUint32(req[0:4], 8)
		binary.BigEndian.PutUint32(req[4:8], 80877103)
		if _, err := conn.Write(req[:]); err != nil {
			return nil, err
		}
		var resp [1]byte
		if _, err := io.ReadFull(conn, resp[:]); err != nil {
			return nil, err
		}
		if resp[0] != 'S' {
			return nil, Refused("database %s: the server does not offer TLS (set tls: insecure-plaintext to connect without it)", db.Name)
		}
		tc := tls.Client(conn, db.tlsConfig())
		if err := tc.HandshakeContext(ctx); err != nil {
			return nil, Refused("database %s: TLS handshake with the server failed: %s", db.Name, tlsReason(err))
		}
		conn, isTLS = tc, true
	}
	up := &pgUpstream{conn: conn, r: bufio.NewReaderSize(conn, 32<<10), params: map[string]string{}}

	sp := map[string]string{}
	for k, v := range clientParams {
		if k == "user" || k == "database" || strings.HasPrefix(k, "_pq_.") {
			continue
		}
		sp[k] = v
	}
	sp["user"] = db.User
	switch {
	case db.DBName != "":
		sp["database"] = db.DBName
	case clientParams["database"] != "":
		sp["database"] = clientParams["database"]
	}
	if err := pgSend(conn, &pgproto3.StartupMessage{ProtocolVersion: pgproto3.ProtocolVersion30, Parameters: sp}); err != nil {
		return nil, err
	}

	var scram *scramClient
	scramDone := false
auth:
	for {
		t, body, err := pgRead(up.r, 1<<20)
		if err != nil {
			return nil, err
		}
		switch t {
		case 'E':
			return nil, pgError(body, g)
		case 'v':
			continue
		case 'R':
		default:
			return nil, fmt.Errorf("unexpected message %q during login", t)
		}
		if len(body) < 4 {
			return nil, errors.New("short authentication request")
		}
		switch code := binary.BigEndian.Uint32(body); code {
		case pgAuthOK:
			if scram != nil && !scramDone {
				return nil, errors.New("the server ended SCRAM without proving it knows the password")
			}
			break auth
		case pgAuthCleartext:
			if !isTLS {
				return nil, Refused("database %s: the server asks for a cleartext password, which scrim sends only over TLS", db.Name)
			}
			if err := pgPassword(conn, g.pw); err != nil {
				return nil, err
			}
		case pgAuthMD5:
			if len(body) < 8 {
				return nil, errors.New("short md5 request")
			}
			resp := pgMD5(g.pw, db.User, body[4:8])
			err := pgPasswordBytes(conn, resp)
			secret.WipeBytes(resp)
			if err != nil {
				return nil, err
			}
		case pgAuthSASL:
			mechs := strings.Split(strings.TrimRight(string(body[4:]), "\x00"), "\x00")
			if !slices.Contains(mechs, "SCRAM-SHA-256") {
				return nil, Refused("database %s: the server offers no SASL mechanism scrim supports (%s)", db.Name, strings.Join(mechs, ", "))
			}
			if scram, err = newScramClient(); err != nil {
				return nil, err
			}
			if err := pgSend(conn, &pgproto3.SASLInitialResponse{AuthMechanism: "SCRAM-SHA-256", Data: scram.first()}); err != nil {
				return nil, err
			}
		case pgAuthSASLContinue:
			if scram == nil {
				return nil, errors.New("SASL continue without SASL")
			}
			final, err := scram.final(g.pw, body[4:])
			if err != nil {
				return nil, err
			}
			if err := pgSend(conn, &pgproto3.SASLResponse{Data: final}); err != nil {
				return nil, err
			}
		case pgAuthSASLFinal:
			if scram == nil {
				return nil, errors.New("SASL final without SASL")
			}
			if err := scram.verify(body[4:]); err != nil {
				return nil, err
			}
			scramDone = true
		default:
			return nil, Refused("database %s: the server asks for an authentication method scrim does not support (code %d)", db.Name, code)
		}
	}
	for {
		t, body, err := pgRead(up.r, 1<<20)
		if err != nil {
			return nil, err
		}
		switch t {
		case 'S':
			var m pgproto3.ParameterStatus
			if err := m.Decode(body); err != nil {
				return nil, err
			}
			up.params[m.Name] = m.Value
		case 'K':
			var m pgproto3.BackendKeyData
			if err := m.Decode(body); err != nil {
				return nil, err
			}
			up.pid, up.key = m.ProcessID, slices.Clone(m.SecretKey)
		case 'E':
			return nil, pgError(body, g)
		case 'Z':
			return up, nil
		case 'N':
		default:
			return nil, fmt.Errorf("unexpected message %q after login", t)
		}
	}
}

func tlsReason(err error) string {
	var he x509.HostnameError
	if errors.As(err, &he) {
		return "the server certificate does not name the host"
	}
	var ce *tls.CertificateVerificationError
	if errors.As(err, &ce) {
		return "the server certificate does not verify"
	}
	return "handshake error"
}

func pgError(body []byte, g guard) error {
	var m pgproto3.ErrorResponse
	if err := m.Decode(body); err != nil {
		return err
	}
	code := m.Code
	if code == "" {
		code = "28000"
	}
	return &upstreamError{code: code, msg: g.sanitize(m.Message)}
}

func pgSend(w io.Writer, m pgproto3.FrontendMessage) error {
	b, err := m.Encode(nil)
	if err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}

// pgPassword sends a PasswordMessage carrying the password, built from its
// bytes so no string copy of it exists.
func pgPassword(w io.Writer, pw secret.Value) error {
	return pw.Expose(func(b []byte) error { return pgPasswordBytes(w, b) })
}

func pgPasswordBytes(w io.Writer, b []byte) error {
	msg := make([]byte, 5+len(b)+1)
	msg[0] = 'p'
	binary.BigEndian.PutUint32(msg[1:5], uint32(4+len(b)+1)) // #nosec G115 -- bounded by the password length
	copy(msg[5:], b)
	_, err := w.Write(msg)
	secret.WipeBytes(msg)
	return err
}

// pgRead reads one backend message: type and body.
func pgRead(r *bufio.Reader, limit int) (byte, []byte, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	n := int(binary.BigEndian.Uint32(hdr[1:])) - 4
	if n < 0 || n > limit {
		return 0, nil, fmt.Errorf("message %q of %d bytes is out of range", hdr[0], n)
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return 0, nil, err
	}
	return hdr[0], body, nil
}

// pgFromServer relays server messages to the client one whole message at a
// time, and stops at a message that carries the password.
func pgFromServer(r *bufio.Reader, c net.Conn, g guard) error {
	w := bufio.NewWriterSize(c, 32<<10)
	var hdr [5]byte
	buf := make([]byte, 0, 8<<10)
	for {
		if _, err := io.ReadFull(r, hdr[:]); err != nil {
			return err
		}
		n := int(binary.BigEndian.Uint32(hdr[1:])) - 4
		if n < 0 || n > maxPGMessage {
			return fmt.Errorf("server message of %d bytes is out of range", n)
		}
		if cap(buf) < n {
			buf = make([]byte, n)
		}
		buf = buf[:n]
		if _, err := io.ReadFull(r, buf); err != nil {
			return err
		}
		if g.contains(buf) {
			secret.WipeBytes(buf)
			w.Reset(c)
			if b, err := (&pgproto3.ErrorResponse{Severity: "FATAL", SeverityUnlocalized: "FATAL", Code: "08006", Message: leakNotice}).Encode(nil); err == nil {
				_, _ = c.Write(b)
			}
			return errLeak
		}
		if _, err := w.Write(hdr[:]); err != nil {
			return err
		}
		if _, err := w.Write(buf); err != nil {
			return err
		}
		if r.Buffered() == 0 {
			if err := w.Flush(); err != nil {
				return err
			}
		}
	}
}
