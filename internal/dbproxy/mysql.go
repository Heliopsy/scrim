// SPDX-License-Identifier: AGPL-3.0-only

package dbproxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"

	"github.com/heliopsy/scrim/internal/secret"
)

// MySQL capability flags (client/server protocol, "Capabilities Flags").
const (
	myLongPassword     = 1 << 0
	myConnectWithDB    = 1 << 3
	myCompress         = 1 << 5
	myProtocol41       = 1 << 9
	mySSL              = 1 << 11
	mySecureConnection = 1 << 15
	myPluginAuth       = 1 << 19
	myConnectAttrs     = 1 << 20
	myPluginAuthLenenc = 1 << 21
	myExpiredPasswords = 1 << 22
	myZstd             = 1 << 26
	myMultiFactor      = 1 << 28
	mySSLVerify        = 1 << 30
	myRememberOptions  = 1 << 31
)

// myHandshakeOnly are capabilities that change only the handshake, never the
// command phase. scrim answers the agent's handshake and makes its own
// upstream, so these are not passed through; compression is not offered at
// all, because the relay checks plain packets.
const myHandshakeOnly = mySSL | myCompress | myZstd | myConnectAttrs | myMultiFactor | myExpiredPasswords | mySSLVerify | myRememberOptions

const (
	myMaxPacket     = 1<<24 - 1
	myComChangeUser = 0x11
	myAgentPlugin   = "caching_sha2_password"
)

// myGreeting is the server's initial handshake (protocol version 10).
type myGreeting struct {
	version string
	connID  uint32
	caps    uint32
	charset byte
	status  uint16
	nonce   []byte
	plugin  string
}

func parseMyGreeting(p []byte) (*myGreeting, error) {
	if len(p) < 1 {
		return nil, errors.New("empty greeting")
	}
	if p[0] == 0xff {
		return nil, myErr(p, guard{})
	}
	if p[0] != 10 {
		return nil, fmt.Errorf("unsupported protocol version %d", p[0])
	}
	r := p[1:]
	i := bytes.IndexByte(r, 0)
	if i < 0 {
		return nil, errors.New("malformed greeting")
	}
	g := &myGreeting{version: string(r[:i])}
	r = r[i+1:]
	if len(r) < 4+8+1+2 {
		return nil, errors.New("short greeting")
	}
	g.connID = binary.LittleEndian.Uint32(r)
	g.nonce = append([]byte(nil), r[4:12]...)
	r = r[13:]
	g.caps = uint32(binary.LittleEndian.Uint16(r))
	r = r[2:]
	if len(r) >= 1+2+2+1+10 {
		g.charset = r[0]
		g.status = binary.LittleEndian.Uint16(r[1:])
		g.caps |= uint32(binary.LittleEndian.Uint16(r[3:])) << 16
		authLen := int(r[5])
		r = r[16:]
		if g.caps&mySecureConnection != 0 {
			n := max(13, authLen-8)
			if n > len(r) {
				n = len(r)
			}
			part := r[:n]
			if len(part) > 0 && part[len(part)-1] == 0 {
				part = part[:len(part)-1]
			}
			g.nonce = append(g.nonce, part...)
			r = r[n:]
		}
		if g.caps&myPluginAuth != 0 {
			if j := bytes.IndexByte(r, 0); j >= 0 {
				g.plugin = string(r[:j])
			} else {
				g.plugin = string(r)
			}
		}
	}
	if g.caps&myProtocol41 == 0 {
		return nil, errors.New("the server does not speak protocol 4.1")
	}
	if g.plugin == "" {
		g.plugin = "mysql_native_password"
	}
	return g, nil
}

// myResponse is the parts of a client's HandshakeResponse41 scrim uses.
type myResponse struct {
	caps      uint32
	maxPacket uint32
	charset   byte
	user      string
	db        string
}

func parseMyResponse(p []byte) (*myResponse, error) {
	if len(p) < 32 {
		return nil, errors.New("short handshake response")
	}
	r := &myResponse{caps: binary.LittleEndian.Uint32(p), maxPacket: binary.LittleEndian.Uint32(p[4:]), charset: p[8]}
	if r.caps&myProtocol41 == 0 {
		return nil, Refused("the client does not speak MySQL protocol 4.1")
	}
	if r.caps&mySSL != 0 && len(p) == 32 {
		return nil, Refused("TLS was not offered on this local endpoint")
	}
	rest := p[32:]
	i := bytes.IndexByte(rest, 0)
	if i < 0 {
		return nil, errors.New("malformed handshake response")
	}
	r.user = string(rest[:i])
	rest = rest[i+1:]
	switch {
	case r.caps&myPluginAuthLenenc != 0:
		n, k := lenenc(rest)
		if k == 0 || uint64(len(rest)-k) < n {
			return nil, errors.New("malformed auth response")
		}
		rest = rest[k+int(n):] // #nosec G115 -- bounded by len(rest) above
	case r.caps&mySecureConnection != 0:
		if len(rest) < 1 || len(rest) < 1+int(rest[0]) {
			return nil, errors.New("malformed auth response")
		}
		rest = rest[1+int(rest[0]):]
	default:
		j := bytes.IndexByte(rest, 0)
		if j < 0 {
			return nil, errors.New("malformed auth response")
		}
		rest = rest[j+1:]
	}
	if r.caps&myConnectWithDB != 0 {
		if j := bytes.IndexByte(rest, 0); j >= 0 {
			r.db = string(rest[:j])
		} else {
			r.db = string(rest)
		}
	}
	return r, nil
}

// lenenc decodes a length-encoded integer, returning the value and how many
// bytes it took (0 when malformed).
func lenenc(b []byte) (uint64, int) {
	if len(b) == 0 {
		return 0, 0
	}
	switch c := b[0]; {
	case c < 0xfb:
		return uint64(c), 1
	case c == 0xfc && len(b) >= 3:
		return uint64(binary.LittleEndian.Uint16(b[1:])), 3
	case c == 0xfd && len(b) >= 4:
		return uint64(b[1]) | uint64(b[2])<<8 | uint64(b[3])<<16, 4
	case c == 0xfe && len(b) >= 9:
		return binary.LittleEndian.Uint64(b[1:]), 9
	}
	return 0, 0
}

func appendLenenc(b []byte, n int) []byte {
	switch {
	case n < 0xfb:
		return append(b, byte(n))
	case n < 1<<16:
		return append(b, 0xfc, byte(n), byte(n>>8))
	case n < 1<<24:
		return append(b, 0xfd, byte(n), byte(n>>8), byte(n>>16))
	}
	return binary.LittleEndian.AppendUint64(append(b, 0xfe), uint64(n)) // #nosec G115 -- n is a positive length
}

// myRead reads one packet: sequence id and payload.
func myRead(r io.Reader) (byte, []byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	n := int(hdr[0]) | int(hdr[1])<<8 | int(hdr[2])<<16
	p := make([]byte, n)
	if _, err := io.ReadFull(r, p); err != nil {
		return 0, nil, err
	}
	return hdr[3], p, nil
}

func myWrite(w io.Writer, seq byte, p []byte) error {
	if len(p) >= myMaxPacket {
		return errors.New("packet too large")
	}
	b := make([]byte, 4, 4+len(p))
	b[0], b[1], b[2], b[3] = byte(len(p)), byte(len(p)>>8), byte(len(p)>>16), seq
	b = append(b, p...)
	_, err := w.Write(b)
	secret.WipeBytes(b)
	return err
}

// myErrPacket is an ERR packet with access-denied's code and SQL state.
func myErrPacket(code uint16, state, msg string) []byte {
	b := []byte{0xff, byte(code), byte(code >> 8), '#'}
	b = append(b, state...)
	return append(b, msg...)
}

func myErr(p []byte, g guard) error {
	e := &upstreamError{code: "HY000"}
	if len(p) >= 3 {
		rest := p[3:]
		if len(rest) >= 6 && rest[0] == '#' {
			e.code, rest = string(rest[1:6]), rest[6:]
		}
		e.msg = g.sanitize(string(rest))
	}
	return e
}

// scramble returns n random printable bytes, as servers generate them.
func scramble(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	for i := range b {
		b[i] = 0x21 + b[i]%0x5e
	}
	return b, nil
}

// serveMySQL reads the server's greeting, offers the agent a handshake of
// its own (the agent's password, if any, is ignored), logs in upstream with
// the agent's command-phase capabilities and relays.
func (p *Proxy) serveMySQL(ctx context.Context, c net.Conn, preset *Caller) error {
	clear := deadline(ctx, c, 2*p.DB.timeout())
	defer clear()
	cr := bufio.NewReaderSize(c, 16<<10)
	fail := func(seq byte, err error) error {
		_ = myWrite(c, seq, myErrPacket(1045, "28000", publicMessage(p.DB, err)))
		return err
	}
	caller, err := p.authorize(ctx, c, preset)
	if err != nil {
		// The client expects a greeting first; an ERR in its place is what
		// a server that refuses the host sends.
		return fail(0, err)
	}
	pw, err := p.DB.Password(ctx)
	if err != nil {
		p.log().Warn("database credential unavailable", "database", p.DB.Name, "error", err)
		return fail(0, Refused("database %s: the credential is not available", p.DB.Name))
	}
	defer pw.Wipe()
	g := guard{pw: pw}

	up, err := dial(ctx, p.DB)
	if err != nil {
		return fail(0, err)
	}
	defer func() { _ = up.Close() }()
	upClear := deadline(ctx, up, p.DB.timeout())
	defer upClear()
	ur := bufio.NewReaderSize(up, 16<<10)
	_, gp, err := myRead(ur)
	if err != nil {
		return fail(0, err)
	}
	greet, err := parseMyGreeting(gp)
	if err != nil {
		return fail(0, err)
	}

	nonce, err := scramble(20)
	if err != nil {
		return err
	}
	offer := greet.caps &^ myHandshakeOnly
	offer |= myPluginAuth | mySecureConnection | myProtocol41
	hs := []byte{10}
	hs = append(hs, greet.version...)
	hs = append(hs, 0)
	hs = binary.LittleEndian.AppendUint32(hs, greet.connID)
	hs = append(hs, nonce[:8]...)
	hs = append(hs, 0)
	hs = binary.LittleEndian.AppendUint16(hs, uint16(offer))
	hs = append(hs, greet.charset)
	hs = binary.LittleEndian.AppendUint16(hs, greet.status)
	hs = binary.LittleEndian.AppendUint16(hs, uint16(offer>>16))
	hs = append(hs, 21)
	hs = append(hs, make([]byte, 10)...)
	hs = append(hs, nonce[8:]...)
	hs = append(hs, 0)
	hs = append(hs, myAgentPlugin...)
	hs = append(hs, 0)
	if err := myWrite(c, 0, hs); err != nil {
		return err
	}
	seq, rp, err := myRead(cr)
	if err != nil {
		return err
	}
	resp, err := parseMyResponse(rp)
	if err != nil {
		return fail(seq+1, err)
	}

	ok, upConn, upR, err := p.loginMySQL(ctx, up, ur, greet, resp, g)
	if err != nil {
		return fail(seq+1, err)
	}
	if err := myWrite(c, seq+1, ok); err != nil {
		return err
	}
	clear()
	upClear()
	p.log().Debug("database session opened", "database", p.DB.Name, "agent", caller.Agent)
	return relay(c, upConn,
		func() error { return myFromClient(cr, upConn, c) },
		func() error { return myFromServer(upR, c, g) })
}

// loginMySQL sends the handshake response upstream, over TLS unless the
// database is insecure-plaintext, and runs the authentication exchange. It
// returns the server's OK payload and the connection the session continues
// on (the TLS connection when there is one).
func (p *Proxy) loginMySQL(ctx context.Context, up net.Conn, ur *bufio.Reader, greet *myGreeting, resp *myResponse, g guard) ([]byte, net.Conn, *bufio.Reader, error) {
	db := p.DB
	caps := resp.caps &^ myHandshakeOnly
	caps |= myProtocol41 | mySecureConnection | myPluginAuth | myLongPassword
	caps &= greet.caps | myLongPassword
	caps |= myProtocol41 | mySecureConnection | myPluginAuth
	if greet.caps&myPluginAuthLenenc != 0 {
		caps |= myPluginAuthLenenc
	}
	dbName := resp.db
	if db.DBName != "" {
		dbName = db.DBName
	}
	if dbName != "" {
		caps |= myConnectWithDB
	} else {
		caps &^= myConnectWithDB
	}
	charset := resp.charset
	if charset == 0 {
		charset = greet.charset
	}
	var seq byte = 1
	var (
		w     io.Writer = up
		r     io.Reader = ur
		conn            = up
		isTLS bool
	)
	if db.useTLS() {
		if greet.caps&mySSL == 0 {
			return nil, nil, nil, Refused("database %s: the server does not offer TLS (set tls: insecure-plaintext to connect without it)", db.Name)
		}
		caps |= mySSL
		req := binary.LittleEndian.AppendUint32(nil, caps)
		req = binary.LittleEndian.AppendUint32(req, resp.maxPacket)
		req = append(req, charset)
		req = append(req, make([]byte, 23)...)
		if err := myWrite(up, seq, req); err != nil {
			return nil, nil, nil, err
		}
		seq++
		tc := tls.Client(&bufferedConn{Conn: up, r: ur}, db.tlsConfig())
		if err := tc.HandshakeContext(ctx); err != nil {
			return nil, nil, nil, Refused("database %s: TLS handshake with the server failed: %s", db.Name, tlsReason(err))
		}
		w, r, conn, isTLS = tc, tc, tc, true
	}
	plugin, nonce := greet.plugin, greet.nonce
	auth, err := myAuth(plugin, nonce, g.pw, isTLS)
	if err != nil {
		return nil, nil, nil, Refused("database %s: %s", db.Name, err.Error())
	}
	hr := binary.LittleEndian.AppendUint32(nil, caps)
	hr = binary.LittleEndian.AppendUint32(hr, resp.maxPacket)
	hr = append(hr, charset)
	hr = append(hr, make([]byte, 23)...)
	hr = append(hr, db.User...)
	hr = append(hr, 0)
	if caps&myPluginAuthLenenc != 0 {
		hr = appendLenenc(hr, len(auth))
	} else {
		hr = append(hr, byte(len(auth)))
	}
	hr = append(hr, auth...)
	secret.WipeBytes(auth)
	if caps&myConnectWithDB != 0 {
		hr = append(hr, dbName...)
		hr = append(hr, 0)
	}
	hr = append(hr, plugin...)
	hr = append(hr, 0)
	err = myWrite(w, seq, hr)
	secret.WipeBytes(hr)
	if err != nil {
		return nil, nil, nil, err
	}
	for range 8 {
		s, pk, err := myRead(r)
		if err != nil {
			return nil, nil, nil, err
		}
		if len(pk) == 0 {
			return nil, nil, nil, errors.New("empty authentication packet")
		}
		switch pk[0] {
		case 0x00:
			if isTLS {
				return pk, conn, bufio.NewReaderSize(conn, 16<<10), nil
			}
			return pk, conn, ur, nil
		case 0xff:
			return nil, nil, nil, myErr(pk, g)
		case 0xfe:
			rest := pk[1:]
			i := bytes.IndexByte(rest, 0)
			if i < 0 {
				return nil, nil, nil, errors.New("malformed auth switch")
			}
			plugin = string(rest[:i])
			nonce = bytes.TrimRight(rest[i+1:], "\x00")
			out, err := myAuth(plugin, nonce, g.pw, isTLS)
			if err != nil {
				return nil, nil, nil, Refused("database %s: %s", db.Name, err.Error())
			}
			err = myWrite(w, s+1, out)
			secret.WipeBytes(out)
			if err != nil {
				return nil, nil, nil, err
			}
		case 0x01:
			if plugin != "caching_sha2_password" || len(pk) < 2 {
				return nil, nil, nil, Refused("database %s: unexpected authentication data from the server", db.Name)
			}
			switch pk[1] {
			case 0x03: // fast authentication succeeded; OK follows
			case 0x04: // full authentication: the password itself
				if !isTLS {
					return nil, nil, nil, Refused("database %s: the server needs caching_sha2_password full authentication, which scrim does only over TLS", db.Name)
				}
				err := g.pw.Expose(func(b []byte) error {
					out := append(append(make([]byte, 0, len(b)+1), b...), 0)
					defer secret.WipeBytes(out)
					return myWrite(w, s+1, out)
				})
				if err != nil {
					return nil, nil, nil, err
				}
			default:
				return nil, nil, nil, Refused("database %s: unexpected authentication data from the server", db.Name)
			}
		default:
			return nil, nil, nil, fmt.Errorf("unexpected packet 0x%02x during login", pk[0])
		}
	}
	return nil, nil, nil, errors.New("authentication did not finish")
}

// myAuth computes the auth response for plugin.
func myAuth(plugin string, nonce []byte, pw secret.Value, isTLS bool) ([]byte, error) {
	if len(nonce) > 20 {
		nonce = nonce[:20]
	}
	switch plugin {
	case "mysql_native_password":
		return mysqlNative(pw, nonce), nil
	case "caching_sha2_password":
		return mysqlCachingSHA2(pw, nonce), nil
	case "mysql_clear_password":
		if !isTLS {
			return nil, errors.New("the server asks for a cleartext password, which scrim sends only over TLS")
		}
		var out []byte
		_ = pw.Expose(func(b []byte) error {
			out = append(append(make([]byte, 0, len(b)+1), b...), 0)
			return nil
		})
		return out, nil
	}
	return nil, fmt.Errorf("the server asks for authentication plugin %s, which scrim does not support", plugin)
}

// bufferedConn reads through r, which may hold bytes already read from
// Conn.
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufferedConn) Read(p []byte) (int, error) { return b.r.Read(p) }

// myFromClient relays client packets upstream and refuses COM_CHANGE_USER,
// which would log in as someone else on scrim's connection.
func myFromClient(r *bufio.Reader, up io.Writer, c io.Writer) error {
	for {
		seq, pk, err := myRead(r)
		if err != nil {
			return err
		}
		if seq == 0 && len(pk) > 0 && pk[0] == myComChangeUser {
			if err := myWrite(c, 1, myErrPacket(1227, "42000", "scrim: changing the user on a proxied connection is refused")); err != nil {
				return err
			}
			continue
		}
		hdr := [4]byte{byte(len(pk)), byte(len(pk) >> 8), byte(len(pk) >> 16), seq}
		if _, err := up.Write(append(hdr[:], pk...)); err != nil {
			return err
		}
	}
}

// myFromServer relays server packets to the client one whole packet at a
// time, and stops at a packet that carries the password, including one split
// across the 16 MiB packet boundary.
func myFromServer(r io.Reader, c net.Conn, g guard) error {
	w := bufio.NewWriterSize(c, 32<<10)
	br, _ := r.(*bufio.Reader)
	var tail []byte
	for {
		seq, pk, err := myRead(r)
		if err != nil {
			return err
		}
		if g.contains(pk) || (tail != nil && g.contains(append(tail, pk[:min(len(pk), 4096)]...))) {
			secret.WipeBytes(pk)
			w.Reset(c)
			_ = myWrite(c, seq, myErrPacket(2013, "HY000", leakNotice))
			return errLeak
		}
		tail = nil
		if len(pk) == myMaxPacket {
			tail = append([]byte(nil), pk[len(pk)-4096:]...)
		}
		var hdr = [4]byte{byte(len(pk)), byte(len(pk) >> 8), byte(len(pk) >> 16), seq}
		if _, err := w.Write(hdr[:]); err != nil {
			return err
		}
		if _, err := w.Write(pk); err != nil {
			return err
		}
		if br == nil || br.Buffered() == 0 {
			if err := w.Flush(); err != nil {
				return err
			}
		}
	}
}
