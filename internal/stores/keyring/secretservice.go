// SPDX-License-Identifier: AGPL-3.0-only

package keyring

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/godbus/dbus/v5"

	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores"
)

// The freedesktop Secret Service API, spoken directly over D-Bus
// (https://specifications.freedesktop.org/secret-service-spec/latest/).
// Only these calls are made: OpenSession, ReadAlias, SearchItems and
// property reads on the service, collections and items, and GetSecret on
// one item. Never Unlock, CreateItem, Delete or anything that can open a
// prompt.
const (
	ssDest       = "org.freedesktop.secrets"
	ssPath       = dbus.ObjectPath("/org/freedesktop/secrets")
	ssService    = "org.freedesktop.Secret.Service"
	ssCollection = "org.freedesktop.Secret.Collection"
	ssItem       = "org.freedesktop.Secret.Item"
	dbusProps    = "org.freedesktop.DBus.Properties"
)

// secretService is the Linux backend.
type secretService struct {
	cfg Config

	mu      sync.Mutex
	conn    *dbus.Conn
	session dbus.ObjectPath
	key     []byte // AES key of an encrypted session; nil for plain
	closed  bool
}

func newSecretService(cfg Config) *secretService { return &secretService{cfg: cfg} }

func (s *secretService) caps() stores.Capabilities {
	return stores.CapRead | stores.CapList | stores.CapGlob
}

// busAddress is the configured address, else DBUS_SESSION_BUS_ADDRESS,
// else $XDG_RUNTIME_DIR/bus when that socket exists. It never autolaunches
// a bus.
func (s *secretService) busAddress() (string, error) {
	if s.cfg.BusAddress != "" {
		return s.cfg.BusAddress, nil
	}
	if a := os.Getenv("DBUS_SESSION_BUS_ADDRESS"); a != "" && a != "autolaunch:" {
		return a, nil
	}
	if dir := os.Getenv("XDG_RUNTIME_DIR"); dir != "" {
		p := filepath.Join(dir, "bus")
		if fi, err := os.Stat(p); err == nil && fi.Mode()&os.ModeSocket != 0 {
			return "unix:path=" + p, nil
		}
	}
	return "", kerr(stores.ErrUnavailable, "no session bus: set bus-address or DBUS_SESSION_BUS_ADDRESS", nil)
}

// connect returns the connection and session, opening them on first use
// and again after the bus went away.
func (s *secretService) connect(ctx context.Context) (*dbus.Conn, dbus.ObjectPath, []byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, "", nil, kerr(stores.ErrUnavailable, "adapter closed", nil)
	}
	if s.conn != nil && s.conn.Connected() {
		return s.conn, s.session, s.key, nil
	}
	s.dropLocked()
	addr, err := s.busAddress()
	if err != nil {
		return nil, "", nil, err
	}
	conn, err := dial(ctx, addr)
	if err != nil {
		return nil, "", nil, err
	}
	session, key, err := openSession(ctx, conn, s.cfg.Session)
	if err != nil {
		_ = conn.Close()
		return nil, "", nil, err
	}
	s.conn, s.session, s.key = conn, session, key
	return conn, session, key, nil
}

// dial connects to the bus at addr within ctx. godbus ties a connection's
// lifetime to the context it is given, so the connection gets none and the
// deadline is enforced here; a connection that completes after the deadline
// is closed.
func dial(ctx context.Context, addr string) (*dbus.Conn, error) {
	type result struct {
		conn *dbus.Conn
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		c, err := dbus.Connect(addr, dbus.WithAuth(dbus.AuthExternal(strconv.Itoa(os.Geteuid())), dbus.AuthAnonymous()))
		ch <- result{c, err}
	}()
	select {
	case r := <-ch:
		if r.err != nil {
			return nil, kerr(stores.ErrUnavailable, "cannot connect to the session bus", r.err)
		}
		return r.conn, nil
	case <-ctx.Done():
		go func() {
			if r := <-ch; r.conn != nil {
				_ = r.conn.Close()
			}
		}()
		return nil, kerr(stores.ErrUnavailable, "session bus did not answer in time", ctx.Err())
	}
}

// dropLocked forgets the connection and wipes the session key.
func (s *secretService) dropLocked() {
	if s.conn != nil {
		_ = s.conn.Close()
	}
	secret.WipeBytes(s.key)
	s.conn, s.session, s.key = nil, "", nil
}

// forget drops the connection after a failure that may mean it is dead,
// so the next call reconnects.
func (s *secretService) forget(conn *dbus.Conn, err error) {
	if !errors.Is(err, dbus.ErrClosed) && conn.Connected() {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn == conn {
		s.dropLocked()
	}
}

// openSession opens a session for transferring secrets.
func openSession(ctx context.Context, conn *dbus.Conn, mode string) (dbus.ObjectPath, []byte, error) {
	svc := conn.Object(ssDest, ssPath)
	var out dbus.Variant
	var session dbus.ObjectPath
	if mode == SessionPlain {
		if err := svc.CallWithContext(ctx, ssService+".OpenSession", 0, "plain", dbus.MakeVariant("")).Store(&out, &session); err != nil {
			return "", nil, mapDBus(err, "open session")
		}
		return session, nil, nil
	}
	dh, err := newDHSession()
	if err != nil {
		return "", nil, kerr(stores.ErrUnavailable, "cannot generate session key", err)
	}
	defer dh.wipe()
	if err := svc.CallWithContext(ctx, ssService+".OpenSession", 0, dhAlgorithm, dbus.MakeVariant(dh.public())).Store(&out, &session); err != nil {
		var de dbus.Error
		if errors.As(err, &de) && de.Name == "org.freedesktop.DBus.Error.NotSupported" {
			return "", nil, kerr(stores.ErrUnavailable, "the Secret Service does not support encrypted sessions; set session: plain to accept secrets in clear on the bus", err)
		}
		return "", nil, mapDBus(err, "open session")
	}
	peer, ok := out.Value().([]byte)
	if !ok {
		return "", nil, kerr(stores.ErrUnavailable, "Secret Service answered OpenSession with an unexpected type", nil)
	}
	key, err := dh.key(peer)
	if err != nil {
		return "", nil, kerr(stores.ErrUnavailable, "session key agreement failed", err)
	}
	return session, key, nil
}

// mapDBus maps a D-Bus failure to an error kind. Only the error name is
// kept in the detail; the message stays in the cause, which is not printed.
func mapDBus(err error, what string) error {
	var de dbus.Error
	if errors.As(err, &de) {
		switch de.Name {
		case "org.freedesktop.Secret.Error.IsLocked":
			return kerr(stores.ErrLocked, "keyring is locked; unlock it in the session (scrim never prompts)", err)
		case "org.freedesktop.Secret.Error.NoSuchObject", "org.freedesktop.DBus.Error.UnknownObject", "org.freedesktop.DBus.Error.UnknownMethod":
			return kerr(stores.ErrNotFound, "", err)
		case "org.freedesktop.DBus.Error.AccessDenied":
			return kerr(stores.ErrPermission, what+": "+de.Name, err)
		}
		return kerr(stores.ErrUnavailable, what+": "+de.Name, err)
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return kerr(stores.ErrUnavailable, what+": no answer from the Secret Service", err)
	}
	return kerr(stores.ErrUnavailable, what+": session bus failure", err)
}

func getProp[T any](ctx context.Context, conn *dbus.Conn, p dbus.ObjectPath, iface, name string) (T, error) {
	var zero T
	var v dbus.Variant
	if err := conn.Object(ssDest, p).CallWithContext(ctx, dbusProps+".Get", 0, iface, name).Store(&v); err != nil {
		return zero, err
	}
	t, ok := v.Value().(T)
	if !ok {
		return zero, kerr(stores.ErrUnavailable, "unexpected type of property "+name, nil)
	}
	return t, nil
}

// collection resolves the configured collection, by alias first, then by
// label. It returns its object path and whether it is locked.
func (s *secretService) collection(ctx context.Context, conn *dbus.Conn) (dbus.ObjectPath, bool, error) {
	svc := conn.Object(ssDest, ssPath)
	var p dbus.ObjectPath
	if err := svc.CallWithContext(ctx, ssService+".ReadAlias", 0, s.cfg.Collection).Store(&p); err != nil {
		return "", false, mapDBus(err, "read alias")
	}
	if p == "/" || p == "" {
		all, err := getProp[[]dbus.ObjectPath](ctx, conn, ssPath, ssService, "Collections")
		if err != nil {
			return "", false, mapDBus(err, "list collections")
		}
		p = ""
		for _, c := range all {
			label, err := getProp[string](ctx, conn, c, ssCollection, "Label")
			if err != nil {
				return "", false, mapDBus(err, "read collection label")
			}
			if label == s.cfg.Collection {
				p = c
				break
			}
		}
		if p == "" {
			return "", false, kerr(stores.ErrNotFound, "collection "+strconv.Quote(s.cfg.Collection)+" does not exist", nil)
		}
	}
	locked, err := getProp[bool](ctx, conn, p, ssCollection, "Locked")
	if err != nil {
		return "", false, mapDBus(err, "read collection state")
	}
	return p, locked, nil
}

// inCollection reports whether item path p belongs to collection c.
func inCollection(c, p dbus.ObjectPath) bool {
	return strings.HasPrefix(string(p), string(c)+"/")
}

// search returns the items of the collection matching attrs, unlocked and
// locked.
func (s *secretService) search(ctx context.Context, conn *dbus.Conn, coll dbus.ObjectPath, attrs map[string]string) (unlocked, locked []dbus.ObjectPath, err error) {
	if err := conn.Object(ssDest, ssPath).CallWithContext(ctx, ssService+".SearchItems", 0, attrs).Store(&unlocked, &locked); err != nil {
		return nil, nil, mapDBus(err, "search items")
	}
	keep := func(ps []dbus.ObjectPath) []dbus.ObjectPath {
		return slices.DeleteFunc(ps, func(p dbus.ObjectPath) bool { return !inCollection(coll, p) })
	}
	return keep(unlocked), keep(locked), nil
}

// find returns the single item for service and account.
func (s *secretService) find(ctx context.Context, service, account string) (*dbus.Conn, dbus.ObjectPath, dbus.ObjectPath, []byte, item, error) {
	conn, session, key, err := s.connect(ctx)
	if err != nil {
		return nil, "", "", nil, item{}, err
	}
	fail := func(err error) (*dbus.Conn, dbus.ObjectPath, dbus.ObjectPath, []byte, item, error) {
		s.forget(conn, err)
		return nil, "", "", nil, item{}, err
	}
	coll, collLocked, err := s.collection(ctx, conn)
	if err != nil {
		return fail(err)
	}
	unlocked, locked, err := s.search(ctx, conn, coll, map[string]string{s.cfg.ServiceAttr: service, s.cfg.AccountAttr: account})
	if err != nil {
		return fail(err)
	}
	switch n := len(unlocked) + len(locked); {
	case n == 0 && collLocked:
		return fail(kerr(stores.ErrLocked, "collection "+strconv.Quote(s.cfg.Collection)+" is locked; unlock it in the session (scrim never prompts)", nil))
	case n == 0:
		return fail(kerr(stores.ErrNotFound, "", nil))
	case n > 1:
		return fail(kerr(stores.ErrConflict, strconv.Itoa(n)+" keyring items match; keep one", nil))
	}
	if len(locked) == 1 {
		return fail(kerr(stores.ErrLocked, "item is locked; unlock the collection in the session (scrim never prompts)", nil))
	}
	it, err := s.itemMeta(ctx, conn, unlocked[0])
	if err != nil {
		return fail(err)
	}
	// SearchItems matched both attributes; keep the reference's spelling.
	it.service, it.account = service, account
	return conn, session, unlocked[0], key, it, nil
}

// itemMeta reads an item's properties, never its secret.
func (s *secretService) itemMeta(ctx context.Context, conn *dbus.Conn, p dbus.ObjectPath) (item, error) {
	var props map[string]dbus.Variant
	if err := conn.Object(ssDest, p).CallWithContext(ctx, dbusProps+".GetAll", 0, ssItem).Store(&props); err != nil {
		return item{}, mapDBus(err, "read item")
	}
	it := item{collection: s.cfg.Collection, attrs: map[string]string{}}
	if v, ok := props["Label"].Value().(string); ok {
		it.label = v
	}
	if v, ok := props["Created"].Value().(uint64); ok && v > 0 {
		it.created = time.Unix(int64(v), 0).UTC()
	}
	if v, ok := props["Modified"].Value().(uint64); ok && v > 0 {
		it.modified = time.Unix(int64(v), 0).UTC()
	}
	if attrs, ok := props["Attributes"].Value().(map[string]string); ok {
		for k, v := range attrs {
			switch k {
			case s.cfg.ServiceAttr:
				it.service = v
			case s.cfg.AccountAttr:
				it.account = v
			default:
				it.attrs[k] = v
			}
		}
	}
	return it, nil
}

// secretStruct is the Secret Service's Secret: (oayays).
type secretStruct struct {
	Session     dbus.ObjectPath
	Parameters  []byte
	Value       []byte
	ContentType string
}

func (s *secretService) read(ctx context.Context, service, account string) (item, secret.Value, error) {
	conn, session, p, key, it, err := s.find(ctx, service, account)
	if err != nil {
		return item{}, secret.Value{}, err
	}
	var sec secretStruct
	if err := conn.Object(ssDest, p).CallWithContext(ctx, ssItem+".GetSecret", 0, session).Store(&sec); err != nil {
		secret.WipeBytes(sec.Value)
		err = mapDBus(err, "get secret")
		s.forget(conn, err)
		return item{}, secret.Value{}, err
	}
	defer secret.WipeBytes(sec.Parameters)
	if key == nil {
		// Adopted: godbus decoded the bytes into a fresh slice we own.
		return it, secret.Adopt(sec.Value), nil
	}
	plain, err := decrypt(key, sec.Parameters, sec.Value)
	secret.WipeBytes(sec.Value)
	if err != nil {
		return item{}, secret.Value{}, kerr(stores.ErrUnavailable, "cannot decrypt the secret from the session", err)
	}
	return it, secret.Adopt(plain), nil
}

func (s *secretService) meta(ctx context.Context, service, account string) (item, error) {
	_, _, _, _, it, err := s.find(ctx, service, account)
	return it, err
}

func (s *secretService) list(ctx context.Context, service string) ([]item, error) {
	conn, _, _, err := s.connect(ctx)
	if err != nil {
		return nil, err
	}
	out, err := s.listOn(ctx, conn, service)
	if err != nil {
		s.forget(conn, err)
	}
	return out, err
}

func (s *secretService) listOn(ctx context.Context, conn *dbus.Conn, service string) ([]item, error) {
	coll, locked, err := s.collection(ctx, conn)
	if err != nil {
		return nil, err
	}
	if locked {
		return nil, kerr(stores.ErrLocked, "collection "+strconv.Quote(s.cfg.Collection)+" is locked; unlock it in the session (scrim never prompts)", nil)
	}
	unlocked, lockedItems, err := s.search(ctx, conn, coll, map[string]string{s.cfg.ServiceAttr: service})
	if err != nil {
		return nil, err
	}
	out := make([]item, 0, len(unlocked)+len(lockedItems))
	for _, p := range append(unlocked, lockedItems...) {
		it, err := s.itemMeta(ctx, conn, p)
		if errors.Is(err, stores.ErrNotFound) {
			continue // deleted between search and read
		}
		if err != nil {
			return nil, err
		}
		if it.service != service || it.account == "" {
			continue
		}
		out = append(out, it)
	}
	return out, nil
}

func (s *secretService) health(ctx context.Context) error {
	conn, _, _, err := s.connect(ctx)
	if err != nil {
		return err
	}
	_, locked, err := s.collection(ctx, conn)
	if err != nil {
		s.forget(conn, err)
		return err
	}
	if locked {
		return kerr(stores.ErrLocked, "collection "+strconv.Quote(s.cfg.Collection)+" is locked; unlock it in the session (scrim never prompts)", nil)
	}
	return nil
}

func (s *secretService) close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn != nil && s.session != "" {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		_ = s.conn.Object(ssDest, s.session).CallWithContext(ctx, "org.freedesktop.Secret.Session.Close", 0).Err
		cancel()
	}
	s.dropLocked()
	s.closed = true
	return nil
}
