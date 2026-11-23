// SPDX-License-Identifier: AGPL-3.0-only

// Package keyring is the keyring store adapter: secrets read from the
// operating system's keyring, addressed as `<instance>://<service>/<account>`.
//
// One adapter, three backends, chosen by the operating system scrim runs on:
//
//   - Linux (and other Unix systems with D-Bus): the freedesktop Secret
//     Service (gnome-keyring, KeePassXC, KWallet's Secret Service bridge),
//     spoken directly over D-Bus. An item is matched by two attributes,
//     `service` and `username` by default (the convention of libsecret's
//     `secret-tool`, Python keyring and go-keyring), in one collection.
//     Reads, lists and label lookups that never fetch the secret.
//   - macOS: generic passwords in the Keychain, through /usr/bin/security
//     (service `-s`, account `-a`). Reads and label lookups only.
//   - Windows: generic credentials in the Credential Manager, target name
//     `<service>:<account>`. Reads only.
//
// The source is read-only: a write is refused with stores.ErrUnsupported
// ("keyring source is read-only") before any D-Bus or OS call, and nothing
// is watched (the refresher polls). Each item is a secret with one field,
// "value".
//
// Least privilege: the `services` option is required and lists the keyring
// services scrim may read; `allow` narrows them to path patterns. Anything
// else is invisible and reads as not found without asking the keyring, so a
// reference cannot reach the browser's, the Wi-Fi's or another program's
// passwords. The Secret Service backend also stays inside one collection.
//
// A locked keyring is refused with stores.ErrLocked. scrim never asks the
// keyring to unlock and never opens a prompt: unlocking is the desktop
// session's job (or `gnome-keyring-daemon --unlock` on a headless host).
package keyring

import (
	"context"
	"path"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores"
	"github.com/heliopsy/scrim/internal/stores/internal/options"
)

// Kind is the adapter kind this package registers.
const Kind = "keyring"

// Field is the name of the only field a keyring secret has.
const Field = "value"

const readOnly = "keyring source is read-only"

// Backend names, also the value of the keyring.backend label.
const (
	BackendSecretService = "secret-service"
	BackendKeychain      = "keychain"
	BackendWinCred       = "wincred"
)

// Option defaults.
const (
	DefaultCollection    = "default"
	DefaultServiceAttr   = "service"
	DefaultAccountAttr   = "username"
	DefaultTimeout       = 10 * time.Second
	SessionEncrypted     = "encrypted"
	SessionPlain         = "plain"
	defaultSession       = SessionEncrypted
	maxServiceNameLength = 512
)

func init() {
	stores.Register(Kind, func(_ context.Context, inst stores.Instance) (stores.Adapter, error) {
		cfg, err := ParseOptions(inst.Name, inst.Options, DefaultBackend())
		if err != nil {
			return nil, err
		}
		return New(inst.Name, cfg)
	})
}

// DefaultBackend is the backend for the operating system scrim was built
// for.
func DefaultBackend() string {
	switch runtime.GOOS {
	case "darwin":
		return BackendKeychain
	case "windows":
		return BackendWinCred
	}
	return BackendSecretService
}

// Config is the keyring source's configuration.
type Config struct {
	// Backend is the keyring backend (see DefaultBackend); not an option.
	Backend string
	// Services are the keyring services scrim may read (option `services`,
	// required). A reference's first path segment must be one of them.
	Services []string
	// Allow, when non-empty, limits the source to `<service>/<account>`
	// paths matching one of these exact paths or path.Match patterns
	// (option `allow`).
	Allow []string
	// Timeout bounds every call to the keyring (option `timeout`).
	Timeout time.Duration

	// Secret Service only.

	// Collection is the alias (`default`, `login`, `session`) or label of
	// the collection items are read from (option `collection`).
	Collection string
	// BusAddress is the D-Bus address of the session bus (option
	// `bus-address`). Empty means DBUS_SESSION_BUS_ADDRESS, then
	// $XDG_RUNTIME_DIR/bus; a bus is never launched.
	BusAddress string
	// ServiceAttr and AccountAttr are the item attributes holding the
	// service and the account (options `attributes.service`,
	// `attributes.account`).
	ServiceAttr string
	AccountAttr string
	// Session is how secrets cross the bus: "encrypted" (Diffie-Hellman
	// and AES, the default) or "plain" (option `session`).
	Session string

	// Keychain only.

	// Keychain is the path of the keychain to read (option `keychain`).
	// Empty means the user's keychain search list.
	Keychain string
}

// ParseOptions decodes and validates instance options strictly for
// backend. Options of another operating system's backend are refused, so a
// configuration copied from Linux to macOS does not silently lose its
// collection.
func ParseOptions(store string, raw map[string]any, backend string) (Config, error) {
	d := options.New(store, raw)
	cfg := Config{
		Backend:  backend,
		Services: d.Strings("services"),
		Allow:    d.Strings("allow"),
		Timeout:  d.Duration("timeout", DefaultTimeout),
	}
	if len(cfg.Services) == 0 {
		d.Errorf("option services is required: list the keyring services scrim may read")
	}
	for _, s := range cfg.Services {
		switch {
		case s == "" || strings.ContainsAny(s, "/*?[\\") || len(s) > maxServiceNameLength:
			d.Errorf("option services: %q must be an exact service name without '/' or glob characters", s)
		case strings.ContainsRune(s, 0):
			d.Errorf("option services: a service name must not contain NUL")
		}
	}
	for _, p := range cfg.Allow {
		if _, err := path.Match(p, ""); err != nil {
			d.Errorf("option allow: malformed pattern %q", p)
		}
	}
	if cfg.Timeout <= 0 {
		d.Errorf("option timeout must be positive")
	}
	// Each backend's own options. Reading a key marks it known, so the
	// keys of the other backends are only read (and refused) when set.
	ss := map[string]bool{"collection": true, "bus-address": true, "attributes.service": true, "attributes.account": true, "session": true}
	kc := map[string]bool{"keychain": true}
	own := map[string]bool{}
	switch backend {
	case BackendSecretService:
		own = ss
		cfg.Collection = d.String("collection", DefaultCollection)
		cfg.BusAddress = d.String("bus-address", "")
		cfg.ServiceAttr = d.String("attributes.service", DefaultServiceAttr)
		cfg.AccountAttr = d.String("attributes.account", DefaultAccountAttr)
		cfg.Session = d.String("session", defaultSession)
		if cfg.Collection == "" {
			d.Errorf("option collection must not be empty")
		}
		if cfg.ServiceAttr == "" || cfg.AccountAttr == "" || cfg.ServiceAttr == cfg.AccountAttr {
			d.Errorf("options attributes.service and attributes.account must be two different attribute names")
		}
		if cfg.Session != SessionEncrypted && cfg.Session != SessionPlain {
			d.Errorf("option session must be %s or %s", SessionEncrypted, SessionPlain)
		}
	case BackendKeychain:
		own = kc
		cfg.Keychain = d.String("keychain", "")
		if cfg.Keychain != "" && !strings.HasPrefix(cfg.Keychain, "/") {
			d.Errorf("option keychain must be an absolute path")
		}
	case BackendWinCred:
	default:
		d.Errorf("unknown keyring backend %q", backend)
	}
	const unset = "\x00unset"
	for _, other := range []map[string]bool{ss, kc} {
		for k := range other {
			if !own[k] && d.String(k, unset) != unset {
				d.Errorf("option %s does not apply to the %s backend", k, backend)
			}
		}
	}
	return cfg, d.Finish()
}

// item is one keyring entry's metadata, never its value.
type item struct {
	service, account string
	// label is the item's display label, when the backend has one.
	label string
	// collection names the Secret Service collection.
	collection string
	// attrs are the item's other attributes (Secret Service), user
	// editable, so reported under keyring.meta.
	attrs             map[string]string
	created, modified time.Time
}

// backend is one operating system's keyring. Errors are *kindError or
// context errors; the adapter wraps them into stores.Error.
type backend interface {
	caps() stores.Capabilities
	// read returns the item and its value; the caller wipes the value.
	read(ctx context.Context, service, account string) (item, secret.Value, error)
	// meta returns the item without fetching its value.
	meta(ctx context.Context, service, account string) (item, error)
	// list returns the items of service.
	list(ctx context.Context, service string) ([]item, error)
	health(ctx context.Context) error
	close() error
}

// kindError is a backend failure: one of the stores error kinds and a
// sanitised detail that never holds a value.
type kindError struct {
	kind   error
	detail string
	cause  error
}

func (e *kindError) Error() string {
	if e.detail == "" {
		return e.kind.Error()
	}
	return e.kind.Error() + ": " + e.detail
}

func (e *kindError) Unwrap() []error {
	if e.cause == nil {
		return []error{e.kind}
	}
	return []error{e.kind, e.cause}
}

func kerr(kind error, detail string, cause error) error {
	return &kindError{kind: kind, detail: detail, cause: cause}
}

// Adapter is the keyring source.
type Adapter struct {
	name string
	cfg  Config
	b    backend
}

// New returns a keyring source named name for cfg.Backend. It does not
// contact the keyring.
func New(name string, cfg Config) (*Adapter, error) {
	b, err := newBackend(cfg)
	if err != nil {
		return nil, err
	}
	return &Adapter{name: name, cfg: cfg, b: b}, nil
}

// Name implements stores.Adapter.
func (a *Adapter) Name() string { return a.name }

// Capabilities implements stores.Adapter: read everywhere, list and glob
// listing where the backend can enumerate items without their values (the
// Secret Service).
func (a *Adapter) Capabilities() stores.Capabilities { return a.b.caps() }

func (a *Adapter) err(op stores.Op, ref stores.Ref, kind error, detail string, cause error) error {
	e := stores.NewError(a.name, op, ref, kind, cause)
	e.Detail = detail
	return e
}

// wrap turns a backend error into a stores.Error.
func (a *Adapter) wrap(op stores.Op, ref stores.Ref, err error) error {
	if ke, ok := err.(*kindError); ok {
		return a.err(op, ref, ke.kind, ke.detail, ke.cause)
	}
	return a.err(op, ref, stores.ErrUnavailable, "keyring did not answer", err)
}

// splitPath splits a secret path into service and account.
func splitPath(p string) (service, account string, ok bool) {
	service, account, ok = strings.Cut(p, "/")
	return service, account, ok && service != "" && account != ""
}

func (a *Adapter) serviceVisible(service string) bool {
	return slices.Contains(a.cfg.Services, service)
}

func (a *Adapter) visible(service, account string) bool {
	if !a.serviceVisible(service) || account == "" {
		return false
	}
	if len(a.cfg.Allow) == 0 {
		return true
	}
	full := service + "/" + account
	for _, p := range a.cfg.Allow {
		if p == full {
			return true
		}
		if ok, _ := path.Match(p, full); ok {
			return true
		}
	}
	return false
}

// target checks ref and returns the service and account it names.
func (a *Adapter) target(op stores.Op, ref stores.Ref) (string, string, error) {
	if ref.Selectors != "" {
		return "", "", a.err(op, ref, stores.ErrInvalidRef, "the keyring source has no version selectors", nil)
	}
	if strings.ContainsRune(ref.Path, 0) {
		return "", "", a.err(op, ref, stores.ErrInvalidRef, "NUL in path", nil)
	}
	service, account, ok := splitPath(ref.Path)
	if !ok {
		return "", "", a.err(op, ref, stores.ErrInvalidRef, "want <service>/<account>", nil)
	}
	if ref.Field != "" && ref.Field != Field {
		return "", "", a.err(op, ref, stores.ErrNotFound, `keyring secrets have one field, "value"`, nil)
	}
	if !a.visible(service, account) {
		return "", "", a.err(op, ref, stores.ErrNotFound, "", nil)
	}
	return service, account, nil
}

// Read implements stores.Adapter.
func (a *Adapter) Read(ctx context.Context, ref stores.Ref) (stores.Secret, error) {
	service, account, err := a.target(stores.OpRead, ref)
	if err != nil {
		return stores.Secret{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, a.cfg.Timeout)
	defer cancel()
	it, v, err := a.b.read(ctx, service, account)
	if err != nil {
		return stores.Secret{}, a.wrap(stores.OpRead, ref.Secret(), err)
	}
	return stores.Secret{
		Meta:   a.metadata(ref.Scheme, it),
		Fields: map[string]secret.Value{Field: v},
	}, nil
}

// ReadMetadata implements stores.MetadataReader: the item's labels without
// its value. On Windows the Credential Manager returns the value with the
// metadata, and it is wiped at once.
func (a *Adapter) ReadMetadata(ctx context.Context, ref stores.Ref) (stores.Metadata, error) {
	service, account, err := a.target(stores.OpRead, ref.Secret())
	if err != nil {
		return stores.Metadata{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, a.cfg.Timeout)
	defer cancel()
	it, err := a.b.meta(ctx, service, account)
	if err != nil {
		return stores.Metadata{}, a.wrap(stores.OpRead, ref.Secret(), err)
	}
	return a.metadata(ref.Scheme, it), nil
}

func (a *Adapter) metadata(scheme string, it item) stores.Metadata {
	return stores.Metadata{
		Ref:       stores.Ref{Scheme: scheme, Path: it.service + "/" + it.account},
		Fields:    []string{Field},
		CreatedAt: it.created,
		UpdatedAt: it.modified,
		Labels:    a.labels(it),
	}
}

// labels are a keyring secret's labels: keyring.backend, keyring.service,
// keyring.account, keyring.collection and keyring.label where the backend
// has them, keyring.keychain when one is configured, and every other item
// attribute as keyring.meta.<attribute>, which can never replace a native
// key.
func (a *Adapter) labels(it item) map[string]string {
	l := map[string]string{}
	stores.SetNative(l, Kind, "backend", a.cfg.Backend)
	stores.SetNative(l, Kind, "service", it.service)
	stores.SetNative(l, Kind, "account", it.account)
	stores.SetNative(l, Kind, "collection", it.collection)
	stores.SetNative(l, Kind, "label", it.label)
	stores.SetNative(l, Kind, "keychain", a.cfg.Keychain)
	keys := make([]string, 0, len(it.attrs))
	for k := range it.attrs {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		stores.UserMeta(l, Kind, k, it.attrs[k])
	}
	return l
}

// List implements stores.Adapter where the backend declares stores.CapList.
// The first path segment must be an exact configured service; the rest is
// an account prefix matched by path segments (`kr://svc/ci` lists `ci` and
// `ci/...`), or a glob when it ends in `*` (`kr://svc/ci-*`). `kr://svc`
// lists every visible account of the service.
func (a *Adapter) List(ctx context.Context, prefix stores.Ref) ([]stores.Metadata, error) {
	if !a.b.caps().Has(stores.CapList) {
		return nil, a.err(stores.OpList, prefix, stores.ErrUnsupported, "the "+a.cfg.Backend+" backend cannot list items without reading them", nil)
	}
	if prefix.Selectors != "" {
		return nil, a.err(stores.OpList, prefix, stores.ErrInvalidRef, "the keyring source has no version selectors", nil)
	}
	service, rest, _ := strings.Cut(prefix.Path, "/")
	if strings.Contains(service, "*") {
		return nil, a.err(stores.OpList, prefix, stores.ErrInvalidRef, "the service segment cannot be a glob; name the service", nil)
	}
	if !a.serviceVisible(service) {
		return []stores.Metadata{}, nil
	}
	match := func(account string) bool {
		if rest == "" {
			return true
		}
		if s, ok := strings.CutSuffix(rest, "*"); ok {
			return strings.HasPrefix(account, s)
		}
		return account == rest || strings.HasPrefix(account, strings.TrimSuffix(rest, "/")+"/")
	}
	ctx, cancel := context.WithTimeout(ctx, a.cfg.Timeout)
	defer cancel()
	items, err := a.b.list(ctx, service)
	if err != nil {
		return nil, a.wrap(stores.OpList, prefix, err)
	}
	out := make([]stores.Metadata, 0, len(items))
	seen := map[string]bool{}
	for _, it := range items {
		if !a.visible(it.service, it.account) || !match(it.account) || strings.ContainsRune(it.account, 0) {
			continue
		}
		// An account that does not make a valid reference path (empty
		// segments, surrounding slashes) cannot be read back; skip it.
		if strings.Contains(it.account, "//") || strings.HasPrefix(it.account, "/") || strings.HasSuffix(it.account, "/") {
			continue
		}
		p := it.service + "/" + it.account
		if seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, a.metadata(prefix.Scheme, it))
	}
	slices.SortFunc(out, func(x, y stores.Metadata) int { return strings.Compare(x.Ref.Path, y.Ref.Path) })
	return out, nil
}

// Watch implements stores.Adapter: always refused; the refresher polls.
func (a *Adapter) Watch(_ context.Context, prefix stores.Ref) (<-chan stores.Change, error) {
	return nil, a.err(stores.OpWatch, prefix, stores.ErrUnsupported, "keyring source does not watch; scrim polls it", nil)
}

// Write implements stores.Adapter: always refused, before the keyring is
// contacted. The caller's values are left as they are.
func (a *Adapter) Write(_ context.Context, ref stores.Ref, _ map[string]secret.Value, _ stores.WriteOptions) (stores.Metadata, error) {
	return stores.Metadata{}, a.err(stores.OpWrite, ref.Secret(), stores.ErrUnsupported, readOnly, nil)
}

// Health implements stores.Adapter: the keyring answers and, for the Secret
// Service, the collection exists and is unlocked.
func (a *Adapter) Health(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, a.cfg.Timeout)
	defer cancel()
	if err := a.b.health(ctx); err != nil {
		return a.wrap(stores.OpHealth, stores.Ref{}, err)
	}
	return nil
}

// Close implements stores.Adapter.
func (a *Adapter) Close() error { return a.b.close() }
