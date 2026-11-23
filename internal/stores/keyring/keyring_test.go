// SPDX-License-Identifier: AGPL-3.0-only

package keyring

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores"
	"github.com/heliopsy/scrim/internal/stores/storetest"
)

// fakeBackend is an in-memory keyring that counts calls, so tests can
// prove a refusal happened before the keyring was asked.
type fakeBackend struct {
	mu      sync.Mutex
	items   map[string]fakeItem // "service\x00account"
	calls   int
	down    bool
	locked  bool
	canList bool
}

type fakeItem struct {
	value []byte
	attrs map[string]string
	label string
}

func newFake() *fakeBackend { return &fakeBackend{items: map[string]fakeItem{}, canList: true} }

func (f *fakeBackend) set(service, account string, v []byte, attrs map[string]string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.items[service+"\x00"+account] = fakeItem{value: slices.Clone(v), attrs: attrs, label: "label of " + account}
}

func (f *fakeBackend) del(service, account string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.items, service+"\x00"+account)
}

func (f *fakeBackend) caps() stores.Capabilities {
	if f.canList {
		return stores.CapRead | stores.CapList | stores.CapGlob
	}
	return stores.CapRead
}

func (f *fakeBackend) enter() error {
	f.calls++
	switch {
	case f.down:
		return kerr(stores.ErrUnavailable, "down", nil)
	case f.locked:
		return kerr(stores.ErrLocked, "locked", nil)
	}
	return nil
}

func (f *fakeBackend) get(service, account string) (item, fakeItem, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.enter(); err != nil {
		return item{}, fakeItem{}, err
	}
	fi, ok := f.items[service+"\x00"+account]
	if !ok {
		return item{}, fakeItem{}, kerr(stores.ErrNotFound, "", nil)
	}
	return item{service: service, account: account, label: fi.label, collection: "default", attrs: fi.attrs}, fi, nil
}

func (f *fakeBackend) read(_ context.Context, service, account string) (item, secret.Value, error) {
	it, fi, err := f.get(service, account)
	if err != nil {
		return item{}, secret.Value{}, err
	}
	return it, secret.New(fi.value), nil
}

func (f *fakeBackend) meta(_ context.Context, service, account string) (item, error) {
	it, _, err := f.get(service, account)
	return it, err
}

func (f *fakeBackend) list(_ context.Context, service string) ([]item, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.enter(); err != nil {
		return nil, err
	}
	var out []item
	for k, fi := range f.items {
		s, a, _ := strings.Cut(k, "\x00")
		if s == service {
			out = append(out, item{service: s, account: a, label: fi.label, attrs: fi.attrs})
		}
	}
	return out, nil
}

func (f *fakeBackend) health(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.enter()
}

func (f *fakeBackend) close() error { return nil }

func (f *fakeBackend) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func testConfig(services ...string) Config {
	return Config{Backend: BackendSecretService, Services: services, Timeout: DefaultTimeout, Collection: DefaultCollection}
}

func newWithFake(cfg Config, f *fakeBackend) *Adapter {
	return &Adapter{name: "kr", cfg: cfg, b: f}
}

func plain(v secret.Value) string {
	var s string
	_ = v.Expose(func(b []byte) error { s = string(b); return nil })
	return s
}

func gen(t testing.TB) string {
	t.Helper()
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return "kr_" + hex.EncodeToString(b)
}

func seedInto(f *fakeBackend) func(storetest.TB, stores.Ref, map[string]secret.Value) {
	return func(t storetest.TB, ref stores.Ref, fields map[string]secret.Value) {
		s, a, _ := strings.Cut(ref.Path, "/")
		_ = fields[Field].Expose(func(b []byte) error { f.set(s, a, b, nil); return nil })
	}
}

// The adapter logic (references, visibility, labels, refusals) against an
// in-memory backend; the real Secret Service run is in
// integration_test.go.
func TestConformanceFake(t *testing.T) {
	storetest.Run(t, func(storetest.TB) storetest.Harness {
		f := newFake()
		return storetest.Harness{
			Adapter:     newWithFake(testConfig("scrim-conformance"), f),
			SingleField: Field,
			Seed:        seedInto(f),
			Delete: func(t storetest.TB, ref stores.Ref) {
				s, a, _ := strings.Cut(ref.Path, "/")
				f.del(s, a)
			},
			Outage: func(storetest.TB) func() {
				f.mu.Lock()
				f.down = true
				f.mu.Unlock()
				return func() { f.mu.Lock(); f.down = false; f.mu.Unlock() }
			},
		}
	})
}

// Read-only backends without listing (Keychain, Credential Manager) pass
// too.
func TestConformanceFakeNoList(t *testing.T) {
	storetest.Run(t, func(storetest.TB) storetest.Harness {
		f := newFake()
		f.canList = false
		return storetest.Harness{
			Adapter:     newWithFake(Config{Backend: BackendKeychain, Services: []string{"scrim-conformance"}, Timeout: DefaultTimeout}, f),
			SingleField: Field,
			Seed:        seedInto(f),
		}
	})
}

func TestWriteRefusedBeforeKeyring(t *testing.T) {
	f := newFake()
	a := newWithFake(testConfig("svc"), f)
	v := gen(t)
	fields := map[string]secret.Value{Field: secret.FromString(v)}
	_, err := a.Write(t.Context(), stores.MustParseRef("kr://svc/new#value"), fields, stores.WriteOptions{})
	if !errors.Is(err, stores.ErrUnsupported) || !strings.Contains(err.Error(), "keyring source is read-only") {
		t.Fatalf("Write = %v, want ErrUnsupported saying the source is read-only", err)
	}
	if strings.Contains(err.Error(), v) || strings.Contains(fmt.Sprintf("%+v", err), v) {
		t.Errorf("write error contains the value")
	}
	if f.callCount() != 0 {
		t.Errorf("Write reached the keyring (%d calls)", f.callCount())
	}
	if fields[Field].Wiped() {
		t.Errorf("Write wiped the caller's value")
	}
	if a.Capabilities().Has(stores.CapWrite) || a.Capabilities().Has(stores.CapWatch) {
		t.Errorf("capabilities %s declare write or watch", a.Capabilities())
	}
	if _, err := a.Watch(t.Context(), stores.MustParseRef("kr://svc")); !errors.Is(err, stores.ErrUnsupported) {
		t.Errorf("Watch = %v, want ErrUnsupported", err)
	}
}

func TestVisibilityNeverAsksKeyring(t *testing.T) {
	f := newFake()
	f.set("svc", "ci/token", []byte(gen(t)), nil)
	f.set("svc", "dev/token", []byte(gen(t)), nil)
	f.set("browser", "me@example.com", []byte(gen(t)), nil)
	cfg := testConfig("svc")
	cfg.Allow = []string{"svc/ci/*"}
	a := newWithFake(cfg, f)
	ctx := t.Context()
	for _, ref := range []string{"kr://browser/me@example.com", "kr://svc/dev/token", "kr://svc", "kr://svc/ci/token?version=1", "kr://svc/ci/token#password"} {
		before := f.callCount()
		s, err := a.Read(ctx, stores.MustParseRef(ref))
		if err == nil {
			s.Wipe()
			t.Errorf("Read %s succeeded", ref)
			continue
		}
		if f.callCount() != before {
			t.Errorf("Read %s asked the keyring before refusing", ref)
		}
	}
	if _, err := a.Read(ctx, stores.MustParseRef("kr://browser/me@example.com")); !errors.Is(err, stores.ErrNotFound) {
		t.Errorf("service outside services: %v, want not found", err)
	}
	if _, err := a.Read(ctx, stores.MustParseRef("kr://svc")); !errors.Is(err, stores.ErrInvalidRef) {
		t.Errorf("reference without account: %v, want invalid", err)
	}
	if _, err := a.Read(ctx, stores.MustParseRef("kr://svc/ci/token?version=1")); !errors.Is(err, stores.ErrInvalidRef) {
		t.Errorf("selector: %v, want invalid", err)
	}
	s, err := a.Read(ctx, stores.MustParseRef("kr://svc/ci/token#value"))
	if err != nil {
		t.Fatalf("allowed read: %v", err)
	}
	s.Wipe()
	ms, err := a.List(ctx, stores.MustParseRef("kr://svc"))
	if err != nil || len(ms) != 1 || ms[0].Ref.Path != "svc/ci/token" {
		t.Errorf("List = %v, %v; want only svc/ci/token", ms, err)
	}
	before := f.callCount()
	if ms, err := a.List(ctx, stores.MustParseRef("kr://browser")); err != nil || len(ms) != 0 || f.callCount() != before {
		t.Errorf("List of a service outside services = %v, %v (asked keyring: %v)", ms, err, f.callCount() != before)
	}
	if _, err := a.List(ctx, stores.MustParseRef("kr://sv*")); !errors.Is(err, stores.ErrInvalidRef) {
		t.Errorf("glob in the service segment: %v, want invalid", err)
	}
}

func TestListGlob(t *testing.T) {
	f := newFake()
	for _, acct := range []string{"ci-a", "ci-b/x", "cia", "other"} {
		f.set("svc", acct, []byte(gen(t)), nil)
	}
	a := newWithFake(testConfig("svc"), f)
	ms, err := a.List(t.Context(), stores.MustParseRef("kr://svc/ci-*"))
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, m := range ms {
		got = append(got, m.Ref.Path)
	}
	if want := []string{"svc/ci-a", "svc/ci-b/x"}; !slices.Equal(got, want) {
		t.Errorf("glob list = %v, want %v", got, want)
	}
}

func TestLockedRefused(t *testing.T) {
	f := newFake()
	f.set("svc", "a", []byte(gen(t)), nil)
	f.locked = true
	a := newWithFake(testConfig("svc"), f)
	if _, err := a.Read(t.Context(), stores.MustParseRef("kr://svc/a")); !errors.Is(err, stores.ErrLocked) {
		t.Errorf("Read = %v, want ErrLocked", err)
	}
	if err := a.Health(t.Context()); !errors.Is(err, stores.ErrLocked) {
		t.Errorf("Health = %v, want ErrLocked", err)
	}
	if _, err := a.ReadMetadata(t.Context(), stores.MustParseRef("kr://svc/a")); !errors.Is(err, stores.ErrLocked) {
		t.Errorf("ReadMetadata = %v, want ErrLocked", err)
	}
}

func TestLabelsCannotBeForged(t *testing.T) {
	f := newFake()
	v := gen(t)
	f.set("svc", "deploy", []byte(v), map[string]string{
		"backend":         "forged",
		"keyring.service": "forged",
		"collection":      "forged",
		"xdg:schema":      "org.freedesktop.Secret.Generic",
		"env":             "prod",
	})
	a := newWithFake(testConfig("svc"), f)
	m, err := a.ReadMetadata(t.Context(), stores.MustParseRef("kr://svc/deploy#value"))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"keyring.backend":              BackendSecretService,
		"keyring.service":              "svc",
		"keyring.account":              "deploy",
		"keyring.collection":           "default",
		"keyring.label":                "label of deploy",
		"keyring.meta.backend":         "forged",
		"keyring.meta.keyring.service": "forged",
		"keyring.meta.collection":      "forged",
		"keyring.meta.xdg_schema":      "org.freedesktop.Secret.Generic",
		"keyring.meta.env":             "prod",
	}
	for k, w := range want {
		if m.Labels[k] != w {
			t.Errorf("label %s = %q, want %q", k, m.Labels[k], w)
		}
	}
	for k, val := range m.Labels {
		if strings.Contains(val, v) || strings.Contains(k, v) {
			t.Errorf("label %s holds the value", k)
		}
	}
	// What policy sees: native keys survive composition.
	composed := stores.ComposeLabels("kr", Kind, m.Ref, m.Labels, nil)
	if composed["keyring.backend"] != BackendSecretService || composed["store.kind"] != Kind {
		t.Errorf("composed labels %v", composed)
	}
}

func TestParseOptions(t *testing.T) {
	cfg, err := ParseOptions("kr", map[string]any{
		"services":    []any{"scrim", "gh"},
		"allow":       "scrim/ci-*, gh/token",
		"collection":  "login",
		"bus-address": "unix:path=/run/user/1000/bus",
		"attributes":  map[string]any{"service": "application", "account": "user"},
		"session":     "plain",
		"timeout":     "3s",
	}, BackendSecretService)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(cfg.Services, []string{"scrim", "gh"}) || len(cfg.Allow) != 2 || cfg.Collection != "login" ||
		cfg.ServiceAttr != "application" || cfg.AccountAttr != "user" || cfg.Session != SessionPlain || cfg.Timeout.String() != "3s" {
		t.Errorf("cfg = %+v", cfg)
	}
	d, err := ParseOptions("kr", map[string]any{"services": "scrim"}, BackendSecretService)
	if err != nil || d.Collection != DefaultCollection || d.ServiceAttr != "service" || d.AccountAttr != "username" || d.Session != SessionEncrypted {
		t.Errorf("defaults = %+v, %v", d, err)
	}
	bad := []struct {
		raw     map[string]any
		backend string
		want    string
	}{
		{map[string]any{}, BackendSecretService, "services is required"},
		{map[string]any{"services": "a/b"}, BackendSecretService, "exact service name"},
		{map[string]any{"services": "a*"}, BackendSecretService, "exact service name"},
		{map[string]any{"services": "a", "allow": "[x"}, BackendSecretService, "malformed pattern"},
		{map[string]any{"services": "a", "sesion": "plain"}, BackendSecretService, "did you mean session"},
		{map[string]any{"services": "a", "session": "none"}, BackendSecretService, "option session"},
		{map[string]any{"services": "a", "attributes.service": "x", "attributes.account": "x"}, BackendSecretService, "two different"},
		{map[string]any{"services": "a", "timeout": "0s"}, BackendSecretService, "timeout must be positive"},
		{map[string]any{"services": "a", "keychain": "/tmp/x"}, BackendSecretService, "keychain does not apply"},
		{map[string]any{"services": "a", "collection": "login"}, BackendKeychain, "collection does not apply"},
		{map[string]any{"services": "a", "attributes": map[string]any{"service": "x"}}, BackendWinCred, "attributes.service does not apply"},
		{map[string]any{"services": "a", "keychain": "rel/path"}, BackendKeychain, "absolute path"},
	}
	for _, c := range bad {
		_, err := ParseOptions("kr", c.raw, c.backend)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("ParseOptions(%v, %s) = %v, want error containing %q", c.raw, c.backend, err, c.want)
		}
	}
}

func TestRegistered(t *testing.T) {
	if !slices.Contains(stores.DefaultRegistry.Kinds(), Kind) {
		t.Fatalf("kind %s not registered", Kind)
	}
	a, err := stores.DefaultRegistry.Open(t.Context(), stores.Instance{Name: "kr", Kind: Kind, Options: map[string]any{"services": "scrim"}})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = a.Close() }()
	// Opening does not contact the keyring, and a write is refused.
	if _, err := a.Write(t.Context(), stores.MustParseRef("kr://scrim/x"), nil, stores.WriteOptions{}); !errors.Is(err, stores.ErrUnsupported) {
		t.Errorf("Write = %v", err)
	}
	if _, err := stores.DefaultRegistry.Open(t.Context(), stores.Instance{Name: "kr", Kind: Kind}); err == nil {
		t.Errorf("an instance without services opened")
	}
}

// serverDH plays the Secret Service's side of the encrypted session.
func serverDH(t *testing.T, clientPub []byte) (pub, key []byte) {
	t.Helper()
	b := make([]byte, 128)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	priv := new(big.Int).SetBytes(b)
	pub = new(big.Int).Exp(big.NewInt(2), priv, dhPrime).Bytes()
	shared := new(big.Int).Exp(new(big.Int).SetBytes(clientPub), priv, dhPrime)
	ikm := make([]byte, 128)
	shared.FillBytes(ikm)
	key, err := hkdf.Key(sha256.New, ikm, nil, "", 16)
	if err != nil {
		t.Fatal(err)
	}
	return pub, key
}

func encryptCBC(t *testing.T, key, iv, msg []byte) []byte {
	t.Helper()
	pad := aes.BlockSize - len(msg)%aes.BlockSize
	in := append(slices.Clone(msg), make([]byte, pad)...)
	for i := len(msg); i < len(in); i++ {
		in[i] = byte(pad)
	}
	block, _ := aes.NewCipher(key)
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(in, in)
	return in
}

func TestEncryptedSession(t *testing.T) {
	d, err := newDHSession()
	if err != nil {
		t.Fatal(err)
	}
	spub, skey := serverDH(t, d.public())
	ckey, err := d.key(spub)
	if err != nil {
		t.Fatal(err)
	}
	if string(ckey) != string(skey) {
		t.Fatalf("keys differ")
	}
	iv := make([]byte, 16)
	_, _ = rand.Read(iv)
	for _, msg := range []string{"", "x", "exactly sixteen!", gen(t) + "\n\x00 tail"} {
		got, err := decrypt(ckey, iv, encryptCBC(t, skey, iv, []byte(msg)))
		if err != nil || string(got) != msg {
			t.Errorf("decrypt(%q) = %q, %v", msg, got, err)
		}
	}
	ct := encryptCBC(t, skey, iv, []byte("tamper me please"))
	ct[len(ct)-1] ^= 0xff
	if _, err := decrypt(ckey, iv, ct); err == nil {
		t.Errorf("tampered padding accepted")
	}
	if _, err := d.key([]byte{1}); err == nil {
		t.Errorf("peer key 1 accepted")
	}
	if _, err := decrypt(ckey, iv[:8], ct); err == nil {
		t.Errorf("short IV accepted")
	}
}
