// SPDX-License-Identifier: AGPL-3.0-only

package keyring

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/heliopsy/scrim/internal/testing/testpodman"

	"github.com/godbus/dbus/v5"

	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores"
	"github.com/heliopsy/scrim/internal/stores/storetest"
)

// The integration run talks to a real gnome-keyring on a private D-Bus
// session bus inside a rootless podman container (testdata/secretservice),
// never to the host's session bus or the user's keyring: the adapter gets
// the container's bus through the bus-address option, published on
// 127.0.0.1 only. The container and the image it builds are named
// scrim-keyring-* and removed when the test ends.

const keyringImage = "localhost/scrim-keyring-secretservice:test"

// requirePodman skips without podman unless SCRIM_TEST_PODMAN=1 demands
// the run, as CI does.
func requirePodman(t *testing.T) {
	t.Helper()
	if testing.Short() {
		t.Skip("-short: skipping the Secret Service run, which needs podman")
	}
	mode := os.Getenv("SCRIM_TEST_PODMAN")
	if mode == "0" {
		t.Skip("SCRIM_TEST_PODMAN=0: skipping the Secret Service run")
	}
	if _, err := exec.LookPath("podman"); err != nil {
		if mode == "1" {
			t.Fatal("SCRIM_TEST_PODMAN=1 but podman is not installed")
		}
		t.Skip("podman not installed: skipping the Secret Service run (set SCRIM_TEST_PODMAN=1 to require it)")
	}
	if out, err := testpodman.Command("info", "--format", "{{.Host.Security.Rootless}}").CombinedOutput(); err != nil {
		if mode == "1" {
			t.Fatalf("SCRIM_TEST_PODMAN=1 but podman does not work: %v: %s", err, out)
		}
		t.Skipf("podman does not work: %v", err)
	}
}

func podman(t *testing.T, env []string, args ...string) string {
	t.Helper()
	cmd := testpodman.Command(args...)
	cmd.Env = append(os.Environ(), env...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("podman %s: %v: %s", args[0], err, out)
	}
	return strings.TrimSpace(string(out))
}

// secretServiceContainer is a running throwaway Secret Service.
type secretServiceContainer struct {
	name     string
	addr     string
	password string
}

func startSecretService(t *testing.T) *secretServiceContainer {
	t.Helper()
	requirePodman(t)
	podman(t, nil, "build", "-q", "-t", keyringImage, "testdata/secretservice")
	t.Cleanup(func() { _ = testpodman.Command("rmi", "-f", keyringImage).Run() })
	c := &secretServiceContainer{name: "scrim-keyring-" + gen(t)[3:15], password: gen(t)}
	// The keyring password goes through podman's environment, not argv.
	podman(t, []string{"KEYRING_PASSWORD=" + c.password}, "run", "-d", "--name", c.name,
		"-e", "KEYRING_PASSWORD", "-p", "127.0.0.1::7777", keyringImage)
	t.Cleanup(func() { _ = testpodman.Command("rm", "-f", "-v", "-t", "2", c.name).Run() })
	hostport := strings.SplitN(podman(t, nil, "port", c.name, "7777"), "\n", 2)[0]
	host, port, _ := strings.Cut(strings.TrimSpace(hostport), ":")
	c.addr = fmt.Sprintf("tcp:host=%s,port=%s", host, port)
	deadline := time.Now().Add(60 * time.Second)
	for {
		conn, err := c.dial(t)
		if err == nil {
			var p dbus.ObjectPath
			err = conn.Object(ssDest, ssPath).Call(ssService+".ReadAlias", 0, "default").Store(&p)
			_ = conn.Close()
			if err == nil && p != "/" {
				return c
			}
		}
		if time.Now().After(deadline) {
			logs, _ := testpodman.Command("logs", c.name).CombinedOutput()
			t.Fatalf("Secret Service not ready: %v\n%s", err, logs)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func (c *secretServiceContainer) dial(t *testing.T) (*dbus.Conn, error) {
	t.Helper()
	return dbus.Connect(c.addr, dbus.WithAuth(dbus.AuthAnonymous()))
}

// admin is the test's own out-of-band client: it creates, deletes, locks
// and unlocks what the read-only adapter cannot.
type admin struct {
	t       *testing.T
	c       *secretServiceContainer
	conn    *dbus.Conn
	session dbus.ObjectPath
}

func (c *secretServiceContainer) admin(t *testing.T) *admin {
	t.Helper()
	conn, err := c.dial(t)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	var out dbus.Variant
	var session dbus.ObjectPath
	if err := conn.Object(ssDest, ssPath).Call(ssService+".OpenSession", 0, "plain", dbus.MakeVariant("")).Store(&out, &session); err != nil {
		t.Fatal(err)
	}
	return &admin{t: t, c: c, conn: conn, session: session}
}

func (a *admin) alias(name string) dbus.ObjectPath {
	var p dbus.ObjectPath
	if err := a.conn.Object(ssDest, ssPath).Call(ssService+".ReadAlias", 0, name).Store(&p); err != nil {
		a.t.Fatal(err)
	}
	return p
}

func (a *admin) secret(v []byte) secretStruct {
	return secretStruct{Session: a.session, Parameters: []byte{}, Value: v, ContentType: "text/plain"}
}

// create stores an item (replacing one with the same attributes) in coll.
func (a *admin) create(coll dbus.ObjectPath, label string, attrs map[string]string, v []byte) dbus.ObjectPath {
	props := map[string]dbus.Variant{
		ssItem + ".Label":      dbus.MakeVariant(label),
		ssItem + ".Attributes": dbus.MakeVariant(attrs),
	}
	var item, prompt dbus.ObjectPath
	if err := a.conn.Object(ssDest, coll).Call(ssCollection+".CreateItem", 0, props, a.secret(v), true).Store(&item, &prompt); err != nil {
		a.t.Fatalf("CreateItem: %v", err)
	}
	if prompt != "/" {
		a.t.Fatalf("CreateItem asked for a prompt")
	}
	return item
}

func (a *admin) deleteItems(coll dbus.ObjectPath, attrs map[string]string) {
	var unlocked, locked []dbus.ObjectPath
	if err := a.conn.Object(ssDest, ssPath).Call(ssService+".SearchItems", 0, attrs).Store(&unlocked, &locked); err != nil {
		a.t.Fatal(err)
	}
	for _, p := range unlocked {
		if !inCollection(coll, p) {
			continue
		}
		var prompt dbus.ObjectPath
		if err := a.conn.Object(ssDest, p).Call(ssItem+".Delete", 0).Store(&prompt); err != nil {
			a.t.Fatalf("Delete: %v", err)
		}
	}
}

func (a *admin) lock(coll dbus.ObjectPath) {
	var locked []dbus.ObjectPath
	var prompt dbus.ObjectPath
	if err := a.conn.Object(ssDest, ssPath).Call(ssService+".Lock", 0, []dbus.ObjectPath{coll}).Store(&locked, &prompt); err != nil {
		a.t.Fatalf("Lock: %v", err)
	}
	if len(locked) != 1 {
		a.t.Fatalf("Lock locked %v, prompt %s", locked, prompt)
	}
}

// guilt is gnome-keyring's interface for unlocking and creating collections
// without a prompt, meant for exactly this kind of test.
const guilt = "org.gnome.keyring.InternalUnsupportedGuiltRiddenInterface"

func (a *admin) unlock(coll dbus.ObjectPath, password string) {
	if err := a.conn.Object(ssDest, ssPath).Call(guilt+".UnlockWithMasterPassword", 0, coll, a.secret([]byte(password))).Err; err != nil {
		a.t.Fatalf("UnlockWithMasterPassword: %v", err)
	}
}

func (a *admin) createCollection(label, password string) dbus.ObjectPath {
	props := map[string]dbus.Variant{ssCollection + ".Label": dbus.MakeVariant(label)}
	var p dbus.ObjectPath
	if err := a.conn.Object(ssDest, ssPath).Call(guilt+".CreateWithMasterPassword", 0, props, a.secret([]byte(password))).Store(&p); err != nil {
		a.t.Fatalf("CreateWithMasterPassword: %v", err)
	}
	return p
}

func (c *secretServiceContainer) adapter(t storetest.TB, opts map[string]any) *Adapter {
	raw := map[string]any{"services": "scrim-conformance", "bus-address": c.addr, "timeout": "3s"}
	for k, v := range opts {
		raw[k] = v
	}
	cfg, err := ParseOptions("kr", raw, BackendSecretService)
	if err != nil {
		t.Fatalf("options: %v", err)
	}
	a, err := New("kr", cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return a
}

func TestSecretService(t *testing.T) {
	c := startSecretService(t)
	adm := c.admin(t)
	login := adm.alias("default")
	attrs := func(ref stores.Ref) map[string]string {
		s, acct, _ := strings.Cut(ref.Path, "/")
		return map[string]string{"service": s, "username": acct}
	}
	harness := func(opts map[string]any) storetest.Factory {
		return func(t storetest.TB) storetest.Harness {
			return storetest.Harness{
				Adapter:     c.adapter(t, opts),
				SingleField: Field,
				Seed: func(t storetest.TB, ref stores.Ref, fields map[string]secret.Value) {
					_ = fields[Field].Expose(func(b []byte) error {
						adm.create(login, "scrim test "+ref.Path, attrs(ref), b)
						return nil
					})
				},
				Delete: func(t storetest.TB, ref stores.Ref) { adm.deleteItems(login, attrs(ref)) },
				Outage: func(t storetest.TB) func() {
					podman(adm.t, nil, "pause", c.name)
					return func() { podman(adm.t, nil, "unpause", c.name) }
				},
			}
		}
	}

	t.Run("Conformance", func(t *testing.T) { storetest.Run(t, harness(nil)) })
	t.Run("ConformancePlainSession", func(t *testing.T) {
		storetest.Run(t, harness(map[string]any{"session": SessionPlain}))
	})

	t.Run("LabelsAndMetadata", func(t *testing.T) {
		v := gen(t)
		adm.create(login, "Deploy key", map[string]string{
			"service": "scrim-conformance", "username": "labels/deploy",
			"collection": "forged", "keyring.backend": "forged", "env": "prod",
		}, []byte(v))
		a := c.adapter(t, nil)
		defer func() { _ = a.Close() }()
		ref := stores.MustParseRef("kr://scrim-conformance/labels/deploy")
		m, err := a.ReadMetadata(t.Context(), ref)
		if err != nil {
			t.Fatal(err)
		}
		want := map[string]string{
			"keyring.backend": BackendSecretService, "keyring.service": "scrim-conformance",
			"keyring.account": "labels/deploy", "keyring.collection": "default", "keyring.label": "Deploy key",
			"keyring.meta.collection": "forged", "keyring.meta.keyring.backend": "forged", "keyring.meta.env": "prod",
		}
		for k, w := range want {
			if m.Labels[k] != w {
				t.Errorf("label %s = %q, want %q", k, m.Labels[k], w)
			}
		}
		if m.UpdatedAt.IsZero() {
			t.Errorf("no modification time")
		}
		for k, val := range m.Labels {
			if strings.Contains(val, v) {
				t.Errorf("label %s holds the value", k)
			}
		}
		s, err := a.Read(t.Context(), ref)
		if err != nil {
			t.Fatal(err)
		}
		defer s.Wipe()
		if got, _ := s.Field(Field); plain(got) != v {
			t.Errorf("wrong value")
		}
		if s.Meta.Labels["keyring.label"] != "Deploy key" {
			t.Errorf("Read labels %v", s.Meta.Labels)
		}
	})

	t.Run("Ambiguous", func(t *testing.T) {
		at := map[string]string{"service": "scrim-conformance", "username": "dup"}
		adm.create(login, "one", at, []byte(gen(t)))
		at2 := map[string]string{"service": "scrim-conformance", "username": "dup", "extra": "x"}
		adm.create(login, "two", at2, []byte(gen(t)))
		a := c.adapter(t, nil)
		defer func() { _ = a.Close() }()
		if _, err := a.Read(t.Context(), stores.MustParseRef("kr://scrim-conformance/dup")); !errors.Is(err, stores.ErrConflict) {
			t.Errorf("two matching items: %v, want ErrConflict", err)
		}
	})

	t.Run("OtherCollectionInvisible", func(t *testing.T) {
		pw := gen(t)
		other := adm.createCollection("scrim-other", pw)
		v := gen(t)
		adm.create(other, "elsewhere", map[string]string{"service": "scrim-conformance", "username": "elsewhere"}, []byte(v))
		a := c.adapter(t, nil)
		defer func() { _ = a.Close() }()
		ref := stores.MustParseRef("kr://scrim-conformance/elsewhere")
		if _, err := a.Read(t.Context(), ref); !errors.Is(err, stores.ErrNotFound) {
			t.Errorf("item in another collection: %v, want not found", err)
		}
		byLabel := c.adapter(t, map[string]any{"collection": "scrim-other"})
		defer func() { _ = byLabel.Close() }()
		s, err := byLabel.Read(t.Context(), ref)
		if err != nil {
			t.Fatalf("read through collection label: %v", err)
		}
		defer s.Wipe()
		if got, _ := s.Field(Field); plain(got) != v || s.Meta.Labels["keyring.collection"] != "scrim-other" {
			t.Errorf("wrong value or labels %v", s.Meta.Labels)
		}
		missing := c.adapter(t, map[string]any{"collection": "no-such-collection"})
		defer func() { _ = missing.Close() }()
		if err := missing.Health(t.Context()); !errors.Is(err, stores.ErrNotFound) {
			t.Errorf("Health with a missing collection: %v", err)
		}
	})

	t.Run("OutsideServicesNeverRead", func(t *testing.T) {
		adm.create(login, "browser", map[string]string{"service": "browser", "username": "me"}, []byte(gen(t)))
		a := c.adapter(t, nil)
		defer func() { _ = a.Close() }()
		if _, err := a.Read(t.Context(), stores.MustParseRef("kr://browser/me")); !errors.Is(err, stores.ErrNotFound) {
			t.Errorf("service outside services: %v, want not found", err)
		}
	})

	// Last: locks the login collection.
	t.Run("LockedRefusedWithoutPrompt", func(t *testing.T) {
		v := gen(t)
		adm.create(login, "locked", map[string]string{"service": "scrim-conformance", "username": "locked"}, []byte(v))
		a := c.adapter(t, nil)
		defer func() { _ = a.Close() }()
		ref := stores.MustParseRef("kr://scrim-conformance/locked")
		adm.lock(login)
		defer adm.unlock(login, c.password)
		start := time.Now()
		_, err := a.Read(t.Context(), ref)
		if !errors.Is(err, stores.ErrLocked) {
			t.Fatalf("Read of a locked keyring: %v, want ErrLocked", err)
		}
		if time.Since(start) > 2*time.Second {
			t.Errorf("Read of a locked keyring took %s; it must refuse at once, not wait for a prompt", time.Since(start))
		}
		if strings.Contains(err.Error(), v) {
			t.Errorf("error holds the value")
		}
		if err := a.Health(t.Context()); !errors.Is(err, stores.ErrLocked) {
			t.Errorf("Health = %v, want ErrLocked", err)
		}
		if _, err := a.List(t.Context(), stores.MustParseRef("kr://scrim-conformance")); !errors.Is(err, stores.ErrLocked) {
			t.Errorf("List = %v, want ErrLocked", err)
		}
		if _, err := a.ReadMetadata(t.Context(), ref); !errors.Is(err, stores.ErrLocked) {
			t.Errorf("ReadMetadata = %v, want ErrLocked", err)
		}
		// Still locked: scrim did not unlock it or leave a prompt behind.
		locked, err := getProp[bool](t.Context(), adm.conn, login, ssCollection, "Locked")
		if err != nil || !locked {
			t.Errorf("collection Locked = %v, %v after the refused reads", locked, err)
		}
	})
}
