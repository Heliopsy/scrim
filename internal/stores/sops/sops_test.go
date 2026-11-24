// SPDX-License-Identifier: AGPL-3.0-only

package sops

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"filippo.io/age"

	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores"
	"github.com/heliopsy/scrim/internal/stores/storetest"
)

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
	return "sops_" + hex.EncodeToString(b)
}

// identity generates a throwaway age identity for one test.
func identity(t testing.TB) *age.X25519Identity {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// resolverFor resolves any reference to the identity's key, as
// stores.Instance.Resolve would after reading `file:` or `env:`.
func resolverFor(id *age.X25519Identity) Resolver {
	return func(context.Context, config.SecretRef) (secret.Value, error) {
		return secret.FromString("# test-only throwaway key\n" + id.String() + "\n"), nil
	}
}

func writeAtomic(t storetest.TB, tmp, path string, data []byte) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	f, err := os.CreateTemp(tmp, "seed")
	if err != nil {
		t.Fatalf("temp: %v", err)
	}
	if _, err := f.Write(data); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = f.Close()
	if err := os.Rename(f.Name(), path); err != nil {
		t.Fatalf("rename: %v", err)
	}
}

func newAdapter(t *testing.T, cfg Config, id *age.X25519Identity) (*Adapter, string) {
	t.Helper()
	if cfg.Root == "" {
		cfg.Root = t.TempDir()
	}
	cfg.AgeIdentity = "env:SOPS_TEST_IDENTITY"
	a, err := New("vault-files", cfg, resolverFor(id))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	return a, cfg.Root
}

func put(t *testing.T, root, rel string, b []byte) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func ref(path string) stores.Ref { return stores.MustParseRef("vault-files://" + path) }

func harness(t *testing.T, f Format) storetest.Factory {
	return func(storetest.TB) storetest.Harness {
		root, tmp := t.TempDir(), t.TempDir()
		id := identity(t)
		a, err := New("sops", Config{Root: root, Format: f, AgeIdentity: "env:X", WatchInterval: 50 * time.Millisecond}, resolverFor(id))
		if err != nil {
			t.Fatal(err)
		}
		return storetest.Harness{
			Adapter: a,
			Seed: func(t storetest.TB, ref stores.Ref, fields map[string]secret.Value) {
				m := map[string]string{}
				for k, v := range fields {
					m[k] = plain(v)
				}
				b := encryptFile(t, f, flatDoc(m), encOptions{recipients: []*age.X25519Recipient{id.Recipient()}})
				writeAtomic(t, tmp, filepath.Join(root, ref.Path), b)
			},
			Delete: func(t storetest.TB, ref stores.Ref) {
				if err := os.Remove(filepath.Join(root, ref.Path)); err != nil {
					t.Fatalf("delete: %v", err)
				}
			},
			WatchTimeout: 3 * time.Second,
		}
	}
}

func TestConformanceYAML(t *testing.T)   { storetest.Run(t, harness(t, FormatYAML)) }
func TestConformanceJSON(t *testing.T)   { storetest.Run(t, harness(t, FormatJSON)) }
func TestConformanceDotenv(t *testing.T) { storetest.Run(t, harness(t, FormatDotenv)) }

// nested is a document with nesting, lists, awkward keys, unencrypted and
// non-string leaves, and the fields Read must return for it.
func nested(t *testing.T) (*node, map[string]string) {
	s := func(v string) *node { return &node{kind: kindLeaf, str: true, text: v} }
	pw, tok0, tok1, odd, tilde := gen(t), gen(t), gen(t), gen(t), gen(t)
	db := newMap()
	db.set("password", s(pw))
	db.set("host_unencrypted", s("db.internal"))
	db.set("port_unencrypted", &node{kind: kindLeaf, text: "5432"})
	db.set("tls_unencrypted", &node{kind: kindLeaf, text: "True"})
	db.set("empty", s(""))
	db.set("none", &node{kind: kindNull})
	tok := newMap()
	tok.set("token", s(tok1))
	list := &node{kind: kindList, items: []*node{s(tok0), tok}}
	root := newMap()
	root.set("db", db)
	root.set("servers", list)
	root.set("api.example.com/v1", s(odd))
	root.set("a~b", s(tilde))
	return root, map[string]string{
		"db/password":         pw,
		"servers/0":           tok0,
		"servers/1/token":     tok1,
		"api.example.com~1v1": odd,
		"a~0b":                tilde,
	}
}

func readAll(t *testing.T, a *Adapter, path string) map[string]string {
	t.Helper()
	s, err := a.Read(t.Context(), ref(path))
	if err != nil {
		t.Fatalf("Read %s: %v", path, err)
	}
	defer s.Wipe()
	out := map[string]string{}
	for k, v := range s.Fields {
		out[k] = plain(v)
	}
	if !slices.Equal(s.Meta.Fields, sortedKeys(out)) {
		t.Errorf("Meta.Fields = %v, want %v", s.Meta.Fields, sortedKeys(out))
	}
	return out
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

func equalFields(t *testing.T, what string, got, want map[string]string) {
	t.Helper()
	if !slices.Equal(sortedKeys(got), sortedKeys(want)) {
		t.Errorf("%s: fields %v, want %v", what, sortedKeys(got), sortedKeys(want))
		return
	}
	for k, w := range want {
		if got[k] != w {
			t.Errorf("%s: field %s has the wrong value", what, k)
		}
	}
}

func TestNestedKeyPaths(t *testing.T) {
	for _, f := range []Format{FormatYAML, FormatJSON} {
		t.Run(string(f), func(t *testing.T) {
			id := identity(t)
			a, root := newAdapter(t, Config{Format: f}, id)
			doc, want := nested(t)
			put(t, root, "app/secrets", encryptFile(t, f, doc, encOptions{recipients: []*age.X25519Recipient{id.Recipient()}}))
			equalFields(t, "Read", readAll(t, a, "app/secrets"), want)

			for field, w := range want {
				s, err := a.Read(t.Context(), ref("app/secrets").WithField(field))
				if err != nil {
					t.Fatalf("Read #%s: %v", field, err)
				}
				if len(s.Fields) != 1 || plain(s.Fields[field]) != w {
					t.Errorf("Read #%s returned the wrong fields", field)
				}
				s.Wipe()
			}
			// Unencrypted leaves, empty strings and subtrees are not fields.
			for _, field := range []string{"db/host_unencrypted", "db/empty", "db", "servers", "db.password", "/db/password"} {
				_, err := a.Read(t.Context(), ref("app/secrets").WithField(field))
				if !errors.Is(err, stores.ErrNotFound) {
					t.Errorf("Read #%s: %v, want not found", field, err)
				}
			}
			m, err := a.ReadMetadata(t.Context(), ref("app/secrets#db/password"))
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(m.Fields, sortedKeys(want)) {
				t.Errorf("ReadMetadata fields = %v, want %v", m.Fields, sortedKeys(want))
			}
		})
	}
}

func TestFormats(t *testing.T) {
	id := identity(t)
	rcp := encOptions{recipients: []*age.X25519Recipient{id.Recipient()}}
	a, root := newAdapter(t, Config{}, id)

	env := map[string]string{"API_TOKEN": gen(t), "DB_PASSWORD": gen(t) + "\nsecond line"}
	put(t, root, "app/.env", encryptFile(t, FormatDotenv, flatDoc(env), rcp))
	equalFields(t, "dotenv", readAll(t, a, "app/.env"), env)

	main, other := gen(t), gen(t)
	ini := newMap()
	sec := newMap()
	sec.set("password", &node{kind: kindLeaf, str: true, text: main})
	sec.set("user_unencrypted", &node{kind: kindLeaf, str: true, text: "admin"})
	ini.set("database", sec)
	sec2 := newMap()
	sec2.set("key", &node{kind: kindLeaf, str: true, text: other})
	ini.set("other", sec2)
	// sops always writes the DEFAULT section first.
	full := newMap()
	full.set("DEFAULT", newMap())
	full.keys = append(full.keys, ini.keys...)
	full.vals = append(full.vals, ini.vals...)
	put(t, root, "app/db.ini", encryptFile(t, FormatINI, full, rcp))
	equalFields(t, "ini", readAll(t, a, "app/db.ini"), map[string]string{"database/password": main, "other/key": other})

	y := map[string]string{"token": gen(t)}
	put(t, root, "app/token.yaml", encryptFile(t, FormatYAML, flatDoc(y), rcp))
	equalFields(t, "yaml", readAll(t, a, "app/token.yaml"), y)
	put(t, root, "app/token.yml", encryptFile(t, FormatYAML, flatDoc(y), rcp))
	equalFields(t, "yml", readAll(t, a, "app/token.yml"), y)

	j := map[string]string{"token": gen(t)}
	put(t, root, "app/token.json", encryptFile(t, FormatJSON, flatDoc(j), rcp))
	equalFields(t, "json", readAll(t, a, "app/token.json"), j)

	// A binary file is a JSON document with a data key, under any name.
	bin := map[string]string{"data": gen(t) + "\x00\x01"}
	put(t, root, "app/cert.pem", encryptFile(t, FormatJSON, flatDoc(bin), rcp))
	equalFields(t, "binary", readAll(t, a, "app/cert.pem"), bin)
}

func TestEncryptionRules(t *testing.T) {
	cases := []struct {
		rule, value string
		macOnly     bool
	}{
		{"encrypted_regex", "^(password|token)$", false},
		{"unencrypted_regex", "^public", false},
		{"encrypted_suffix", "_secret", false},
		{"unencrypted_suffix", "_plain", true},
	}
	for _, c := range cases {
		t.Run(c.rule, func(t *testing.T) {
			id := identity(t)
			a, root := newAdapter(t, Config{Format: FormatYAML}, id)
			pw, tok, sec := gen(t), gen(t), gen(t)
			doc := flatDoc(map[string]string{
				"password": pw, "token": tok, "api_secret": sec,
				"public_name": "visible", "note_plain": "visible",
			})
			b := encryptFile(t, FormatYAML, doc, encOptions{
				recipients: []*age.X25519Recipient{id.Recipient()}, rule: c.rule, ruleValue: c.value, macOnly: c.macOnly,
			})
			put(t, root, "f.yaml", b)
			got := readAll(t, a, "f.yaml")
			want := map[string]string{}
			switch c.rule {
			case "encrypted_regex":
				want = map[string]string{"password": pw, "token": tok}
			case "unencrypted_regex", "unencrypted_suffix":
				want = map[string]string{"password": pw, "token": tok, "api_secret": sec}
				if c.rule == "unencrypted_regex" {
					want["note_plain"] = "visible"
				} else {
					want["public_name"] = "visible"
				}
			case "encrypted_suffix":
				want = map[string]string{"api_secret": sec}
			}
			equalFields(t, c.rule, got, want)
			for k, w := range want {
				if w != "visible" && strings.Contains(string(b), w) {
					t.Fatalf("generated fixture holds the plaintext of %s", k)
				}
			}
		})
	}
}

// tamper reads a file, applies fn and writes it back.
func tamper(t *testing.T, path string, fn func(string) string) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	out := fn(string(b))
	if out == string(b) {
		t.Fatal("tamper changed nothing")
	}
	if err := os.WriteFile(path, []byte(out), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestIntegrityFailuresAreRefused(t *testing.T) {
	id := identity(t)
	rcp := []*age.X25519Recipient{id.Recipient()}
	a, root := newAdapter(t, Config{Format: FormatYAML}, id)
	a1, a2 := gen(t), gen(t)
	fresh := func(name string, o encOptions) string {
		o.recipients = rcp
		doc := flatDoc(map[string]string{"alpha": a1, "beta": a2, "label_unencrypted": "public"})
		put(t, root, name, encryptFile(t, FormatYAML, doc, o))
		return filepath.Join(root, name)
	}
	encOf := func(s, key string) string {
		i := strings.Index(s, key+": ENC[")
		rest := s[i+len(key)+2:]
		return rest[:strings.IndexByte(rest, '\n')]
	}
	cases := []struct {
		name string
		make func() string
	}{
		{"wrong MAC", func() string { return fresh("mac.yaml", encOptions{tamperMAC: true}) }},
		{"empty MAC", func() string { return fresh("nomac.yaml", encOptions{noMAC: true}) }},
		{"values swapped between keys", func() string {
			p := fresh("swap.yaml", encOptions{})
			tamper(t, p, func(s string) string {
				x, y := encOf(s, "alpha"), encOf(s, "beta")
				s = strings.Replace(s, x, "SWAP", 1)
				s = strings.Replace(s, y, x, 1)
				return strings.Replace(s, "SWAP", y, 1)
			})
			return p
		}},
		{"value removed", func() string {
			p := fresh("removed.yaml", encOptions{})
			tamper(t, p, func(s string) string { return strings.Replace(s, "beta: "+encOf(s, "beta")+"\n", "", 1) })
			return p
		}},
		{"unencrypted leaf changed", func() string {
			p := fresh("plain.yaml", encOptions{})
			tamper(t, p, func(s string) string { return strings.Replace(s, "public", "changed", 1) })
			return p
		}},
		{"ciphertext flipped", func() string {
			p := fresh("flip.yaml", encOptions{})
			tamper(t, p, func(s string) string {
				x := encOf(s, "alpha")
				i := strings.Index(x, "data:") + 5
				c := byte('A')
				if x[i] == 'A' {
					c = 'B'
				}
				return strings.Replace(s, x, x[:i]+string(c)+x[i+1:], 1)
			})
			return p
		}},
		{"lastmodified changed", func() string {
			p := fresh("lastmod.yaml", encOptions{})
			tamper(t, p, func(s string) string {
				i := strings.Index(s, "lastmodified: ")
				line := s[i : i+strings.IndexByte(s[i:], '\n')]
				return strings.Replace(s, line, `lastmodified: "2001-02-03T04:05:06Z"`, 1)
			})
			return p
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := c.make()
			rel, _ := filepath.Rel(root, p)
			for _, r := range []stores.Ref{ref(rel), ref(rel).WithField("alpha")} {
				s, err := a.Read(t.Context(), r)
				if err == nil {
					s.Wipe()
					t.Fatalf("Read %s of a tampered file succeeded", r)
				}
				if !errors.Is(err, stores.ErrPermission) {
					t.Errorf("Read %s: %v, want a permission error", r, err)
				}
				assertNoLeak(t, err, a1, a2)
			}
		})
	}
}

func TestWrongKey(t *testing.T) {
	owner, other := identity(t), identity(t)
	a, root := newAdapter(t, Config{Format: FormatYAML}, other)
	v := gen(t)
	put(t, root, "f.yaml", encryptFile(t, FormatYAML, flatDoc(map[string]string{"k": v}), encOptions{recipients: []*age.X25519Recipient{owner.Recipient()}}))
	_, err := a.Read(t.Context(), ref("f.yaml"))
	if !errors.Is(err, stores.ErrPermission) || !strings.Contains(err.Error(), "no configured age identity") {
		t.Fatalf("Read with the wrong key: %v", err)
	}
	assertNoLeak(t, err, v, other.String(), owner.String())
	// Metadata needs no key.
	if m, err := a.ReadMetadata(t.Context(), ref("f.yaml")); err != nil || !slices.Equal(m.Fields, []string{"k"}) {
		t.Errorf("ReadMetadata = %v, %v", m, err)
	}
	// A file for several recipients opens with any one of them.
	put(t, root, "g.yaml", encryptFile(t, FormatYAML, flatDoc(map[string]string{"k": v}),
		encOptions{recipients: []*age.X25519Recipient{owner.Recipient(), other.Recipient()}}))
	equalFields(t, "second recipient", readAll(t, a, "g.yaml"), map[string]string{"k": v})
}

func assertNoLeak(t *testing.T, x any, values ...string) {
	t.Helper()
	var texts []string
	if err, ok := x.(error); ok {
		for e := err; e != nil; {
			texts = append(texts, e.Error())
			switch u := e.(type) {
			case interface{ Unwrap() []error }:
				for _, c := range u.Unwrap() {
					texts = append(texts, fmt.Sprintf("%v", c))
				}
				e = nil
			case interface{ Unwrap() error }:
				e = u.Unwrap()
			default:
				e = nil
			}
		}
	}
	texts = append(texts, fmt.Sprintf("%+v", x), fmt.Sprintf("%#v", x))
	for _, s := range texts {
		for _, v := range values {
			if v != "" && strings.Contains(s, v) {
				t.Errorf("output contains a secret value: %q", s)
			}
		}
	}
}

func TestWriteIsRefusedBeforeAnything(t *testing.T) {
	id := identity(t)
	a, root := newAdapter(t, Config{}, id)
	v := gen(t)
	_, err := a.Write(t.Context(), ref("new.yaml#k"), map[string]secret.Value{"k": secret.FromString(v)}, stores.WriteOptions{})
	if !errors.Is(err, stores.ErrUnsupported) || !strings.Contains(err.Error(), "sops source is read-only") {
		t.Fatalf("Write: %v", err)
	}
	assertNoLeak(t, err, v)
	if entries, _ := os.ReadDir(root); len(entries) != 0 {
		t.Errorf("Write left %d entries in the root", len(entries))
	}
	if a.Capabilities().Has(stores.CapWrite) {
		t.Error("sops source declares write")
	}
	set := stores.NewSet()
	if err := set.Add(a); err != nil {
		t.Fatal(err)
	}
	if _, err := set.Write(t.Context(), ref("new.yaml"), nil, stores.WriteOptions{}); !errors.Is(err, stores.ErrUnsupported) {
		t.Errorf("Set.Write: %v", err)
	}
}

func TestNativeLabels(t *testing.T) {
	id, second := identity(t), identity(t)
	a, root := newAdapter(t, Config{}, id)
	v := gen(t)
	put(t, root, "app/db.yaml", encryptFile(t, FormatYAML, flatDoc(map[string]string{"password": v}), encOptions{
		recipients: []*age.X25519Recipient{id.Recipient(), second.Recipient()}, rule: "encrypted_regex", ruleValue: "^password$", macOnly: true,
	}))
	s, err := a.Read(t.Context(), ref("app/db.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	s.Wipe()
	m, err := a.ReadMetadata(t.Context(), ref("app/db.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	ls, err := a.List(t.Context(), ref("app"))
	if err != nil || len(ls) != 1 {
		t.Fatalf("List: %v %v", ls, err)
	}
	r1, r2 := id.Recipient().String(), second.Recipient().String()
	want := map[string]string{
		"sops.root":                root,
		"sops.path":                filepath.Join(root, "app", "db.yaml"),
		"sops.format":              "yaml",
		"sops.version":             "3.12.1",
		"sops.mac-only-encrypted":  "true",
		"sops.key-type":            "age",
		"sops.key-type.age":        "true",
		"sops.age-recipient":       r1 + "," + r2,
		"sops.age-recipient." + r1: "true",
		"sops.age-recipient." + r2: "true",
		"sops.encrypted-regex":     "^password$",
	}
	for _, l := range []map[string]string{s.Meta.Labels, m.Labels, ls[0].Labels} {
		for k, w := range want {
			if l[k] != w {
				t.Errorf("label %s = %q, want %q", k, l[k], w)
			}
		}
		if _, err := time.Parse(time.RFC3339, l["sops.lastmodified"]); err != nil {
			t.Errorf("sops.lastmodified = %q", l["sops.lastmodified"])
		}
		for k, val := range l {
			if !strings.HasPrefix(k, "sops.") {
				t.Errorf("label %s outside the sops. namespace", k)
			}
			assertNoLeak(t, k+"="+val, v, id.String(), second.String())
		}
	}
	if !slices.Equal(ls[0].Fields, []string{"password"}) {
		t.Errorf("List fields = %v", ls[0].Fields)
	}
}

func TestNoValueInErrorsListsOrMetadata(t *testing.T) {
	id := identity(t)
	a, root := newAdapter(t, Config{}, id)
	v1, v2 := gen(t), gen(t)
	put(t, root, "a.yaml", encryptFile(t, FormatYAML, flatDoc(map[string]string{"one": v1, "two": v2}), encOptions{recipients: []*age.X25519Recipient{id.Recipient()}}))
	var outputs []any
	_, err := a.Read(t.Context(), ref("a.yaml#missing"))
	if !errors.Is(err, stores.ErrNotFound) {
		t.Errorf("missing field: %v", err)
	}
	outputs = append(outputs, err)
	s, err := a.Read(t.Context(), ref("a.yaml#one"))
	if err != nil {
		t.Fatal(err)
	}
	outputs = append(outputs, s.Meta, s, fmt.Sprint(s.Fields))
	s.Wipe()
	m, err := a.ReadMetadata(t.Context(), ref("a.yaml"))
	outputs = append(outputs, m, err)
	l, err := a.List(t.Context(), ref("a.yaml"))
	outputs = append(outputs, l, err)
	for _, o := range outputs {
		assertNoLeak(t, o, v1, v2, id.String())
	}
}

func TestIdentityHandling(t *testing.T) {
	id := identity(t)
	root := t.TempDir()
	v := gen(t)
	put(t, root, "f.yaml", encryptFile(t, FormatYAML, flatDoc(map[string]string{"k": v}), encOptions{recipients: []*age.X25519Recipient{id.Recipient()}}))

	t.Run("resolve fails", func(t *testing.T) {
		a, err := New("s", Config{Root: root, AgeIdentity: "env:MISSING"}, func(context.Context, config.SecretRef) (secret.Value, error) {
			return secret.Value{}, errors.New("env:MISSING is not set")
		})
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = a.Close() }()
		if _, err := a.Read(t.Context(), ref("f.yaml")); !errors.Is(err, stores.ErrLocked) {
			t.Errorf("Read: %v, want locked", err)
		}
		if err := a.Health(t.Context()); !errors.Is(err, stores.ErrLocked) {
			t.Errorf("Health: %v, want locked", err)
		}
		if _, err := a.ReadMetadata(t.Context(), ref("f.yaml")); err != nil {
			t.Errorf("ReadMetadata needs no identity: %v", err)
		}
	})
	t.Run("garbage identity", func(t *testing.T) {
		bad := "AGE-SECRET-KEY-1" + strings.ToUpper(hex.EncodeToString([]byte(v)))
		a, _ := New("s", Config{Root: root, AgeIdentity: "env:X"}, func(context.Context, config.SecretRef) (secret.Value, error) {
			return secret.FromString(bad), nil
		})
		defer func() { _ = a.Close() }()
		_, err := a.Read(t.Context(), ref("f.yaml"))
		if !errors.Is(err, stores.ErrLocked) {
			t.Errorf("Read: %v, want locked", err)
		}
		assertNoLeak(t, err, bad, v)
	})
	t.Run("credentials", func(t *testing.T) {
		a, _ := New("s", Config{Root: root, AgeIdentity: "env:X"}, resolverFor(id))
		if c := a.Credentials(); len(c) != 0 {
			t.Errorf("credentials before first use: %d", len(c))
		}
		if err := a.Health(t.Context()); err != nil {
			t.Fatal(err)
		}
		c := a.Credentials()
		if len(c) != 1 || plain(c[0]) != id.String() {
			t.Fatalf("Credentials returned %d values, want the secret key", len(c))
		}
		keys := append([]secret.Value(nil), a.keys...)
		_ = a.Close()
		for _, k := range keys {
			if !k.Wiped() {
				t.Error("Close left the age key unwiped")
			}
		}
		if !strings.Contains(plain(c[0]), "AGE-SECRET-KEY-") {
			t.Error("a returned credential was wiped by Close; the caller owns it")
		}
		c[0].Wipe()
	})
}

func TestNotASopsFile(t *testing.T) {
	id := identity(t)
	a, root := newAdapter(t, Config{}, id)
	v := gen(t)
	put(t, root, "plain.yaml", []byte("password: "+v+"\n"))
	put(t, root, ".sops.yaml", []byte("creation_rules:\n  - age: age1xyz\n"))
	put(t, root, "broken.json", []byte(`{"password": "`+v+`", oops}`))
	put(t, root, "ok.yaml", encryptFile(t, FormatYAML, flatDoc(map[string]string{"k": gen(t)}), encOptions{recipients: []*age.X25519Recipient{id.Recipient()}}))

	_, err := a.Read(t.Context(), ref("plain.yaml"))
	if !errors.Is(err, stores.ErrInvalidRef) || !strings.Contains(err.Error(), "not a SOPS-encrypted file") {
		t.Errorf("plain file: %v", err)
	}
	assertNoLeak(t, err, v)
	_, err = a.Read(t.Context(), ref("broken.json"))
	if !errors.Is(err, stores.ErrInvalidRef) || !strings.Contains(err.Error(), "at byte") {
		t.Errorf("broken file: %v", err)
	}
	assertNoLeak(t, err, v, "oops")
	ls, err := a.List(t.Context(), ref("*"))
	if err != nil {
		t.Fatal(err)
	}
	var paths []string
	for _, m := range ls {
		paths = append(paths, m.Ref.Path)
	}
	slices.Sort(paths)
	if !slices.Equal(paths, []string{"broken.json", "ok.yaml"}) {
		t.Errorf("List = %v, want the SOPS file and the broken one", paths)
	}
}

func TestUnsupportedFiles(t *testing.T) {
	id := identity(t)
	a, root := newAdapter(t, Config{Format: FormatYAML}, id)
	b := encryptFile(t, FormatYAML, flatDoc(map[string]string{"k": gen(t)}), encOptions{recipients: []*age.X25519Recipient{id.Recipient()}})
	groups := strings.Replace(string(b), "sops:\n", "sops:\n    shamir_threshold: 2\n    key_groups:\n        - age: []\n        - age: []\n", 1)
	put(t, root, "groups.yaml", []byte(groups))
	comments := strings.Replace(string(b), "sops:\n", "sops:\n    encrypted_comment_regex: x\n", 1)
	comments = strings.Replace(comments, "    unencrypted_suffix: _unencrypted\n", "", 1)
	put(t, root, "comments.yaml", []byte(comments))
	put(t, root, "multi.yaml", append(append([]byte{}, b...), []byte("---\nother: x\n")...))
	for _, p := range []string{"groups.yaml", "comments.yaml", "multi.yaml"} {
		_, err := a.Read(t.Context(), ref(p))
		if !errors.Is(err, stores.ErrUnsupported) {
			t.Errorf("Read %s: %v, want unsupported", p, err)
		}
	}
	m, err := a.ReadMetadata(t.Context(), ref("groups.yaml"))
	if err != nil || m.Labels["sops.key-groups"] != "2" || m.Labels["sops.shamir-threshold"] != "2" {
		t.Errorf("key group labels: %v %v", m.Labels, err)
	}
}

func TestCanonicalInt(t *testing.T) {
	for in, want := range map[string]string{
		"0": "0", "-0": "0", "+7": "7", "007": "7", "-0042": "-42", "9223372036854775807": "9223372036854775807",
		"-9223372036854775808": "-9223372036854775808",
	} {
		got, ok := canonicalInt([]byte(in))
		if !ok || string(got) != want {
			t.Errorf("canonicalInt(%q) = %q, %v; want %q", in, got, ok, want)
		}
	}
	for _, in := range []string{"", "-", "1.5", "1e3", "9223372036854775808", "-9223372036854775809", "0x10", " 1"} {
		if _, ok := canonicalInt([]byte(in)); ok {
			t.Errorf("canonicalInt(%q) accepted", in)
		}
	}
}

func TestPathConfinement(t *testing.T) {
	id := identity(t)
	outside := t.TempDir()
	put(t, outside, "x.yaml", encryptFile(t, FormatYAML, flatDoc(map[string]string{"k": gen(t)}), encOptions{recipients: []*age.X25519Recipient{id.Recipient()}}))
	a, root := newAdapter(t, Config{}, id)
	if err := os.Symlink(filepath.Join(outside, "x.yaml"), filepath.Join(root, "link.yaml")); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"../x.yaml", "a/../../x.yaml"} {
		if _, err := a.Read(t.Context(), ref(p)); !errors.Is(err, stores.ErrInvalidRef) {
			t.Errorf("Read %s: %v, want invalid", p, err)
		}
	}
	if _, err := a.Read(t.Context(), ref("link.yaml")); !errors.Is(err, stores.ErrPermission) {
		t.Errorf("symlink out of the root: %v", err)
	}
	if _, err := a.Read(t.Context(), ref("x.yaml?version=1")); !errors.Is(err, stores.ErrInvalidRef) {
		t.Errorf("version selector: %v", err)
	}
}

func TestParseOptions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the cases are Unix paths, which are not absolute on Windows")
	}
	cfg, err := ParseOptions("s", map[string]any{"root": "/srv/secrets", "age-identity": "file:/run/age.txt", "watch": map[string]any{"interval": "5s"}})
	if err != nil || cfg.Format != FormatAuto || cfg.AgeIdentity != "file:/run/age.txt" || cfg.WatchInterval != 5*time.Second || cfg.MaxSize != DefaultMaxSize {
		t.Fatalf("ParseOptions = %+v, %v", cfg, err)
	}
	for _, c := range []struct {
		opts map[string]any
		want string
	}{
		{map[string]any{"age-identity": "env:K"}, "root is required"},
		{map[string]any{"root": "rel", "age-identity": "env:K"}, "absolute"},
		{map[string]any{"root": "/x"}, "age-identity is required"},
		{map[string]any{"root": "/x", "age-identity": "env:K", "format": "toml"}, "format must be"},
		{map[string]any{"root": "/x", "age-identity": "env:K", "age-identiti": "env:K"}, "did you mean age-identity"},
	} {
		if _, err := ParseOptions("s", c.opts); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("ParseOptions(%v) = %v, want %q", c.opts, err, c.want)
		}
	}
}

func TestRegistered(t *testing.T) {
	if !slices.Contains(stores.DefaultRegistry.Kinds(), Kind) {
		t.Fatal("sops kind not registered")
	}
	a, err := stores.DefaultRegistry.Open(t.Context(), stores.Instance{
		Name: "enc", Kind: Kind, Options: map[string]any{"root": t.TempDir(), "age-identity": "env:K"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = a.Close() }()
	if got := a.Capabilities().String(); got != "read,list,watch,glob" {
		t.Errorf("capabilities = %s", got)
	}
}

func TestWatchSameSizeRewrite(t *testing.T) {
	id := identity(t)
	a, root := newAdapter(t, Config{Format: FormatYAML, WatchInterval: 20 * time.Millisecond}, id)
	rcp := encOptions{recipients: []*age.X25519Recipient{id.Recipient()}}
	b := encryptFile(t, FormatYAML, flatDoc(map[string]string{"k": gen(t)}), rcp)
	put(t, root, "w/f.yaml", b)
	st, _ := os.Stat(filepath.Join(root, "w/f.yaml"))
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	ch, err := a.Watch(ctx, ref("w"))
	if err != nil {
		t.Fatal(err)
	}
	// Re-encrypting gives new ciphertext of the same length; keep the
	// modification time so only the digest can tell.
	for {
		nb := encryptFile(t, FormatYAML, flatDoc(map[string]string{"k": gen(t)}), rcp)
		if len(nb) == len(b) {
			b = nb
			break
		}
	}
	put(t, root, "w/f.yaml", b)
	if err := os.Chtimes(filepath.Join(root, "w/f.yaml"), st.ModTime(), st.ModTime()); err != nil {
		t.Fatal(err)
	}
	select {
	case c := <-ch:
		if c.Ref.Path != "w/f.yaml" || c.Kind != stores.Changed {
			t.Errorf("change = %+v", c)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("same-size rewrite not reported")
	}
}
