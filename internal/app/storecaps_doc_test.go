// SPDX-License-Identifier: AGPL-3.0-only

package app_test

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"testing"

	_ "github.com/heliopsy/scrim/internal/app" // every adapter compiled into scrim
	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores"
	"github.com/heliopsy/scrim/internal/stores/keyring"
)

// The capability tables in docs/stores/*.md are generated from the adapters
// themselves: each kind is built offline (factories never contact the store)
// and asked for its Capabilities, whether it checks an agent's own store
// identity (stores.AgentAccess) and which identity.store-login methods it
// takes (stores.AgentFederation). A page holds a table between
//
//	<!-- BEGIN GENERATED STORE CAPABILITIES kinds=awssm,ssm -->
//	<!-- END GENERATED STORE CAPABILITIES -->
//
// (kinds=all in README.md, the full matrix). Rewrite them with
//
//	go test ./internal/app -run TestStoreCapabilityMatrix -update
var update = flag.Bool("update", false, "rewrite the generated capability tables in docs/stores")

var storeCapsBegin = regexp.MustCompile(`<!-- BEGIN GENERATED STORE CAPABILITIES kinds=([a-z0-9,]+) -->`)

const storeCapsEnd = "<!-- END GENERATED STORE CAPABILITIES -->"

// capsRow is one row of the matrix: an instance built with opts, and
// optionally the same kind built with alt added, for a capability an option
// turns on or off.
type capsRow struct {
	kind  string
	label string
	opts  map[string]any
	alt   map[string]any
	open  func(t *testing.T, opts map[string]any) stores.Adapter
}

func storeCapsRows() []capsRow {
	ref := "env:SCRIM_DOC_UNUSED"
	keyringBackend := func(backend string) func(*testing.T, map[string]any) stores.Adapter {
		return func(t *testing.T, opts map[string]any) stores.Adapter {
			t.Helper()
			cfg, err := keyring.ParseOptions("x", opts, backend)
			if err != nil {
				t.Fatal(err)
			}
			a, err := keyring.New("x", cfg)
			if err != nil {
				t.Fatal(err)
			}
			return a
		}
	}
	kr := map[string]any{"services": []any{"scrim"}}
	return []capsRow{
		{kind: "openbao", opts: map[string]any{"address": "https://bao.example", "token": ref}},
		{kind: "vault", opts: map[string]any{"address": "https://vault.example", "token": ref}},
		{kind: "infisical", opts: map[string]any{"address": "https://infisical.example", "client-id": ref, "client-secret": ref}},
		{kind: "doppler", opts: map[string]any{"token": ref}},
		{kind: "onepassword", opts: map[string]any{"address": "http://op-connect:8080", "token": ref}},
		{kind: "awssm"},
		{kind: "ssm"},
		{kind: "bws", opts: map[string]any{"token": ref}},
		{kind: "vaultwarden", opts: map[string]any{"url": "https://vw.example", "unlock": ref, "client-id": ref, "client-secret": ref}},
		{kind: "gcpsm", alt: map[string]any{"read-only": true}},
		{kind: "azkv", opts: map[string]any{"vault-url": "https://v.vault.azure.net"}, alt: map[string]any{"read-only": true}},
		{kind: "kubernetes", opts: map[string]any{"namespace": "default"}, alt: map[string]any{"writable": true}},
		{kind: "env"},
		{kind: "file", opts: map[string]any{"root": os.TempDir()}},
		{kind: "sops", opts: map[string]any{"root": os.TempDir(), "age-identity": ref}},
		{kind: "keyring", label: "Secret Service (Linux)", opts: kr, open: keyringBackend(keyring.BackendSecretService)},
		// The Windows Credential Manager backend cannot be built off Windows;
		// like the Keychain it reads single items only (backend_windows.go).
		{kind: "keyring", label: "Keychain (macOS), Credential Manager (Windows)", opts: kr, open: keyringBackend(keyring.BackendKeychain)},
		{kind: "memory"},
		{kind: "plugin"},
	}
}

func openStore(t *testing.T, r capsRow, extra map[string]any) stores.Adapter {
	t.Helper()
	opts := map[string]any{}
	for k, v := range r.opts {
		opts[k] = v
	}
	for k, v := range extra {
		opts[k] = v
	}
	if r.open != nil {
		return r.open(t, opts)
	}
	a, err := stores.DefaultRegistry.Open(context.Background(), stores.Instance{
		Name: "x", Kind: r.kind, Options: opts,
		Resolve: func(context.Context, config.SecretRef) (secret.Value, error) {
			return secret.Value{}, errors.New("not resolved while building the capability matrix")
		},
	})
	if err != nil {
		t.Fatalf("store kind %s: %v", r.kind, err)
	}
	return a
}

var matrixCaps = []struct {
	c    stores.Capability
	name string
}{
	{stores.CapRead, "read"}, {stores.CapList, "list"}, {stores.CapWatch, "watch"},
	{stores.CapWrite, "write"}, {stores.CapGlob, "glob"}, {stores.CapDynamic, "dynamic"},
}

// storeCapsTable renders the rows of kinds, or every row for "all".
func storeCapsTable(t *testing.T, kinds []string) string {
	t.Helper()
	all := slices.Equal(kinds, []string{"all"})
	var b strings.Builder
	b.WriteString("| Kind |")
	for _, c := range matrixCaps {
		b.WriteString(" " + c.name + " |")
	}
	b.WriteString(" per-agent check | `identity.store-login` |\n| --- |")
	for range matrixCaps {
		b.WriteString(" --- |")
	}
	b.WriteString(" --- | --- |\n")
	n := 0
	for _, r := range storeCapsRows() {
		if !all && !slices.Contains(kinds, r.kind) {
			continue
		}
		n++
		name := "`" + r.kind + "`"
		if r.label != "" {
			name += " " + r.label
		}
		fmt.Fprintf(&b, "| %s |", name)
		if r.kind == "plugin" {
			// What the plugin declares (pkg/plugin), narrowed by the
			// instance's capabilities field; plugins cannot issue dynamic
			// secrets or check agents.
			b.WriteString(" (1) | (1) | (1) | (1) | (1) | no | no | none |\n")
			continue
		}
		a := openStore(t, r, nil)
		var alt stores.Adapter
		if r.alt != nil {
			alt = openStore(t, r, r.alt)
		}
		for _, c := range matrixCaps {
			cell := yesNo(a.Capabilities().Has(c.c))
			if alt != nil && alt.Capabilities().Has(c.c) != a.Capabilities().Has(c.c) {
				cell = optionCell(a.Capabilities().Has(c.c), r.alt)
			}
			b.WriteString(" " + cell + " |")
		}
		_, check := a.(stores.AgentAccess)
		logins := "none"
		if f, ok := a.(stores.AgentFederation); ok && len(f.FederationMethods()) > 0 {
			logins = "`" + strings.Join(f.FederationMethods(), "`, `") + "`"
		}
		fmt.Fprintf(&b, " %s | %s |\n", yesNo(check), logins)
	}
	if n == 0 || !all && n < len(kinds) {
		t.Errorf("capability table for kinds %v: some kind has no row in storeCapsRows", kinds)
	}
	if !all {
		b.WriteString("\nThe columns are explained under [Capabilities](README.md#capabilities).\n")
	}
	return b.String()
}

func yesNo(v bool) string {
	if v {
		return "yes"
	}
	return "no"
}

// optionCell says which option changes a capability: on by default and off
// with the option, or the other way round.
func optionCell(def bool, alt map[string]any) string {
	var opt string
	for k, v := range alt {
		opt = fmt.Sprintf("`%s: %v`", k, v)
	}
	if def {
		return "yes, not with " + opt
	}
	return "with " + opt
}

// spliceStoreCaps rewrites every generated table in doc.
func spliceStoreCaps(t *testing.T, doc []byte) (out []byte, kinds [][]string) {
	t.Helper()
	var b bytes.Buffer
	rest := doc
	for {
		m := storeCapsBegin.FindSubmatchIndex(rest)
		if m == nil {
			b.Write(rest)
			return b.Bytes(), kinds
		}
		end := bytes.Index(rest[m[1]:], []byte(storeCapsEnd))
		if end < 0 {
			t.Fatal("a generated store capability table has no end marker")
		}
		k := strings.Split(string(rest[m[2]:m[3]]), ",")
		kinds = append(kinds, k)
		b.Write(rest[:m[1]])
		b.WriteString("\n\n" + storeCapsTable(t, k) + "\n")
		rest = rest[m[1]+end:]
	}
}

func TestStoreCapabilityMatrix(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the Secret Service and Keychain backends of the keyring source are not built on Windows")
	}
	covered := map[string]bool{}
	for _, r := range storeCapsRows() {
		covered[r.kind] = true
	}
	for _, k := range stores.DefaultRegistry.Kinds() {
		if !covered[k] {
			t.Errorf("store kind %s has no row in the capability matrix: add it to storeCapsRows", k)
		}
	}

	pages, err := filepath.Glob(filepath.Join("..", "..", "docs", "stores", "*.md"))
	if err != nil {
		t.Fatal(err)
	}
	var full bool
	for _, path := range pages {
		doc, err := os.ReadFile(path) // #nosec G304 -- a page under docs/stores
		if err != nil {
			t.Fatal(err)
		}
		want, kinds := spliceStoreCaps(t, doc)
		if filepath.Base(path) == "README.md" {
			full = slices.ContainsFunc(kinds, func(k []string) bool { return slices.Equal(k, []string{"all"}) })
		}
		if bytes.Equal(doc, want) {
			continue
		}
		if *update {
			if err := os.WriteFile(path, want, 0o644); err != nil { // #nosec G306 -- a document in the repository
				t.Fatal(err)
			}
			continue
		}
		t.Errorf("%s: the store capability table is out of date: run "+
			"`go test ./internal/app -run TestStoreCapabilityMatrix -update`", path)
	}
	if !full {
		t.Error("docs/stores/README.md lacks the full capability matrix (kinds=all)")
	}
}
