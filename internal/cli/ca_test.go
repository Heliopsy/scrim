// SPDX-License-Identifier: AGPL-3.0-only

package cli

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/heliopsy/scrim/internal/ca"
)

type cliFakeRunner struct{ calls []string }

func (f *cliFakeRunner) LookPath(name string) (string, error) { return "/usr/bin/" + name, nil }

func (f *cliFakeRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	f.calls = append(f.calls, name+" "+strings.Join(args, " "))
	return nil, nil
}

type caFixture struct {
	home, state string
	runner      *cliFakeRunner
	outputs     strings.Builder
}

func newCAFixture(t *testing.T) *caFixture {
	t.Helper()
	f := &caFixture{home: t.TempDir(), state: t.TempDir(), runner: &cliFakeRunner{}}
	roots := filepath.Join(t.TempDir(), "roots.pem")
	_ = os.WriteFile(roots, []byte("# roots\n"), 0o644)
	oldRunner, oldGOOS, oldRoots := caRunner, caGOOS, caSysRoots
	caRunner, caGOOS, caSysRoots = f.runner, "linux", []string{roots}
	t.Cleanup(func() { caRunner, caGOOS, caSysRoots = oldRunner, oldGOOS, oldRoots })
	return f
}

func (f *caFixture) run(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	e, out, errb := newEnv("HOME="+f.home, "XDG_STATE_HOME="+f.state, "XDG_CONFIG_HOME="+f.home+"/.config")
	code := Run(context.Background(), e, args)
	f.outputs.WriteString(out.String())
	f.outputs.WriteString(errb.String())
	return code, out.String(), errb.String()
}

func (f *caFixture) dir() string { return filepath.Join(f.state, "scrim", "ca") }

func pemCerts(t *testing.T, s string) []*x509.Certificate {
	t.Helper()
	var out []*x509.Certificate
	rest := []byte(s)
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		if b.Type != "CERTIFICATE" {
			t.Fatalf("export contains a %s block", b.Type)
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, c)
	}
	if strings.TrimSpace(string(rest)) != "" {
		t.Fatalf("trailing data in export: %q", rest)
	}
	return out
}

func TestCAExportRotate(t *testing.T) {
	f := newCAFixture(t)
	code, out, errb := f.run(t, "ca", "export")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errb)
	}
	certs := pemCerts(t, out)
	if len(certs) != 1 || !certs[0].IsCA || !strings.HasPrefix(certs[0].Subject.CommonName, ca.CommonName+" ") {
		t.Fatalf("export: %d certs", len(certs))
	}
	if _, err := os.Stat(filepath.Join(f.dir(), "state.json")); err != nil {
		t.Fatal("export did not persist the CA where the daemon reads it")
	}
	if _, again, _ := f.run(t, "ca", "export"); again != out {
		t.Fatal("second export differs: the CA was regenerated")
	}
	file := filepath.Join(t.TempDir(), "bundle.pem")
	if code, _, errb := f.run(t, "ca", "export", "--out", file); code != 0 || !strings.Contains(errb, "wrote 1 certificate(s) to "+file) {
		t.Fatalf("export --out: %d %s", code, errb)
	}
	if b, _ := os.ReadFile(file); string(b) != out {
		t.Fatal("export --out content differs from stdout")
	}

	code, out, errb = f.run(t, "ca", "rotate")
	if code != 0 || !strings.Contains(out, "current:") || !strings.Contains(out, "previous:") || !strings.Contains(out, "overlap ends") {
		t.Fatalf("rotate: %d\n%s\n%s", code, out, errb)
	}
	_, out, _ = f.run(t, "ca", "export")
	certs2 := pemCerts(t, out)
	if len(certs2) != 2 || !certs2[1].Equal(certs[0]) || certs2[0].Equal(certs[0]) {
		t.Fatal("export after rotation must list the new CA first, then the previous")
	}
}

func TestCAInstallUninstall(t *testing.T) {
	f := newCAFixture(t)
	nss := filepath.Join(f.home, ".pki", "nssdb")
	_ = os.MkdirAll(nss, 0o700)
	_ = os.WriteFile(filepath.Join(nss, "cert9.db"), []byte("x"), 0o600)

	if code, _, errb := f.run(t, "ca", "install"); code != 1 || !strings.Contains(errb, "choose --user") {
		t.Fatalf("install without scope: %d %s", code, errb)
	}
	if code, _, errb := f.run(t, "ca", "install", "--system"); code != 1 || !strings.Contains(errb, "scrim install --system") {
		t.Fatalf("install --system: %d %s", code, errb)
	}
	code, out, errb := f.run(t, "ca", "install", "--user", "--dry-run")
	if code != 0 || !strings.Contains(out, "+ would trust") || len(f.runner.calls) != 0 {
		t.Fatalf("dry run: %d %v\n%s%s", code, f.runner.calls, out, errb)
	}
	code, out, errb = f.run(t, "ca", "install", "--user")
	if code != 0 {
		t.Fatalf("install: %d\n%s%s", code, out, errb)
	}
	data := filepath.Join(f.home, ".local", "share", "scrim")
	if !strings.Contains(out, "export NODE_EXTRA_CA_CERTS="+filepath.Join(data, "scrim-ca.pem")) ||
		len(f.runner.calls) != 1 || !strings.HasPrefix(f.runner.calls[0], "certutil -d sql:"+nss+" -A") {
		t.Fatalf("install: %v\n%s", f.runner.calls, out)
	}
	if _, err := os.Stat(filepath.Join(f.dir(), "trust-manifest.json")); err != nil {
		t.Fatal("no manifest")
	}
	code, out, errb = f.run(t, "ca", "uninstall", "--user")
	if code != 0 || len(f.runner.calls) != 2 || !strings.Contains(f.runner.calls[1], " -D -n ") {
		t.Fatalf("uninstall: %d %v\n%s%s", code, f.runner.calls, out, errb)
	}
	if _, err := os.Stat(filepath.Join(data, "scrim-ca.pem")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("bundle file left after uninstall")
	}
}

// No command prints the CA private key, whatever it does.
func TestCAKeyNeverPrinted(t *testing.T) {
	f := newCAFixture(t)
	for _, args := range [][]string{
		{"ca", "export"}, {"ca", "rotate"}, {"ca", "export", "--out", filepath.Join(t.TempDir(), "b.pem")},
		{"ca", "install", "--user", "--dry-run"}, {"ca", "install", "--user"}, {"ca", "rotate"},
		{"ca", "uninstall", "--user"}, {"--log-level", "debug", "ca", "rotate"}, {"ca", "--help"},
	} {
		f.run(t, args...)
	}
	keys, _ := filepath.Glob(filepath.Join(f.dir(), "gen", "*", "key.pem"))
	if len(keys) != 2 {
		t.Fatalf("%d key files", len(keys))
	}
	all := f.outputs.String()
	if !strings.Contains(all, "BEGIN CERTIFICATE") {
		t.Fatal("outputs not captured")
	}
	for _, k := range keys {
		b, err := os.ReadFile(k)
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range strings.Split(string(b), "\n") {
			if line != "" && !strings.HasPrefix(line, "-----") && strings.Contains(all, line) {
				t.Fatal("CA key material appears in CLI output")
			}
		}
	}
	if strings.Contains(all, "PRIVATE KEY") {
		t.Fatal("a private key block appears in CLI output")
	}
}
