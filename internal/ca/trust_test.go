// SPDX-License-Identifier: AGPL-3.0-only

package ca

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeRunner records commands instead of touching a keychain or NSS db.
type fakeRunner struct {
	mu      sync.Mutex
	calls   []string
	missing map[string]bool
	fail    func(call string) bool
}

func (f *fakeRunner) LookPath(name string) (string, error) {
	if f.missing[name] {
		return "", errors.New("not found")
	}
	return "/usr/bin/" + name, nil
}

func (f *fakeRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	// Replace the temporary certificate path, which changes every run.
	shown := slices.Clone(args)
	for i, a := range shown {
		if strings.Contains(a, ".trust-") {
			b, err := os.ReadFile(a)
			if err != nil || !bytes.Contains(b, []byte("BEGIN CERTIFICATE")) {
				return nil, errors.New("certificate file missing")
			}
			shown[i] = "CERT"
		}
	}
	call := name + " " + strings.Join(shown, " ")
	f.calls = append(f.calls, call)
	if f.fail != nil && f.fail(call) {
		return []byte("simulated failure"), errors.New("exit status 1")
	}
	return nil, nil
}

type trustFixture struct {
	home, data, roots string
	runner            *fakeRunner
	out               *bytes.Buffer
}

func newTrustFixture(t *testing.T) *trustFixture {
	t.Helper()
	f := &trustFixture{home: t.TempDir(), runner: &fakeRunner{missing: map[string]bool{}}, out: &bytes.Buffer{}}
	f.data = filepath.Join(f.home, ".local", "share", "scrim")
	f.roots = filepath.Join(t.TempDir(), "ca-certificates.crt")
	if err := os.WriteFile(f.roots, []byte("# system roots\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *trustFixture) installer(dir, goos string) *Installer {
	return &Installer{Dir: dir, Home: f.home, DataDir: f.data, GOOS: goos, Runner: f.runner, Out: f.out,
		SystemRoots: []string{"/nonexistent/roots.pem", f.roots}}
}

func TestInstallUninstallLinux(t *testing.T) {
	c := newClock()
	dir := privateDir(t)
	m, _ := openTest(t, dir, c)
	f := newTrustFixture(t)
	nss := filepath.Join(f.home, ".pki", "nssdb")
	_ = os.MkdirAll(nss, 0o700)
	_ = os.WriteFile(filepath.Join(nss, "cert9.db"), []byte("x"), 0o600)
	cn := mustCert(t, m.Certificates()[0].PEM).Subject.CommonName

	// Dry run changes nothing.
	dry := f.installer(dir, "linux")
	dry.DryRun = true
	if err := dry.Install(context.Background(), m.Certificates()); err != nil {
		t.Fatal(err)
	}
	if len(f.runner.calls) != 0 || !strings.Contains(f.out.String(), "+ would write") {
		t.Fatalf("dry run: calls %v, out %s", f.runner.calls, f.out)
	}
	if _, err := os.Stat(filepath.Join(dir, manifestFile)); !os.IsNotExist(err) {
		t.Fatal("dry run wrote a manifest")
	}

	f.out.Reset()
	if err := f.installer(dir, "linux").Install(context.Background(), m.Certificates()); err != nil {
		t.Fatal(err)
	}
	out := f.out.String()
	for _, want := range []string{
		"+ write " + filepath.Join(f.data, "scrim-ca.pem"),
		"+ write " + filepath.Join(f.data, "ca-bundle.pem") + " (system roots from " + f.roots,
		"+ trust \"" + cn + "\" in the NSS database " + nss,
		"export NODE_EXTRA_CA_CERTS=" + filepath.Join(f.data, "scrim-ca.pem"),
		"export SSL_CERT_FILE=" + filepath.Join(f.data, "ca-bundle.pem"),
		"export GIT_SSL_CAINFO=", "export REQUESTS_CA_BUNDLE=",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("install output lacks %q:\n%s", want, out)
		}
	}
	wantCall := "certutil -d sql:" + nss + " -A -t C,, -n " + cn + " -i CERT"
	if !slices.Equal(f.runner.calls, []string{wantCall}) {
		t.Fatalf("calls %v, want %s", f.runner.calls, wantCall)
	}
	bundle, _ := os.ReadFile(filepath.Join(f.data, "ca-bundle.pem"))
	if !strings.HasPrefix(string(bundle), "# system roots\n") || !strings.Contains(string(bundle), m.Certificates()[0].PEM) {
		t.Fatalf("combined bundle:\n%s", bundle)
	}
	mf, _ := ReadManifest(dir)
	if len(mf.Entries) != 3 {
		t.Fatalf("manifest %+v", mf)
	}

	// Installing again changes nothing in the stores.
	f.runner.calls = nil
	if err := f.installer(dir, "linux").Install(context.Background(), m.Certificates()); err != nil {
		t.Fatal(err)
	}
	if len(f.runner.calls) != 0 {
		t.Fatalf("second install ran %v", f.runner.calls)
	}

	// A rotation refreshes the bundle files at once; install adds the new CA.
	if err := m.Rotate(context.Background()); err != nil {
		t.Fatal(err)
	}
	extra, _ := os.ReadFile(filepath.Join(f.data, "scrim-ca.pem"))
	if string(extra) != m.TrustBundlePEM() {
		t.Fatal("bundle file not refreshed after rotation")
	}
	if err := f.installer(dir, "linux").Install(context.Background(), m.Certificates()); err != nil {
		t.Fatal(err)
	}
	if len(f.runner.calls) != 1 || !strings.Contains(f.runner.calls[0], " -A ") {
		t.Fatalf("after rotation %v", f.runner.calls)
	}
	// After the overlap, install drops the old generation's entry.
	c.Add(8 * 24 * time.Hour)
	m.maintain()
	f.runner.calls = nil
	f.out.Reset()
	if err := f.installer(dir, "linux").Install(context.Background(), m.Certificates()); err != nil {
		t.Fatal(err)
	}
	if want := "certutil -d sql:" + nss + " -D -n " + cn; !slices.Equal(f.runner.calls, []string{want}) {
		t.Fatalf("calls %v, want %s", f.runner.calls, want)
	}

	// Uninstall reverts everything recorded, reporting what it could not.
	f.runner.calls = nil
	f.runner.fail = func(call string) bool { return strings.Contains(call, " -D ") }
	f.out.Reset()
	err := f.installer(dir, "linux").Uninstall(context.Background())
	if !errors.Is(err, ErrNotReverted) {
		t.Fatalf("uninstall with a failing store: %v", err)
	}
	if !strings.Contains(f.out.String(), "manual step: certutil -d sql:"+nss+" -D -n") {
		t.Fatalf("no manual step:\n%s", f.out)
	}
	if _, err := os.Stat(filepath.Join(f.data, "scrim-ca.pem")); !os.IsNotExist(err) {
		t.Fatal("bundle file not removed")
	}
	mf, _ = ReadManifest(dir)
	if len(mf.Entries) != 1 || mf.Entries[0].Kind != KindNSSDB {
		t.Fatalf("manifest after partial uninstall %+v", mf)
	}
	f.runner.fail = nil
	if err := f.installer(dir, "linux").Uninstall(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, manifestFile)); !os.IsNotExist(err) {
		t.Fatal("manifest left after a complete uninstall")
	}
	f.out.Reset()
	if err := f.installer(dir, "linux").Uninstall(context.Background()); err != nil || !strings.Contains(f.out.String(), "nothing to uninstall") {
		t.Fatalf("second uninstall: %v %s", err, f.out)
	}
}

func TestInstallLinuxWithoutNSS(t *testing.T) {
	c := newClock()
	dir := privateDir(t)
	m, _ := openTest(t, dir, c)
	f := newTrustFixture(t)
	in := f.installer(dir, "linux")
	in.SystemRoots = []string{"/nonexistent"}
	if err := in.Install(context.Background(), m.Certificates()); err != nil {
		t.Fatal(err)
	}
	out := f.out.String()
	if len(f.runner.calls) != 0 || !strings.Contains(out, "skipped the NSS database") ||
		!strings.Contains(out, "no system CA bundle found") || strings.Contains(out, "SSL_CERT_FILE=") {
		t.Fatalf("calls %v\n%s", f.runner.calls, out)
	}
	// A file scrim did not write is left alone.
	f.out.Reset()
	_ = os.Remove(filepath.Join(dir, manifestFile))
	if err := in.Install(context.Background(), m.Certificates()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(f.out.String(), "was not written by scrim; left alone") {
		t.Fatal(f.out.String())
	}
}

func TestInstallUninstallDarwin(t *testing.T) {
	c := newClock()
	dir := privateDir(t)
	m, _ := openTest(t, dir, c)
	f := newTrustFixture(t)
	kc := filepath.Join(f.home, "Library", "Keychains", "login.keychain-db")
	if err := f.installer(dir, "darwin").Install(context.Background(), m.Certificates()); err != nil {
		t.Fatal(err)
	}
	if want := "security add-trusted-cert -r trustRoot -k " + kc + " CERT"; !slices.Equal(f.runner.calls, []string{want}) {
		t.Fatalf("calls %v", f.runner.calls)
	}
	mf, _ := ReadManifest(dir)
	var sha string
	for _, e := range mf.Entries {
		if e.Kind == KindKeychain {
			sha = e.SHA1
		}
	}
	if len(sha) != 40 {
		t.Fatalf("manifest %+v", mf)
	}
	f.runner.calls = nil
	if err := f.installer(dir, "darwin").Uninstall(context.Background()); err != nil {
		t.Fatal(err)
	}
	want := []string{"security remove-trusted-cert CERT", "security delete-certificate -Z " + sha + " " + kc}
	if !slices.Equal(f.runner.calls, want) {
		t.Fatalf("calls %v, want %v", f.runner.calls, want)
	}

	// Without the security tool the keychain is skipped, not failed.
	f.runner.missing["security"] = true
	f.runner.calls = nil
	f.out.Reset()
	if err := f.installer(dir, "darwin").Install(context.Background(), m.Certificates()); err != nil {
		t.Fatal(err)
	}
	if len(f.runner.calls) != 0 || !strings.Contains(f.out.String(), "skipped the login keychain") {
		t.Fatalf("calls %v\n%s", f.runner.calls, f.out)
	}
}
