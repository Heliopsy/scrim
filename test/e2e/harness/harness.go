// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

// Package harness runs the real scrim binary for the end-to-end tests under
// test/e2e: a `scrim proxy` with its own temporary directories, memory state
// and a file store of generated values, agents and tools started under
// `scrim run`, TLS test servers standing in for tool APIs and a private CA
// for them.
//
// The tests run inside test/e2e/sandbox.sh (`just e2e-tools`, `just
// e2e-chain`, `just e2e-session`): a network namespace with loopback only,
// so no request can reach a real provider, and an /etc/hosts that resolves
// the test hosts by name. Outside it every test is skipped.
package harness

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// Hosts the sandbox resolves, each on its own loopback address.
const (
	APIHost   = "api.scrim.test"
	GitHost   = "git.scrim.test"
	OtherHost = "other.scrim.test"
)

// Binaries are the programs under test.
type Binaries struct {
	Scrim     string
	DataPlane string
}

// Require skips the test outside the sandbox or without the binaries, and
// checks that the sandbox does what the tests rely on.
func Require(t *testing.T) Binaries {
	t.Helper()
	if os.Getenv("SCRIM_E2E_SANDBOX") != "1" {
		t.Skip("end-to-end test: run it through test/e2e/sandbox.sh (just e2e-tools, e2e-chain, e2e-session)")
	}
	b := Binaries{Scrim: os.Getenv("SCRIM_E2E_SCRIM"), DataPlane: os.Getenv("SCRIM_DATAPLANE_PATH")}
	if b.Scrim == "" || b.DataPlane == "" {
		t.Fatal("SCRIM_E2E_SCRIM and SCRIM_DATAPLANE_PATH must name the scrim and scrim-dataplane binaries")
	}
	for _, h := range []string{APIHost, GitHost, OtherHost} {
		addrs, err := net.LookupHost(h)
		if err != nil || len(addrs) == 0 || !net.ParseIP(addrs[0]).IsLoopback() {
			t.Fatalf("sandbox: %s does not resolve to loopback (%v %v)", h, addrs, err)
		}
	}
	// No route out: a real provider must be unreachable.
	if c, err := net.DialTimeout("tcp", "1.1.1.1:443", time.Second); err == nil {
		_ = c.Close()
		t.Fatal("sandbox: the network namespace reaches the internet")
	}
	return b
}

// LookPath skips the test when a client is not installed, or fails it when
// SCRIM_E2E_REQUIRE_TOOLS is 1 (CI, where every client must run).
func LookPath(t *testing.T, name string) string {
	t.Helper()
	p, err := exec.LookPath(name)
	if err != nil {
		if os.Getenv("SCRIM_E2E_REQUIRE_TOOLS") == "1" {
			t.Fatalf("%s is not installed and SCRIM_E2E_REQUIRE_TOOLS is set", name)
		}
		t.Skipf("%s is not installed", name)
	}
	return p
}

// RealPath returns the executable a command name runs, through version
// manager shims (asdf, mise, nvm) that need the user's HOME to pick a
// version: the tests run clients with an empty HOME.
func RealPath(t *testing.T, name string) string {
	t.Helper()
	p := LookPath(t, name)
	var probe []string
	switch name {
	case "node":
		probe = []string{"-p", "process.execPath"}
	case "python3":
		probe = []string{"-I", "-c", "import sys; print(sys.executable)"}
	}
	if probe != nil {
		if out, err := exec.Command(p, probe...).Output(); err == nil { //nolint:gosec // the user's own tool
			p = strings.TrimSpace(string(out))
		}
	} else if strings.Contains(p, "/shims/") {
		// asdf picks the version from the user's HOME, which the tests replace.
		if out, err := exec.Command("asdf", "which", name).Output(); err == nil { //nolint:gosec // the user's own tool
			p = strings.TrimSpace(string(out))
		}
	}
	if r, err := filepath.EvalSymlinks(p); err == nil {
		p = r
	}
	return p
}

// PathWith is a PATH variable with the directories of the named tools'
// real executables first.
func PathWith(t *testing.T, names ...string) string {
	t.Helper()
	var dirs []string
	for _, n := range names {
		dirs = append(dirs, filepath.Dir(RealPath(t, n)))
	}
	return "PATH=" + strings.Join(append(dirs, os.Getenv("PATH")), string(os.PathListSeparator))
}

// ProfileHosts are the hosts the sandbox resolves to [ProfileAddr] for the
// tool profile tests: the default endpoints of real CLIs and a few test
// hosts. One server answers for all of them.
var ProfileHosts = []string{
	"api.github.com", "github.com", "uploads.github.com", "registry.npmjs.org", "app.terraform.io",
	"cloudresourcemanager.googleapis.com", "login.microsoftonline.com", "management.azure.com",
	"upload.pypi.org", "crates.io", "index.crates.io", "static.crates.io", "api.hetzner.cloud",
	"api.digitalocean.com", "k8s.scrim.test", "registry.scrim.test", "pypi.scrim.test",
}

// ProfileAddr is where the sandbox puts [ProfileHosts].
const ProfileAddr = "127.0.0.10:443"

// ServeTLSNames serves h on addr with one leaf from p for every name, until
// the test ends.
func ServeTLSNames(t *testing.T, p *PKI, addr string, names []string, h http.Handler) {
	t.Helper()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second,
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{p.Leaf(t, names...)}, MinVersion: tls.VersionTLS12}}
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	t.Cleanup(func() { _ = srv.Close() })
}

// HostAddr is the loopback address:443 the sandbox gives a host.
func HostAddr(t *testing.T, host string) string {
	t.Helper()
	addrs, err := net.LookupHost(host)
	if err != nil || len(addrs) == 0 {
		t.Fatalf("resolve %s: %v", host, err)
	}
	return net.JoinHostPort(addrs[0], "443")
}

// PKI is a private CA for the test servers, the way a company's internal
// API hosts have one.
type PKI struct {
	CAPEM []byte
	ca    *x509.Certificate
	key   *ecdsa.PrivateKey
}

// NewPKI creates a CA valid for an hour.
func NewPKI(t *testing.T) *PKI {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "scrim e2e tool API CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(der)
	return &PKI{CAPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), ca: ca, key: key}
}

// Leaf issues a server certificate for the names.
func (p *PKI) Leaf(t *testing.T, names ...string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tmpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: names[0]}, DNSNames: names,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.ca, &key.PublicKey, p.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// ServeTLS serves h on the host's sandbox address, port 443, with a leaf
// from p, until the test ends.
func ServeTLS(t *testing.T, p *PKI, host string, h http.Handler) {
	t.Helper()
	ln, err := net.Listen("tcp", HostAddr(t, host))
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second,
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{p.Leaf(t, host)}, MinVersion: tls.VersionTLS12}}
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	t.Cleanup(func() { _ = srv.Close() })
}

// Listen returns a free loopback TCP listener.
func Listen(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return ln
}

// FreePort returns a loopback address nobody listens on right now.
func FreePort(t *testing.T) string {
	t.Helper()
	ln := Listen(t)
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

// Options configure a daemon.
type Options struct {
	// Secrets are the file store's values by name; they are loaded into the
	// redaction set as e2e://tools/<name>.
	Secrets map[string]string
	// Catalog is the YAML of catalog.entries, indented by four spaces.
	Catalog string
	// Upstream is the base URL of both provider routes (a fake provider).
	Upstream string
	// Chain is proxy.chain.url, empty for none.
	Chain string
	// UpstreamCA is trusted by the data plane for upstream TLS.
	UpstreamCA []byte
	// Capture turns capture mode on into Dir/capture.
	Capture bool
	// Rules is the policy rules file (YAML), empty for none.
	Rules string
	// Extra is appended to the configuration file.
	Extra string
}

// Daemon is a running `scrim proxy`.
type Daemon struct {
	Bin    Binaries
	Dir    string // everything scrim writes lives here
	Config string
	Home   string // HOME of every process the test starts
	Admin  string // admin socket
	Log    *SyncBuffer

	cmd  *exec.Cmd
	done chan struct{}
}

// Start writes the configuration and starts `scrim proxy`, and waits until
// it is ready. It is stopped when the test ends.
func Start(t *testing.T, b Binaries, o Options) *Daemon {
	t.Helper()
	// Unix socket paths are short: keep the directory out of t.TempDir().
	dir, err := os.MkdirTemp("", "scrim-e2e-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	d := &Daemon{Bin: b, Dir: dir, Config: filepath.Join(dir, "config.yaml"), Home: filepath.Join(dir, "home"),
		Admin: filepath.Join(dir, "admin.sock"), Log: &SyncBuffer{}, done: make(chan struct{})}
	for _, sub := range []string{"home", "secrets/tools", "xdg/config", "xdg/state", "xdg/data", "xdg/cache"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for name, v := range o.Secrets {
		if err := os.WriteFile(filepath.Join(dir, "secrets/tools", name), []byte(v), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	var cfg strings.Builder
	fmt.Fprintf(&cfg, `apiVersion: scrim.dev/v1
kind: Config
state: {backend: memory}
stores:
  e2e:
    kind: file
    root: %[1]s/secrets
    format: raw
    trim-newline: false
    redact: ["e2e://tools/*"]
proxy:
  listen: 127.0.0.1:0
  forward-listen: 127.0.0.1:0
  upstream: {anthropic: %[2]q, openai: %[2]q, gemini: %[2]q}
%[4]sapi: {socket: %[1]s/api.sock}
admin: {url: "unix:%[1]s/admin.sock"}
redaction: {placeholder-key-dir: %[1]s/keys}
tool-proxy: {ca: {dir: %[1]s/ca}}
notify: {terminal: {enabled: false}}
dataplane:
  path: %[3]s
  push-debounce: 10ms
`, dir, o.Upstream, b.DataPlane, proxyExtra(dir, o))
	if len(o.UpstreamCA) > 0 {
		ca := filepath.Join(dir, "upstream-ca.pem")
		if err := os.WriteFile(ca, o.UpstreamCA, 0o600); err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(&cfg, "  upstream-ca-file: %s\n", ca)
	}
	if o.Rules != "" {
		rules := filepath.Join(dir, "rules.yaml")
		if err := os.WriteFile(rules, []byte(o.Rules), 0o600); err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(&cfg, "policy: {rules-file: %s}\n", rules)
	}
	if o.Catalog != "" {
		fmt.Fprintf(&cfg, "catalog:\n  entries:\n%s", o.Catalog)
	}
	cfg.WriteString(o.Extra)
	if err := os.WriteFile(d.Config, []byte(cfg.String()), 0o600); err != nil {
		t.Fatal(err)
	}

	d.cmd = exec.Command(b.Scrim, "--config", d.Config, "proxy") //nolint:gosec // the binary under test
	d.cmd.Env = d.Env()
	d.cmd.Stdout, d.cmd.Stderr = d.Log, d.Log
	d.cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGTERM}
	if err := d.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() { _ = d.cmd.Wait(); close(d.done) }()
	t.Cleanup(func() {
		_ = d.cmd.Process.Signal(syscall.SIGTERM)
		select {
		case <-d.done:
		case <-time.After(20 * time.Second):
			_ = d.cmd.Process.Kill()
			<-d.done
		}
		// A rejected snapshot leaves the data plane on an older one: new
		// sessions, values and rotations would silently not apply.
		if strings.Contains(d.Log.String(), "snapshot rejected") {
			t.Error("the data plane rejected a snapshot")
		}
		if t.Failed() {
			t.Logf("scrim proxy log:\n%s", d.Log.String())
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	for {
		info, err := d.Info(ctx)
		if err == nil && info.Ready {
			break
		}
		select {
		case <-d.done:
			t.Fatalf("scrim proxy exited: %s", d.Log.String())
		case <-ctx.Done():
			t.Fatalf("scrim proxy not ready (%v %+v):\n%s", err, info.Problems, d.Log.String())
		case <-time.After(100 * time.Millisecond):
		}
	}
	return d
}

// proxyExtra is the chain and capture part of the proxy block.
func proxyExtra(dir string, o Options) string {
	var s string
	if o.Chain != "" {
		s += fmt.Sprintf("  chain: {url: %q}\n", o.Chain)
	}
	if o.Capture {
		s += fmt.Sprintf("  capture: {dir: %s/capture}\n", dir)
	}
	return s
}

// CaptureDir is where capture mode writes, when it is on.
func (d *Daemon) CaptureDir() string { return filepath.Join(d.Dir, "capture") }

// Env is the environment of every process the test starts: an empty HOME
// and XDG directories in the daemon's directory, no global or system git
// configuration, and the caller's PATH and XDG_RUNTIME_DIR.
func (d *Daemon) Env(extra ...string) []string {
	env := []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + d.Home,
		"TERM=dumb",
		"LANG=C.UTF-8",
		"XDG_CONFIG_HOME=" + filepath.Join(d.Dir, "xdg/config"),
		"XDG_STATE_HOME=" + filepath.Join(d.Dir, "xdg/state"),
		"XDG_DATA_HOME=" + filepath.Join(d.Dir, "xdg/data"),
		"XDG_CACHE_HOME=" + filepath.Join(d.Dir, "xdg/cache"),
		"GIT_CONFIG_GLOBAL=" + filepath.Join(d.Home, ".gitconfig"),
		"GIT_CONFIG_NOSYSTEM=1",
		"SCRIM_DATAPLANE_PATH=" + d.Bin.DataPlane,
	}
	if v := os.Getenv("XDG_RUNTIME_DIR"); v != "" {
		env = append(env, "XDG_RUNTIME_DIR="+v)
	}
	return append(env, extra...)
}

// Info is the part of GET /v1/daemon the tests read.
type Info struct {
	Ready    bool              `json:"ready"`
	Problems map[string]string `json:"problems"`
	Addrs    struct {
		BaseURL      string `json:"base_url"`
		ForwardProxy string `json:"forward_proxy"`
	} `json:"addrs"`
}

func (d *Daemon) admin() *http.Client {
	return &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", d.Admin)
		}}}
}

// Info asks the daemon for its status.
func (d *Daemon) Info(ctx context.Context) (Info, error) {
	var info Info
	b, err := d.AdminGet(ctx, "/v1/daemon")
	if err != nil {
		return info, err
	}
	return info, json.Unmarshal(b, &info)
}

// AdminGet fetches a path of the admin API.
func (d *Daemon) AdminGet(ctx context.Context, path string) ([]byte, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://scrim"+path, nil)
	resp, err := d.admin().Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %s", path, resp.Status)
	}
	return b, nil
}

// Result is a finished command.
type Result struct {
	Stdout, Stderr string
	Code           int
}

// Output is stdout and stderr together.
func (r Result) Output() string { return r.Stdout + r.Stderr }

// Run runs args under `scrim run` in dir with the test environment plus
// extra.
func (d *Daemon) Run(t *testing.T, dir string, extra []string, args ...string) Result {
	t.Helper()
	return d.Scrim(t, dir, extra, append([]string{"run", "--"}, args...)...)
}

// Scrim runs the scrim CLI with the daemon's configuration.
func (d *Daemon) Scrim(t *testing.T, dir string, extra []string, args ...string) Result {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, d.Bin.Scrim, append([]string{"--config", d.Config}, args...)...) //nolint:gosec // the binary under test
	cmd.Dir = dir
	cmd.Env = d.Env(extra...)
	cmd.Stdin = strings.NewReader("")
	var out, errb SyncBuffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	r := Result{Stdout: out.String(), Stderr: errb.String()}
	var ee *exec.ExitError
	switch {
	case errors.As(err, &ee):
		r.Code = ee.ExitCode()
	case err != nil:
		t.Fatalf("scrim %s: %v", strings.Join(args, " "), err)
	}
	return r
}

// SyncBuffer is a bytes.Buffer safe for concurrent writers.
type SyncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *SyncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *SyncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}
