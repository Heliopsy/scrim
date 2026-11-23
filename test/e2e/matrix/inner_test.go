// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package matrix

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/heliopsy/scrim/internal/leak"
	"github.com/heliopsy/scrim/internal/leak/audit"
	fp "github.com/heliopsy/scrim/internal/testing/fakeprovider"
	"github.com/heliopsy/scrim/test/e2e/harness"
)

// transparentListen is scrim's transparent listener in the transparent
// cells; the sandbox's nftables rule redirects outgoing TCP port 443 to it.
// Other cells leave it off, so an agent that skipped its mode's path would
// connect to nothing.
const transparentListen = "127.0.0.1:9793"

// plan is what the outer test hands the inner one.
type plan struct {
	Store   storeServer `json:"store"`
	Cells   []string    `json:"cells"`
	Results string      `json:"results"` // directory for one JSON result per cell
}

// Result is one cell's outcome, written for the job summary.
type Result struct {
	Cell            string  `json:"cell"`
	Pass            bool    `json:"pass"`
	Seconds         float64 `json:"seconds"`
	Rows            int     `json:"rows,omitempty"`
	Scenarios       int     `json:"scenarios,omitempty"`
	GatedLeaks      int     `json:"gated_leaks"`
	LimitationLeaks int     `json:"limitation_leaks,omitempty"`
	CloudRequests   int     `json:"cloud_requests,omitempty"`
	MCPCalls        int     `json:"mcp_calls,omitempty"`
}

// TestMatrixInner runs the cells of one store inside test/e2e/sandbox.sh.
// TestMatrix starts it; on its own it skips.
func TestMatrixInner(t *testing.T) {
	path := os.Getenv("SCRIM_MATRIX_PLAN")
	if path == "" {
		t.Skip("started by TestMatrix inside the sandbox")
	}
	bin := harness.Require(t)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var p plan
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatal(err)
	}
	cells, err := ParseCells(strings.Join(p.Cells, " "))
	if err != nil {
		t.Fatal(err)
	}
	addr := ""
	if p.Store.Socket != "" {
		a, stop, err := relayTCPToUnix(p.Store.Socket)
		if err != nil {
			t.Fatal(err)
		}
		defer stop()
		addr = a
	}
	for i, c := range cells {
		t.Run(strings.ReplaceAll(c.String(), "/", "_"), func(t *testing.T) {
			start := time.Now()
			res := Result{Cell: c.String()}
			cs := newCellStore(p.Store, addr, t.TempDir(), fmt.Sprintf("matrix/c%02d", i))
			if c.Mode == ModeMCPOnly {
				runMCPCell(t, bin, cs, &res)
			} else {
				runTrafficCell(t, bin, c, cs, &res)
			}
			res.Pass = !t.Failed()
			res.Seconds = time.Since(start).Seconds()
			if p.Results != "" {
				b, _ := json.Marshal(res)
				_ = os.WriteFile(filepath.Join(p.Results, fmt.Sprintf("%02d.json", i)), b, 0o600)
			}
		})
	}
}

// daemonOptions configure one cell's scrim proxy.
type daemonOptions struct {
	store       *cellStore
	upstream    string // built-in routes' upstream
	transparent bool   // turn the transparent listener on
	providers   string // providers block, empty for none
	rules       string // policy rules file, empty for none
	env         []string
}

// startDaemon writes the configuration and starts `scrim proxy` with the
// real data plane, and waits until it is ready. Its directory is short, for
// the Unix sockets in it.
func startDaemon(t *testing.T, bin harness.Binaries, o daemonOptions) *harness.Daemon {
	t.Helper()
	dir, err := os.MkdirTemp("", "scrim-mx-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	d := &harness.Daemon{Bin: bin, Dir: dir, Config: filepath.Join(dir, "config.yaml"), Home: filepath.Join(dir, "home"),
		Admin: filepath.Join(dir, "admin.sock"), Log: &harness.SyncBuffer{}}
	for _, sub := range []string{"home", "xdg/config", "xdg/state", "xdg/data", "xdg/cache", "work"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	transparent := ""
	if o.transparent {
		transparent = "  transparent-listen: [" + transparentListen + "]\n"
	}
	var cfg strings.Builder
	fmt.Fprintf(&cfg, `apiVersion: scrim.dev/v1
kind: Config
state: {backend: memory}
stores:
%[5]sproxy:
  listen: 127.0.0.1:0
  forward-listen: 127.0.0.1:0
%[4]s  upstream: {anthropic: %[2]q, openai: %[2]q, gemini: %[2]q}
api: {socket: %[1]s/api.sock}
admin: {url: "unix:%[1]s/admin.sock"}
redaction: {placeholder-key-dir: %[1]s/keys}
tool-proxy: {ca: {dir: %[1]s/ca}}
notify: {terminal: {enabled: false}}
dataplane:
  path: %[3]s
  push-debounce: 10ms
`, dir, o.upstream, bin.DataPlane, transparent, o.store.Config())
	if o.providers != "" {
		cfg.WriteString("providers:\n" + o.providers)
	}
	if o.rules != "" {
		rules := filepath.Join(dir, "rules.yaml")
		if err := os.WriteFile(rules, []byte(o.rules), 0o600); err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(&cfg, "policy: {rules-file: %s}\n", rules)
	}
	if err := os.WriteFile(d.Config, []byte(cfg.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin.Scrim, "--config", d.Config, "proxy") //nolint:gosec // the binary under test
	cmd.Env = d.Env(append(o.store.env, o.env...)...)
	cmd.Stdout, cmd.Stderr = d.Log, d.Log
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGTERM}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { _ = cmd.Wait(); close(done) }()
	t.Cleanup(func() {
		_ = cmd.Process.Signal(syscall.SIGTERM)
		select {
		case <-done:
		case <-time.After(20 * time.Second):
			_ = cmd.Process.Kill()
			<-done
		}
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
			return d
		}
		select {
		case <-done:
			t.Fatalf("scrim proxy exited: %s", d.Log.String())
		case <-ctx.Done():
			t.Fatalf("scrim proxy not ready (%v %+v):\n%s", err, info.Problems, d.Log.String())
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// runFlags turn off what a matrix agent does not need from scrim run.
var runFlags = []string{"--run-mcp=false", "--run-scan-project=false", "--run-ssh-agent=false", "--run-fs-view=off"}

// startAgent starts this test binary as an agent process running the test
// named test, under `scrim run` unless bare, and stops it when the test ends.
func startAgent(t *testing.T, d *harness.Daemon, bare bool, test string, env []string, log *harness.SyncBuffer) *exec.Cmd {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	args := []string{self, "-test.run", "^" + test + "$", "-test.count=1"}
	var cmd *exec.Cmd
	if bare {
		cmd = exec.Command(args[0], args[1:]...) //nolint:gosec // this test binary
	} else {
		cmd = exec.Command(d.Bin.Scrim, append(append(append([]string{"--config", d.Config, "run"}, runFlags...), "--"), args...)...) //nolint:gosec // the binary under test
	}
	cmd.Dir = filepath.Join(d.Dir, "work")
	cmd.Env = d.Env(env...)
	cmd.Stdout, cmd.Stderr = log, log
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGTERM}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	return cmd
}

// startShim starts the agent shim of a traffic cell and returns its URL.
func startShim(t *testing.T, d *harness.Daemon, c Cell, env []string) string {
	t.Helper()
	addr := harness.FreePort(t)
	log := &harness.SyncBuffer{}
	env = append(env, "SCRIM_MATRIX_SHIM_LISTEN="+addr, "SCRIM_MATRIX_SHIM_MODE="+string(c.Mode), "SCRIM_MATRIX_PROVIDER="+string(c.Provider))
	cmd := startAgent(t, d, c.Mode == ModeTransparent, "TestMatrixShim", env, log)
	done := make(chan struct{})
	go func() { _ = cmd.Wait(); close(done) }()
	base := "http://" + addr
	t.Cleanup(func() {
		if resp, err := http.Get(base + "/_shim/exit"); err == nil {
			_ = resp.Body.Close()
		}
		select {
		case <-done:
		case <-time.After(20 * time.Second):
			_ = cmd.Process.Kill()
			<-done
		}
		if t.Failed() {
			t.Logf("agent shim log:\n%s", log.String())
		}
	})
	deadline := time.Now().Add(60 * time.Second)
	for {
		resp, err := http.Get(base + "/_shim/health")
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return base
			}
		}
		select {
		case <-done:
			t.Fatalf("the agent shim exited:\n%s", log.String())
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("the agent shim did not listen on %s:\n%s", addr, log.String())
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// caBundle writes scrim's CA certificates to a file the transparent agent
// trusts, as `scrim install` puts them in the system store.
func caBundle(t *testing.T, d *harness.Daemon) string {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for {
		certs, _ := filepath.Glob(filepath.Join(d.Dir, "ca", "gen", "*", "cert.pem"))
		if len(certs) > 0 {
			var b bytes.Buffer
			for _, c := range certs {
				pem, err := os.ReadFile(c)
				if err != nil {
					t.Fatal(err)
				}
				b.Write(pem)
			}
			out := filepath.Join(d.Dir, "ca-bundle.pem")
			if err := os.WriteFile(out, b.Bytes(), 0o600); err != nil {
				t.Fatal(err)
			}
			return out
		}
		if time.Now().After(deadline) {
			t.Fatal("scrim wrote no CA certificate")
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// runTrafficCell sends the leak suite through one mode to one provider route
// with the secrets in one store.
func runTrafficCell(t *testing.T, bin harness.Binaries, c Cell, cs *cellStore, res *Result) {
	ctx := t.Context()
	seeds := leak.GenerateSet()
	values := map[string]string{}
	for i, s := range seeds {
		values[fmt.Sprintf("seed-%d", i)] = s.Value()
	}
	seedFile := filepath.Join(t.TempDir(), "seeds.json")
	if err := leak.WriteSeedFile(seedFile, seeds); err != nil {
		t.Fatal(err)
	}

	upAddr := harness.FreePort(t)
	_, upPort, _ := net.SplitHostPort(upAddr)
	o := daemonOptions{store: cs, upstream: "http://" + upAddr, transparent: c.Mode == ModeTransparent}
	var cloud *cloudSetup
	if c.Provider.Cloud() {
		var err error
		if cloud, err = newCloudSetup(c.Provider, cs.FieldRef); err != nil {
			t.Fatal(err)
		}
		for k, v := range cloud.Values {
			values[k] = v
		}
		issuerURL := ""
		if cloud.Issuer != nil {
			isrv := httptest.NewServer(cloud.Issuer)
			t.Cleanup(isrv.Close)
			cloud.Issuer.URL, issuerURL = isrv.URL, isrv.URL
		}
		o.providers = cloud.Config(c.Provider, "http://"+c.Provider.Host()+":"+upPort, issuerURL)
	}
	if err := cs.Put(ctx, values); err != nil {
		t.Fatalf("seed the %s store: %v", cs.server.Kind, err)
	}

	d := startDaemon(t, bin, o)
	var env []string
	if c.Mode == ModeTransparent {
		env = append(env, "SSL_CERT_FILE="+caBundle(t, d))
	}
	// scrim run reads the configuration too, store credentials included.
	shim := startShim(t, d, c, append(env, cs.env...))

	api := c.Provider.API()
	var progress bytes.Buffer
	ao := audit.Options{
		Proxy: shim, UpstreamListen: upAddr, SeedsIn: seedFile,
		APIs: []fp.API{api}, Prefix: map[fp.API]string{api: "/" + c.Provider.Route()},
		Progress: &progress,
	}
	var front *fp.Cloud
	if cloud != nil {
		// The scenarios read replies in the Anthropic format; a cloud route
		// answers in its own (Bedrock's event stream), so cloud cells run the
		// bypass matrix, which reads what reached the provider.
		ao.Suites = []string{audit.SuiteMatrix}
		ao.WrapUpstream = func(s *fp.Server) http.Handler {
			front = fp.NewCloud(s, cloud.Opts)
			return front
		}
	}
	rep, err := audit.Run(ctx, ao)
	if rep != nil {
		res.GatedLeaks = rep.Summary.GatedLeaks + rep.Summary.ScenarioLeaks
		res.LimitationLeaks = rep.Summary.LimitationLeaks
		if rep.Matrix != nil {
			res.Rows = len(rep.Matrix.Results)
		}
		if rep.Scenarios != nil {
			res.Scenarios = len(rep.Scenarios.Results)
		}
	}
	if err != nil {
		var text bytes.Buffer
		if rep != nil {
			rep.WriteText(&text)
		}
		t.Fatalf("leak suite: %v\n%s\n%s", err, progress.String(), text.String())
	}
	t.Logf("%d matrix results, %d scenarios, 0 gated leaks (%d known-limitation leaks, not gated)", res.Rows, res.Scenarios, res.LimitationLeaks)
	if res.Rows == 0 {
		t.Error("no matrix row ran")
	}

	// Every request the cloud provider received was authenticated by scrim
	// with the credentials from the store (the gate above judged what the
	// requests carry, row by row).
	if front != nil {
		reqs := front.Requests()
		res.CloudRequests = len(reqs)
		if len(reqs) == 0 {
			t.Fatal("the cloud provider received nothing")
		}
		for _, q := range reqs {
			if q.Auth != "" {
				t.Errorf("request %d %s %s not authenticated: %s", q.Seq, q.Method, q.Path, q.Auth)
			}
			if strings.Contains(fmt.Sprint(q.Header), "fake-provider-key-not-a-seed") {
				t.Errorf("request %d carries the agent's own credentials", q.Seq)
			}
		}
		if cloud.Issuer != nil && len(cloud.Issuer.Refused()) > 0 {
			t.Errorf("token requests refused: %v", cloud.Issuer.Refused())
		}
	}
	checkLog(t, d, append(append([]leak.Seed{}, seeds...), cloudSeeds(cloud)...))
}

func cloudSeeds(c *cloudSetup) []leak.Seed {
	if c == nil {
		return nil
	}
	return c.Seeds
}

// checkLog fails when a value appears in scrim's own log.
func checkLog(t *testing.T, d *harness.Daemon, seeds []leak.Seed) {
	t.Helper()
	log := d.Log.String()
	for _, s := range seeds {
		if s.Len() >= 8 && strings.Contains(log, s.Value()) {
			t.Errorf("seed %s appears in scrim's log", s)
		}
	}
}
