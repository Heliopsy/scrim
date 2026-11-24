// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/heliopsy/scrim/internal/testing/pgtest"
	"github.com/heliopsy/scrim/internal/testing/podtest"
)

// BaseImage runs the replicas and the load generator: glibc and libgcc for
// the data plane, nothing else. The binaries are mounted read-only.
const BaseImage = "gcr.io/distroless/cc-debian13:nonroot@sha256:cb87acc574abe719b6e5c547384defa2f7b1f24af9605d3f618cf852495d8be2"

type runOpts struct {
	profiles, profile  string
	scrim, dataplane   string
	driver             string
	out                string
	events             string
	sabotage           string
	machine            string
	keep               bool
	overrides          RunParams
	durationS, warmupS string
	timeout            time.Duration
}

func runMain(args []string) error {
	var o runOpts
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.StringVar(&o.profiles, "profiles", "test/load/profiles.json", "profiles file")
	fs.StringVar(&o.profile, "profile", "smoke", "profile in the profiles file")
	fs.StringVar(&o.scrim, "scrim", "", "scrim binary, built with CGO_ENABLED=0")
	fs.StringVar(&o.dataplane, "dataplane", "", "release data plane binary")
	fs.StringVar(&o.driver, "driver", "", "scrim-load binary for the load generator container (default: this binary)")
	fs.StringVar(&o.out, "out", "load-results", "output directory (result.json, report.md, logs)")
	fs.StringVar(&o.events, "events", "valkey", "events backend between the replicas: valkey or nats")
	fs.StringVar(&o.sabotage, "sabotage", "", "break one thing on purpose to watch the checks fail: leak (bulk values not redacted) or events (replicas configured alone, local events)")
	fs.StringVar(&o.machine, "machine", "", "machine description for the report (default: host name, CPU count)")
	fs.BoolVar(&o.keep, "keep", false, "leave the containers running for inspection")
	fs.IntVar(&o.overrides.Replicas, "replicas", 0, "override: replicas")
	fs.IntVar(&o.overrides.Streams, "streams", 0, "override: concurrent agent streams")
	fs.IntVar(&o.overrides.Sessions, "sessions", 0, "override: sessions")
	fs.IntVar(&o.overrides.ApprovalWorkers, "approval-workers", 0, "override: approval workers")
	fs.StringVar(&o.durationS, "duration", "", "override: measured duration")
	fs.StringVar(&o.warmupS, "warmup", "", "override: warm-up")
	fs.DurationVar(&o.timeout, "timeout", 0, "give up after this long (default: warm-up + duration + 5m)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	prof, err := loadProfile(o.profiles, o.profile)
	if err != nil {
		return err
	}
	p := &prof.Run
	if v := o.overrides; v.Replicas > 0 {
		p.Replicas = v.Replicas
	}
	if v := o.overrides.Streams; v > 0 {
		p.Streams = v
		p.Sessions = min(p.Sessions, v)
	}
	if v := o.overrides.Sessions; v > 0 {
		p.Sessions = v
	}
	if v := o.overrides.ApprovalWorkers; v > 0 {
		p.ApprovalWorkers = v
	}
	for _, f := range []struct {
		s string
		d *Duration
	}{{o.durationS, &p.Duration}, {o.warmupS, &p.Warmup}} {
		if f.s != "" {
			v, err := time.ParseDuration(f.s)
			if err != nil {
				return err
			}
			*f.d = Duration(v)
		}
	}
	if err := p.validate(); err != nil {
		return err
	}
	if o.events != "valkey" && o.events != "nats" {
		return fmt.Errorf("--events %q: valkey or nats", o.events)
	}
	if o.sabotage != "" && o.sabotage != "leak" && o.sabotage != "events" {
		return fmt.Errorf("--sabotage %q: leak or events", o.sabotage)
	}
	if o.scrim == "" || o.dataplane == "" {
		return errors.New("--scrim and --dataplane are required (test/load/run.sh builds them)")
	}
	if o.driver == "" {
		if o.driver, err = os.Executable(); err != nil {
			return err
		}
	}
	if o.timeout == 0 {
		o.timeout = p.Warmup.D() + p.Duration.D() + 5*time.Minute
	}
	if o.machine == "" {
		h, _ := os.Hostname()
		o.machine = fmt.Sprintf("%s, %d CPUs", h, runtime.NumCPU())
	}
	return orchestrate(o, prof)
}

// world is one run's containers and files.
type world struct {
	o     runOpts
	prof  Profile
	id    string
	dir   string // absolute output directory
	rdir  string // run files, mounted at the same path in every container
	plan  Plan
	names []string
	repl  []string // replica container names
	drv   string
	pgDSN string
	// phKey is the placeholder key every replica shares: more than one
	// replica refuses to start without redaction.placeholder-keys.
	phKey string
	ports map[string]int
	noCPU bool
}

func orchestrate(o runOpts, prof Profile) error {
	ctx, cancel := context.WithTimeout(context.Background(), o.timeout)
	defer cancel()
	abs, err := filepath.Abs(o.out)
	if err != nil {
		return err
	}
	w := &world{o: o, prof: prof, id: randHex(3), dir: abs, ports: map[string]int{}}
	w.rdir = filepath.Join(abs, "run")
	if err := os.RemoveAll(w.rdir); err != nil {
		return err
	}
	if err := os.MkdirAll(w.rdir, 0o700); err != nil {
		return err
	}
	for _, b := range []string{o.scrim, o.dataplane, o.driver} {
		if _, err := os.Stat(b); err != nil {
			return err
		}
	}
	defer w.cleanup()
	if err := w.checkCgroups(ctx); err != nil {
		return err
	}
	if err := w.prepare(); err != nil {
		return err
	}
	if err := w.startServices(ctx); err != nil {
		return err
	}
	if err := w.startReplicas(ctx); err != nil {
		return err
	}
	samp := newSampler(w)
	sampCtx, stopSamp := context.WithCancel(ctx)
	var sw sync.WaitGroup
	sw.Go(func() { samp.loop(sampCtx) })
	idle := samp.snapshot(ctx)

	logf("load generator: %d streams for %s after %s warm-up", prof.Run.Streams, prof.Run.Duration.D(), prof.Run.Warmup.D())
	driveErr := w.drive(ctx)
	stopSamp()
	sw.Wait()
	w.saveLogs()
	if driveErr != nil {
		return driveErr
	}
	b, err := os.ReadFile(w.plan.ResultFile)
	if err != nil {
		return fmt.Errorf("the load generator wrote no result: %w", err)
	}
	var dr DriveResult
	if err := json.Unmarshal(b, &dr); err != nil {
		return err
	}
	res := w.assemble(dr, samp, idle)
	res.Checks, res.Pass = evaluate(res, prof.Thresholds)
	if err := writeResult(w.dir, res); err != nil {
		return err
	}
	for _, c := range res.Checks {
		mark := "ok  "
		if !c.Pass {
			mark = "FAIL"
		}
		logf("%s %-34s %s (limit %s)", mark, c.Name, c.Value, c.Limit)
	}
	logf("wrote %s and %s", filepath.Join(w.dir, "result.json"), filepath.Join(w.dir, "report.md"))
	if !res.Pass {
		return errors.New("thresholds missed")
	}
	return nil
}

// checkCgroups refuses to run without memory limits: an unbounded load
// test can take a desktop down with it. Without the cpu controller the CPU
// limits are dropped and the report says so.
func (w *world) checkCgroups(ctx context.Context) error {
	out, err := podman(ctx, "info", "--format", "{{.Host.CgroupControllers}}")
	if err != nil {
		return err
	}
	ctrls := strings.Fields(strings.Trim(out, "[]"))
	if !slices.Contains(ctrls, "memory") {
		return fmt.Errorf("podman reports cgroup controllers %v: the memory controller is needed to cap the containers", ctrls)
	}
	if !slices.Contains(ctrls, "cpu") {
		logf("warning: no cpu cgroup controller for rootless podman; CPU limits are not enforced")
		w.noCPU = true
	}
	return nil
}

// cpus returns the --cpus flag for a limit, or nothing without the cpu
// controller.
func (w *world) cpus(limit string) []string {
	if w.noCPU {
		return nil
	}
	return []string{"--cpus", limit}
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// Listen ports come from below the kernel's ephemeral range (Linux default
// 32768-60999). A port the kernel hands out for 127.0.0.1:0 is an ephemeral
// one, and under load the generator's thousands of outbound connections can
// take it as a source port before the replica binds it ("address already in
// use"). Outbound connections never use ports below the ephemeral range.
const (
	portLow  = 20000
	portHigh = 32000
)

// freePort returns a port in [portLow, portHigh) that binds now and is not in
// used, starting from a random offset so concurrent runs rarely collide.
func freePort(used map[int]bool) (int, error) {
	var r [2]byte
	_, _ = rand.Read(r[:])
	span := portHigh - portLow
	start := int(r[0])<<8 | int(r[1])
	for i := 0; i < span; i++ {
		p := portLow + (start+i)%span
		if used[p] {
			continue
		}
		l, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(p)))
		if err != nil {
			continue
		}
		_ = l.Close()
		return p, nil
	}
	return 0, fmt.Errorf("no free port in %d-%d", portLow, portHigh-1)
}

func (w *world) port(name string) int {
	if p, ok := w.ports[name]; ok {
		return p
	}
	used := make(map[int]bool, len(w.ports))
	for _, p := range w.ports {
		used[p] = true
	}
	p, err := freePort(used)
	if err != nil {
		panic(err)
	}
	w.ports[name] = p
	return p
}

const alnum = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

// seedValue is a fresh 40-character value, generated at run time.
func seedValue() []byte {
	b := make([]byte, 40)
	r := make([]byte, 40)
	_, _ = rand.Read(r)
	for i := range b {
		b[i] = alnum[int(r[i])%len(alnum)]
	}
	return b
}

func (w *world) prepare() error {
	p := w.prof.Run
	seeds := filepath.Join(w.rdir, "seeds")
	for _, set := range []struct {
		dir, prefix string
		n           int
	}{{"bulk", "b", p.BulkSecrets}, {"notes", "n", p.Notes}, {"creds", "c", p.Creds}, {"approve", "a", p.ApprovalWorkers}} {
		d := filepath.Join(seeds, set.dir)
		if err := os.MkdirAll(d, 0o700); err != nil {
			return err
		}
		for i := range set.n {
			if err := os.WriteFile(filepath.Join(d, fmt.Sprintf("%s%d", set.prefix, i)), seedValue(), 0o600); err != nil {
				return err
			}
		}
	}
	if err := w.writePKI(); err != nil {
		return err
	}
	rules := `default: deny
rules:
  - name: approve-load
    decision: ask
    when: op == "inject" && secret.ref.glob("load://approve/*")
    reason: load test approval
    grant: {ttl: 10m}
`
	if err := os.WriteFile(filepath.Join(w.rdir, "rules.yaml"), []byte(rules), 0o600); err != nil {
		return err
	}
	w.phKey = randHex(24)
	w.plan = Plan{
		Profile: w.o.profile, Run: p, SeedsDir: seeds,
		ProviderAddr: fmt.Sprintf("127.0.0.1:%d", w.port("provider")),
		ToolAddr:     fmt.Sprintf("127.0.0.1:%d", w.port("tool")),
		ToolCertFile: filepath.Join(w.rdir, "tool-cert.pem"), ToolKeyFile: filepath.Join(w.rdir, "tool-key.pem"),
		AdminToken: randHex(24), ResultFile: filepath.Join(w.rdir, "drive.json"), Sabotage: w.o.sabotage,
	}
	w.pgDSN = fmt.Sprintf("postgres://postgres:load@127.0.0.1:%d/scrim?sslmode=disable", w.port("postgres"))
	for i := range p.Replicas {
		name := fmt.Sprintf("r%d", i)
		e := Endpoints{
			Name:      name,
			LLM:       fmt.Sprintf("http://127.0.0.1:%d", w.port(name+"-llm")),
			Forward:   fmt.Sprintf("127.0.0.1:%d", w.port(name+"-forward")),
			Admin:     fmt.Sprintf("http://127.0.0.1:%d", w.port(name+"-admin")),
			Metrics:   fmt.Sprintf("http://127.0.0.1:%d", w.port(name+"-metrics")),
			APISocket: filepath.Join(w.rdir, name, "api.sock"),
		}
		w.plan.Replicas = append(w.plan.Replicas, e)
		if err := os.MkdirAll(filepath.Join(w.rdir, name, "home"), 0o700); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(w.rdir, name, "config.yaml"), []byte(w.config(e)), 0o600); err != nil {
			return err
		}
	}
	b, err := json.MarshalIndent(w.plan, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(w.rdir, "plan.json"), b, 0o600)
}

// config is one replica's scrim configuration.
func (w *world) config(e Endpoints) string {
	p := w.prof.Run
	redact := `["load://bulk/*", "load://notes/*", "load://creds/*", "load://approve/*"]`
	replicas := p.Replicas
	events := ""
	switch {
	case w.o.sabotage == "events":
		// Each replica believes it is alone: no wake-ups between them, so
		// only the polls (far longer than the approval timeout) could
		// release a request held elsewhere.
		replicas = 1
		events = "events: {backend: local, poll-interval: 50s}\n"
	case w.o.events == "valkey":
		events = fmt.Sprintf("events: {backend: valkey, poll-interval: 50s, valkey: {channel: \"scrim:load:%s\"}}\n", w.id)
	case w.o.events == "nats":
		events = fmt.Sprintf("events: {backend: nats, poll-interval: 50s, nats: {subject: \"scrim.load.%s\"}}\n", w.id)
	}
	if w.o.sabotage == "leak" {
		redact = `["load://notes/*", "load://creds/*", "load://approve/*"]`
	}
	ratelimit := "ratelimit:\n  backend: local\n"
	if w.o.events == "valkey" {
		ratelimit = fmt.Sprintf("ratelimit:\n  backend: valkey\n  valkey: {prefix: \"scrim:load:%s:\"}\n", w.id)
	}
	ratelimit += "  agent-api: {rate: 1000000, interval: 1m, burst: 100000}\n  approvals: {rate: 1000000, interval: 1m, burst: 100000}\n"
	tool := w.plan.ToolAddr
	return fmt.Sprintf(`apiVersion: scrim.dev/v1
kind: Config
deployment: {replicas: %d}
state:
  backend: postgres
  postgres: {dsn: "env:SCRIM_LOAD_PG_DSN", max-conns: 20}
%svalkey: {addresses: ["127.0.0.1:%d"]}
nats: {servers: ["nats://127.0.0.1:%d"]}
%sapprovals: {timeout: 40s, poll-interval: 50s}
policy: {rules-file: %s, deny-all-refresh: 50s}
stores:
  load:
    kind: file
    root: %s
    format: raw
    trim-newline: false
    redact: %s
catalog:
  entries:
    notes: {prefix: "load://notes/*", template: "SCRIM_LOADNOTE_{NAME}", class: display}
    creds: {prefix: "load://creds/*", template: "SCRIM_LOADCRED_{NAME}", hosts: ["%s"]}
    approve: {prefix: "load://approve/*", template: "SCRIM_LOADAPPROVE_{NAME}", hosts: ["%s"]}
proxy:
  listen: %s
  forward-listen: %s
  upstream: {anthropic: "http://%s"}
api: {socket: %s}
admin: {url: "%s", token: "env:SCRIM_LOAD_ADMIN_TOKEN"}
metrics: {enabled: true, listen: %s}
redaction:
  placeholder-key-dir: %s
  placeholder-keys: {load: {version: 1, key: "env:SCRIM_LOAD_PLACEHOLDER_KEY"}}
tool-proxy: {ca: {dir: %s}}
dataplane: {upstream-ca-file: %s}
notify: {terminal: {enabled: false}}
log: {format: json}
`, replicas, events, w.port("valkey"), w.port("nats"), ratelimit,
		filepath.Join(w.rdir, "rules.yaml"), w.plan.SeedsDir, redact, tool, tool,
		strings.TrimPrefix(e.LLM, "http://"), e.Forward, w.plan.ProviderAddr, e.APISocket, e.Admin,
		strings.TrimPrefix(e.Metrics, "http://"), filepath.Join(w.rdir, "keys"), filepath.Join(w.rdir, "ca"),
		filepath.Join(w.rdir, "tool-ca.pem"))
}

// writePKI writes a CA and a 127.0.0.1 server certificate for the fake
// tool API; the data plane trusts the CA as an upstream root.
func (w *world) writePKI() error {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	now := time.Now()
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "scrim load test tool CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return err
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		return err
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	leafTmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "127.0.0.1"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour), IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		return err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		return err
	}
	files := map[string][]byte{
		"tool-ca.pem":   pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
		"tool-cert.pem": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}),
		"tool-key.pem":  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
	}
	for n, b := range files {
		if err := os.WriteFile(filepath.Join(w.rdir, n), b, 0o600); err != nil {
			return err
		}
	}
	return nil
}

// ---------------------------------------------------------------- containers

func podman(ctx context.Context, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "podman", args...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return out.String(), fmt.Errorf("podman %s: %w: %s", args[0], err, strings.TrimSpace(errb.String()))
	}
	return strings.TrimSpace(out.String()), nil
}

func (w *world) name(role string) string { return "scrim-load-" + w.id + "-" + role }

// start runs a detached container on the host network, capped at mem
// (no swap) and, with the cpu controller, at cpus.
func (w *world) start(ctx context.Context, role, mem, cpus string, args ...string) (string, error) {
	n := w.name(role)
	base := []string{"run", "-d", "--name", n, "--label", "scrim-load=" + w.id, "--network", "host", "--memory", mem, "--memory-swap", mem}
	base = append(base, w.cpus(cpus)...)
	w.names = append(w.names, n)
	_, err := podman(ctx, append(base, args...)...)
	return n, err
}

func (w *world) startServices(ctx context.Context) error {
	p := w.prof.Run
	logf("starting PostgreSQL and %s", w.o.events)
	if _, err := w.start(ctx, "postgres", p.PostgresMemory, p.PostgresCPUs, "-e", "POSTGRES_PASSWORD=load", "-e", "POSTGRES_DB=scrim", pgtest.DefaultImage,
		"postgres", "-p", strconv.Itoa(w.port("postgres")), "-c", "listen_addresses=127.0.0.1",
		"-c", "fsync=off", "-c", "synchronous_commit=off", "-c", "full_page_writes=off", "-c", "max_connections=300"); err != nil {
		return err
	}
	switch w.o.events {
	case "valkey":
		if _, err := w.start(ctx, "valkey", "256m", "0.5", podtest.ValkeyImage,
			"valkey-server", "--port", strconv.Itoa(w.port("valkey")), "--bind", "127.0.0.1", "--save", "", "--appendonly", "no"); err != nil {
			return err
		}
	case "nats":
		if _, err := w.start(ctx, "nats", "128m", "0.5", podtest.NATSImage,
			"-a", "127.0.0.1", "-p", strconv.Itoa(w.port("nats"))); err != nil {
			return err
		}
	}
	deadline := time.Now().Add(90 * time.Second)
	for {
		conn, err := pgx.Connect(ctx, w.pgDSN)
		if err == nil {
			err = conn.Ping(ctx)
			_ = conn.Close(ctx)
			if err == nil {
				break
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("PostgreSQL not ready: %w", err)
		}
		time.Sleep(300 * time.Millisecond)
	}
	svc := w.o.events
	for {
		c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", w.port(svc)), time.Second)
		if err == nil {
			_ = c.Close()
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("%s not ready: %w", svc, err)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func (w *world) startReplicas(ctx context.Context) error {
	p := w.prof.Run
	bin := filepath.Join(w.rdir, "bin")
	if err := os.MkdirAll(bin, 0o700); err != nil {
		return err
	}
	for src, dst := range map[string]string{w.o.scrim: "scrim", w.o.dataplane: "scrim-dataplane", w.o.driver: "scrim-load"} {
		if err := copyFile(src, filepath.Join(bin, dst)); err != nil {
			return err
		}
	}
	startOne := func(i int) error {
		e := w.plan.Replicas[i]
		n, err := w.start(ctx, e.Name, p.ReplicaMemory, p.ReplicaCPUs, "--pid", "host", "--userns", "keep-id", "--user", userSpec(),
			"-v", w.dir+":"+w.dir, "-w", w.rdir,
			"-e", "HOME="+filepath.Join(w.rdir, e.Name, "home"),
			"-e", "SCRIM_DATAPLANE_PATH="+filepath.Join(bin, "scrim-dataplane"),
			"-e", "SCRIM_LOAD_PG_DSN="+w.pgDSN, "-e", "SCRIM_LOAD_ADMIN_TOKEN="+w.plan.AdminToken,
			"-e", "SCRIM_LOAD_PLACEHOLDER_KEY="+w.phKey,
			BaseImage, filepath.Join(bin, "scrim"), "--config", filepath.Join(w.rdir, e.Name, "config.yaml"), "proxy")
		if err != nil {
			return err
		}
		w.repl = append(w.repl, n)
		return w.waitReady(ctx, i)
	}
	// The first replica creates the placeholder keys, the CA and the
	// schema; the others start together and share them.
	logf("starting replica r0")
	if err := startOne(0); err != nil {
		return err
	}
	logf("starting replicas r1..r%d", p.Replicas-1)
	for i := 1; i < p.Replicas; i++ {
		if err := startOne(i); err != nil {
			return err
		}
	}
	return nil
}

func (w *world) waitReady(ctx context.Context, i int) error {
	e := w.plan.Replicas[i]
	deadline := time.Now().Add(90 * time.Second)
	for {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, e.Metrics+"/readyz", nil)
		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
			err = fmt.Errorf("readyz %d", resp.StatusCode)
		}
		if st, _ := podman(ctx, "inspect", "-f", "{{.State.Status}}", w.name(e.Name)); st == "exited" {
			logs := containerLogs(w.name(e.Name), 40)
			return fmt.Errorf("replica %s exited:\n%s", e.Name, logs)
		}
		if time.Now().After(deadline) {
			logs := containerLogs(w.name(e.Name), 40)
			return fmt.Errorf("replica %s not ready: %w\n%s", e.Name, err, logs)
		}
		time.Sleep(300 * time.Millisecond)
	}
}

func (w *world) drive(ctx context.Context) error {
	p := w.prof.Run
	limit, err := parseMem(p.DriverMemory)
	if err != nil {
		return err
	}
	bin := filepath.Join(w.rdir, "bin")
	n, err := w.start(ctx, "driver", p.DriverMemory, p.DriverCPUs, "--pid", "host", "--userns", "keep-id", "--user", userSpec(),
		"-e", fmt.Sprintf("GOMEMLIMIT=%dMiB", limit*85/100>>20), "-e", "SCRIM_LOAD_CPUPROFILE="+os.Getenv("SCRIM_LOAD_CPUPROFILE"),
		"-v", w.dir+":"+w.dir, "-w", w.rdir,
		BaseImage, filepath.Join(bin, "scrim-load"), "drive", "--plan", filepath.Join(w.rdir, "plan.json"))
	if err != nil {
		return err
	}
	w.drv = n
	code, err := podman(ctx, "wait", n)
	if err != nil {
		return err
	}
	if code != "0" {
		logs := containerLogs(n, 60)
		return fmt.Errorf("the load generator exited %s:\n%s", code, logs)
	}
	return nil
}

// userSpec runs a container process as the invoking user (keep-id maps it
// to the same id), so it can use the run directory; the base image's own
// user would override keep-id.
func userSpec() string { return fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()) }

func copyFile(src, dst string) error {
	b, err := os.ReadFile(src) //nolint:gosec // binaries the operator names
	if err != nil {
		return err
	}
	return os.WriteFile(dst, b, 0o700) //nolint:gosec // executables
}

// parseMem reads a podman memory size (512m, 1g) in bytes.
func parseMem(s string) (int64, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	mult := int64(1)
	switch {
	case strings.HasSuffix(s, "g"):
		mult, s = 1<<30, strings.TrimSuffix(s, "g")
	case strings.HasSuffix(s, "m"):
		mult, s = 1<<20, strings.TrimSuffix(s, "m")
	case strings.HasSuffix(s, "k"):
		mult, s = 1<<10, strings.TrimSuffix(s, "k")
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0, fmt.Errorf("memory size %q: %w", s, err)
	}
	return int64(v * float64(mult)), nil
}

// containerLogs returns the last lines a container wrote to stdout and
// stderr.
func containerLogs(name string, tail int) string {
	out, _ := exec.Command("podman", "logs", "--tail", strconv.Itoa(tail), name).CombinedOutput() //nolint:gosec // our own container names
	return string(out)
}

// saveLogs keeps every container's log next to the result and scans the
// replicas' logs for seeded values.
func (w *world) saveLogs() {
	logs := filepath.Join(w.dir, "logs")
	_ = os.MkdirAll(logs, 0o700)
	for _, n := range w.names {
		cmd := exec.Command("podman", "logs", n) //nolint:gosec // our own container names
		out, _ := cmd.CombinedOutput()
		_ = os.WriteFile(filepath.Join(logs, strings.TrimPrefix(n, "scrim-load-"+w.id+"-")+".log"), out, 0o600)
	}
}

func (w *world) cleanup() {
	if w.o.keep {
		logf("--keep: containers left running; remove them with: podman rm -f -v $(podman ps -aq --filter label=scrim-load=%s)", w.id)
		return
	}
	if len(w.names) > 0 {
		args := append([]string{"rm", "-f", "-v", "-t", "5"}, w.names...)
		if _, err := podman(context.Background(), args...); err != nil {
			logf("cleanup: %v", err)
		}
	}
	// Sockets, keys and seeds of this run; the logs and results stay.
	_ = os.RemoveAll(w.rdir)
}
