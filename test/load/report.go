// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// Result is result.json: the conditions, everything measured and the
// verdict of every threshold.
type Result struct {
	Schema          int         `json:"schema"`
	Profile         string      `json:"profile"`
	Started         time.Time   `json:"started"`
	Machine         string      `json:"machine"`
	Conditions      Conditions  `json:"conditions"`
	Drive           DriveResult `json:"measured"`
	Resources       []Resources `json:"resources"`
	MemPerStreamKiB float64     `json:"memory_per_stream_kib"`
	// CPUMsPerRequest is the replicas' CPU time per provider request and
	// its tool call, approvals and everything else included.
	CPUMsPerRequest float64    `json:"replica_cpu_ms_per_provider_request"`
	Thresholds      Thresholds `json:"thresholds"`
	Checks          []Check    `json:"checks"`
	Pass            bool       `json:"pass"`
}

// Conditions under which the numbers were taken.
type Conditions struct {
	Run       RunParams `json:"run"`
	Events    string    `json:"events_backend"`
	State     string    `json:"state_backend"`
	Sabotage  string    `json:"sabotage,omitempty"`
	Commit    string    `json:"commit,omitempty"`
	Kernel    string    `json:"kernel,omitempty"`
	CPUModel  string    `json:"cpu_model,omitempty"`
	CPUs      int       `json:"host_cpus"`
	Podman    string    `json:"podman,omitempty"`
	GoVersion string    `json:"go"`
}

// Check is one threshold and its outcome.
type Check struct {
	Name  string `json:"name"`
	Value string `json:"value"`
	Limit string `json:"limit"`
	Pass  bool   `json:"pass"`
}

func (w *world) assemble(dr DriveResult, s *sampler, idle map[string]float64) Result {
	p := w.prof.Run
	res := Result{Schema: 1, Profile: w.o.profile, Started: dr.WindowStart, Machine: w.o.machine, Drive: dr, Thresholds: w.prof.Thresholds}
	res.Conditions = Conditions{Run: p, Events: w.o.events, State: "postgres", Sabotage: w.o.sabotage, CPUs: runtime.NumCPU(), GoVersion: runtime.Version()}
	if w.o.sabotage == "events" {
		res.Conditions.Events = "local (sabotage)"
	}
	if out, err := exec.Command("git", "rev-parse", "--short=12", "HEAD").Output(); err == nil {
		res.Conditions.Commit = strings.TrimSpace(string(out))
	}
	if b, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		res.Conditions.Kernel = strings.TrimSpace(string(b))
	}
	if b, err := os.ReadFile("/proc/cpuinfo"); err == nil {
		for _, l := range strings.Split(string(b), "\n") {
			if k, v, ok := strings.Cut(l, ":"); ok && strings.TrimSpace(k) == "model name" {
				res.Conditions.CPUModel = strings.TrimSpace(v)
				break
			}
		}
	}
	if v, err := exec.Command("podman", "version", "--format", "{{.Client.Version}}").Output(); err == nil {
		res.Conditions.Podman = strings.TrimSpace(string(v))
	}
	repLimit, _ := parseMem(p.ReplicaMemory)
	perReplica := float64(p.Streams) / float64(p.Replicas)
	growth := 0.0
	for _, e := range w.plan.Replicas {
		r := s.resources(e.Name, dr.WindowStart, dr.WindowEnd, idle[e.Name], repLimit, p.ReplicaCPUs)
		res.Resources = append(res.Resources, r)
		growth = max(growth, r.AnonMaxMiB-r.IdleAnonMiB)
	}
	cores := 0.0
	for _, r := range res.Resources {
		cores += r.CPUCoresMean
	}
	if dr.Throughput.LLMPerSecond > 0 {
		res.CPUMsPerRequest = round3(cores * 1000 / dr.Throughput.LLMPerSecond)
	}
	if perReplica > 0 {
		res.MemPerStreamKiB = round3(growth * 1024 / perReplica)
	}
	drvLimit, _ := parseMem(p.DriverMemory)
	pgLimit, _ := parseMem(p.PostgresMemory)
	res.Resources = append(res.Resources,
		s.resources("driver", dr.WindowStart, dr.WindowEnd, 0, drvLimit, p.DriverCPUs),
		s.resources("postgres", dr.WindowStart, dr.WindowEnd, 0, pgLimit, p.PostgresCPUs))
	res.Drive.Correctness.LogLeaks = w.scanLogs()
	res.Drive.Correctness.Leaks += res.Drive.Correctness.LogLeaks
	return res
}

// scanLogs counts seeded values (and the admin token) in the replicas' logs.
func (w *world) scanLogs() int64 {
	var values [][]byte
	_ = filepath.WalkDir(w.plan.SeedsDir, func(path string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			if b, err := os.ReadFile(path); err == nil { //nolint:gosec // the run's seed files
				values = append(values, b)
			}
		}
		return nil
	})
	seeded := len(values)
	values = append(values, []byte(w.plan.AdminToken))
	sc := newScanner(values, seeded)
	var n int64
	for _, e := range w.plan.Replicas {
		b, err := os.ReadFile(filepath.Join(w.dir, "logs", e.Name+".log"))
		if err != nil {
			continue
		}
		n += int64(len(sc.find(b)))
	}
	return n
}

func evaluate(r Result, t Thresholds) ([]Check, bool) {
	var cs []Check
	add := func(name string, pass bool, value, limit string) {
		cs = append(cs, Check{Name: name, Value: value, Limit: limit, Pass: pass})
	}
	d := r.Drive
	c := d.Correctness
	a := d.Approvals
	add("leaks", c.Leaks <= int64(t.MaxLeaks), fmt.Sprintf("%d (provider %d, tool API %d, agent %d, unredacted %d, logs %d)",
		c.Leaks, c.LeaksToProvider, c.LeaksToToolAPI, c.LeaksToAgent, c.UnredactedMarkers, c.LogLeaks), fmt.Sprintf("<= %d", t.MaxLeaks))
	add("restore failures", c.RestoreFailures <= int64(t.MaxRestoreFailures) && c.RestoreChecks > 0,
		fmt.Sprintf("%d of %d checks", c.RestoreFailures, c.RestoreChecks), fmt.Sprintf("<= %d, checks > 0", t.MaxRestoreFailures))
	add("injection failures", c.InjectionFailures <= int64(t.MaxInjectionFailures) && c.Injections > 0,
		fmt.Sprintf("%d of %d injections", c.InjectionFailures, c.Injections), fmt.Sprintf("<= %d, injections > 0", t.MaxInjectionFailures))
	add("approval failures", a.Failures <= int64(t.MaxApprovalFailures) && a.Released > 0 && a.Revoked > 0,
		fmt.Sprintf("%d (not held %d, late %d, timeouts %d); %d released across replicas, %d grants revoked", a.Failures, a.NotHeld, a.Late, a.Timeouts, a.Released, a.Revoked),
		fmt.Sprintf("<= %d, released and revoked > 0", t.MaxApprovalFailures))
	add("events agree", d.Events.Agree, fmt.Sprintf("last ids %v", d.Events.LastIDs), "equal on every replica")
	add("error rate", d.Errors.Rate <= t.MaxErrorRate, fmt.Sprintf("%.5f (%d of %d)", d.Errors.Rate, d.Errors.Total, d.Errors.Ops), fmt.Sprintf("<= %g", t.MaxErrorRate))
	frac := 0.0
	if d.Streams.Target > 0 {
		frac = d.Streams.Mean / float64(d.Streams.Target)
	}
	add("concurrent streams", frac >= t.MinStreamsReached, fmt.Sprintf("mean %.0f, max %.0f of %d", d.Streams.Mean, d.Streams.Max, d.Streams.Target),
		fmt.Sprintf("mean >= %.0f%% of target", t.MinStreamsReached*100))
	add("throughput", d.Throughput.LLMPerSecond >= t.MinLLMRequestsPerSecond, fmt.Sprintf("%.1f provider requests/s, %.1f tool requests/s", d.Throughput.LLMPerSecond, d.Throughput.ToolPerSecond),
		fmt.Sprintf(">= %g provider requests/s", t.MinLLMRequestsPerSecond))
	sr := d.Scrim
	add("scrim request added p99", sr.RequestAdded.Count > 0 && sr.RequestWithin5ms >= 0.99 && t.ScrimRequestAddedP99Ms >= 5,
		fmt.Sprintf("%.3f ms (%.2f%% within 5 ms, %.0f requests)", sr.RequestAddedP99Ms, sr.RequestWithin5ms*100, sr.RequestAdded.Count), fmt.Sprintf("<= %g ms", t.ScrimRequestAddedP99Ms))
	add("scrim restore chunk p99", sr.RestoreChunk.Count > 0 && sr.RestoreChunkWithin50u >= 0.99 && t.ScrimChunkP99Us >= 50,
		fmt.Sprintf("%.1f µs (%.2f%% within 50 µs, %.0f chunks)", sr.RestoreChunkP99Us, sr.RestoreChunkWithin50u*100, sr.RestoreChunk.Count), fmt.Sprintf("<= %g µs", t.ScrimChunkP99Us))
	add("client-observed added p99", d.Latency.TotalAdded.Count > 0 && d.Latency.TotalAdded.P99 <= t.ClientAddedP99Ms,
		fmt.Sprintf("%.2f ms (request %.2f, first byte %.2f)", d.Latency.TotalAdded.P99, d.Latency.RequestAdded.P99, d.Latency.FirstByte.P99), fmt.Sprintf("<= %g ms", t.ClientAddedP99Ms))
	add("approval release p99", a.ReleaseLag.Count > 0 && a.ReleaseLag.P99 <= t.ApprovalReleaseP99Ms,
		fmt.Sprintf("%.2f ms (max %.2f, %d releases)", a.ReleaseLag.P99, a.ReleaseLag.Max, a.ReleaseLag.Count), fmt.Sprintf("<= %g ms", t.ApprovalReleaseP99Ms))
	memOK, worst, ooms := true, 0.0, 0.0
	for _, rs := range r.Resources {
		if !strings.HasPrefix(rs.Role, "r") || rs.LimitMiB == 0 {
			continue
		}
		f := max(rs.MemMaxMiB, rs.PeakMiB) / rs.LimitMiB
		worst = max(worst, f)
		ooms += rs.OOMKills
		memOK = memOK && f <= t.MaxReplicaMemoryFraction
	}
	add("replica memory", memOK && ooms == 0, fmt.Sprintf("%.0f%% of the limit at peak, %.0f OOM kills", worst*100, ooms), fmt.Sprintf("<= %.0f%%, no OOM kill", t.MaxReplicaMemoryFraction*100))
	add("memory per stream", r.MemPerStreamKiB <= t.MaxMemoryPerStreamKiB, fmt.Sprintf("%.1f KiB", r.MemPerStreamKiB), fmt.Sprintf("<= %g KiB", t.MaxMemoryPerStreamKiB))
	pass := true
	for _, c := range cs {
		pass = pass && c.Pass
	}
	return cs, pass
}

// dataPlaneCPU is everything in a replica that is not the control plane:
// the data plane runs from a memory file descriptor, so its process name is
// a number.
func dataPlaneCPU(by map[string]float64) float64 {
	sum := 0.0
	for k, v := range by {
		if k != "scrim" {
			sum += v
		}
	}
	return round3(sum)
}

func writeResult(dir string, r Result) error {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "result.json"), append(b, '\n'), 0o600); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "report.md"), []byte(markdown(r)), 0o600)
}

func markdown(r Result) string {
	var b bytes.Buffer
	p := r.Conditions.Run
	d := r.Drive
	verdict := "PASS"
	if !r.Pass {
		verdict = "FAIL"
	}
	fmt.Fprintf(&b, "# scrim load test: %s, %s\n\n", r.Profile, verdict)
	fmt.Fprintf(&b, "%s, commit %s, %s. Machine: %s (%s, kernel %s, podman %s).\n\n",
		r.Started.UTC().Format(time.RFC3339), r.Conditions.Commit, r.Conditions.GoVersion, r.Machine, r.Conditions.CPUModel, r.Conditions.Kernel, r.Conditions.Podman)
	fmt.Fprintf(&b, "%d replicas (each %s CPU, %s memory) on PostgreSQL with %s events; %d concurrent agent streams over %d sessions plus %d approval workers; "+
		"%s measured after %s warm-up. Requests of %d KB with %d of %d bulk secrets each (one also base64-encoded), one display value and one credential; replies streamed in %d-rune chunks every %s.\n\n",
		p.Replicas, p.ReplicaCPUs, p.ReplicaMemory, r.Conditions.Events, p.Streams, p.Sessions, p.ApprovalWorkers,
		p.Duration.D(), p.Warmup.D(), p.BodyKB, p.SecretsPerRequest, p.BulkSecrets, p.ChunkRunes, p.ChunkInterval.D())
	if r.Conditions.Sabotage != "" {
		fmt.Fprintf(&b, "**Sabotaged run (%s): the checks are expected to fail.**\n\n", r.Conditions.Sabotage)
	}
	b.WriteString("| Check | Measured | Limit | |\n| --- | --- | --- | --- |\n")
	for _, c := range r.Checks {
		mark := "pass"
		if !c.Pass {
			mark = "**FAIL**"
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", c.Name, c.Value, c.Limit, mark)
	}
	b.WriteString("\n## Throughput\n\n")
	fmt.Fprintf(&b, "%.1f provider requests/s (%.2f MB/s of request bodies redacted), %.1f tool requests/s, %.0f stream events/s; streams open: mean %.0f, max %.0f.\n\n",
		d.Throughput.LLMPerSecond, d.Throughput.RequestMBPerSecond, d.Throughput.ToolPerSecond, d.Throughput.ChunksPerSecond, d.Streams.Mean, d.Streams.Max)
	b.WriteString("## Latency (ms)\n\n| | count | p50 | p95 | p99 | max |\n| --- | --- | --- | --- | --- | --- |\n")
	row := func(name string, s Summary) {
		fmt.Fprintf(&b, "| %s | %d | %.2f | %.2f | %.2f | %.2f |\n", name, s.Count, s.P50, s.P95, s.P99, s.Max)
	}
	row("added before the provider sees the request", d.Latency.RequestAdded)
	row("added to the first streamed byte", d.Latency.FirstByte)
	row("added end to end (client time minus upstream time)", d.Latency.TotalAdded)
	row("provider request, client end to end", d.Latency.ClientTotal)
	row("tool request through the forward proxy", d.Latency.Tool)
	row("approval decided on one replica to release on another", d.Approvals.ReleaseLag)
	fmt.Fprintf(&b, "\nscrim's own histograms over the window, all replicas: request added p99 %.3f ms (%.2f%% within 5 ms), restore per chunk p99 %.1f µs (%.2f%% within 50 µs).\n",
		d.Scrim.RequestAddedP99Ms, d.Scrim.RequestWithin5ms*100, d.Scrim.RestoreChunkP99Us, d.Scrim.RestoreChunkWithin50u*100)
	b.WriteString("\n## Resources over the window\n\n| container | CPU mean | CPU max | memory max MiB | anon max MiB | anon idle MiB | peak MiB | limit |\n| --- | --- | --- | --- | --- | --- | --- | --- |\n")
	for _, rs := range r.Resources {
		fmt.Fprintf(&b, "| %s | %.2f | %.2f | %.0f | %.0f | %.0f | %.0f | %s CPU, %.0f MiB |\n", rs.Role, rs.CPUCoresMean, rs.CPUCoresMax, rs.MemMaxMiB, rs.AnonMaxMiB, rs.IdleAnonMiB, rs.PeakMiB, rs.CPULimit, rs.LimitMiB)
	}
	for _, rs := range r.Resources {
		if len(rs.CPUByProcess) > 1 && strings.HasPrefix(rs.Role, "r") {
			fmt.Fprintf(&b, "\n%s CPU by process: control plane (scrim) %.2f, data plane (scrim-dataplane) %.2f cores.", rs.Role, rs.CPUByProcess["scrim"], dataPlaneCPU(rs.CPUByProcess))
		}
	}
	b.WriteString("\n")
	fmt.Fprintf(&b, "\nReplica CPU per provider request (with its tool call and a share of the approvals): %.1f ms.\n", r.CPUMsPerRequest)
	fmt.Fprintf(&b, "\nMemory per stream: %.1f KiB (largest growth of one replica's anonymous memory over its idle value before the load, divided by its share of the streams; fixed costs such as connection pools are included, so small runs overstate it).\n", r.MemPerStreamKiB)
	a := d.Approvals
	fmt.Fprintf(&b, "\n## Correctness\n\n%d restore checks, %d injections, %d approvals held (%d approved, %d denied, %d grants revoked on a third replica), every replica's last event id %v.\n",
		d.Correctness.RestoreChecks, d.Correctness.Injections, a.Held, a.Approved, a.Denied, a.Revoked, d.Events.LastIDs)
	if len(d.Failures) > 0 {
		b.WriteString("\nFirst failures:\n\n")
		for k, v := range d.Failures {
			for _, s := range v {
				fmt.Fprintf(&b, "- %s: %s\n", k, s)
			}
		}
	}
	return b.String()
}
