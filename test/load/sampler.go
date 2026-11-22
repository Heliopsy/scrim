// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// sample is one reading of a container's cgroup.
type sample struct {
	t       time.Time
	cpuUsec float64
	mem     float64            // memory.current, bytes
	anon    float64            // memory.stat anon, bytes
	procs   map[string]float64 // CPU seconds per process name (scrim, scrim-dataplane)
}

// sampler reads the cgroup of every container once a second.
type sampler struct {
	w     *world
	mu    sync.Mutex
	paths map[string]string // role -> cgroup directory
	data  map[string][]sample
}

func newSampler(w *world) *sampler {
	s := &sampler{w: w, paths: map[string]string{}, data: map[string][]sample{}}
	return s
}

func (s *sampler) path(ctx context.Context, role string) string {
	s.mu.Lock()
	p, ok := s.paths[role]
	s.mu.Unlock()
	if ok {
		return p
	}
	rel, err := podman(ctx, "inspect", "-f", "{{.State.CgroupPath}}", s.w.name(role))
	if err != nil || rel == "" {
		return ""
	}
	p = filepath.Join("/sys/fs/cgroup", rel)
	s.mu.Lock()
	s.paths[role] = p
	s.mu.Unlock()
	return p
}

func (s *sampler) roles() []string {
	var r []string
	for _, e := range s.w.plan.Replicas {
		r = append(r, e.Name)
	}
	return append(r, "driver", "postgres", s.w.o.events)
}

func readSample(dir string) (sample, bool) {
	smp := sample{t: time.Now()}
	if dir == "" {
		return smp, false
	}
	if v, ok := statField(filepath.Join(dir, "cpu.stat"), "usage_usec"); ok {
		smp.cpuUsec = v
	} else {
		return smp, false
	}
	if b, err := os.ReadFile(filepath.Join(dir, "memory.current")); err == nil { //nolint:gosec // cgroup file
		smp.mem, _ = strconv.ParseFloat(strings.TrimSpace(string(b)), 64)
	}
	smp.anon, _ = statField(filepath.Join(dir, "memory.stat"), "anon")
	smp.procs = procCPU(dir)
	return smp, true
}

// procCPU sums user and system time per process name over the processes
// of a cgroup, so a replica's CPU splits into control plane (scrim) and
// data plane (scrim-dataplane). The containers share the host's PID
// namespace, so the PIDs in cgroup.procs are the host's.
func procCPU(dir string) map[string]float64 {
	b, err := os.ReadFile(filepath.Join(dir, "cgroup.procs")) //nolint:gosec // cgroup file
	if err != nil {
		return nil
	}
	out := map[string]float64{}
	for _, pid := range strings.Fields(string(b)) {
		st, err := os.ReadFile(filepath.Join("/proc", pid, "stat")) //nolint:gosec // proc file
		if err != nil {
			continue
		}
		// pid (comm) state ppid ... utime is field 14, stime 15.
		open, end := strings.IndexByte(string(st), '('), strings.LastIndexByte(string(st), ')')
		if open < 0 || end < open {
			continue
		}
		comm := string(st[open+1 : end])
		f := strings.Fields(string(st[end+1:]))
		if len(f) < 13 {
			continue
		}
		u, _ := strconv.ParseFloat(f[11], 64)
		sy, _ := strconv.ParseFloat(f[12], 64)
		out[comm] += (u + sy) / clockTicks
	}
	return out
}

// clockTicks is USER_HZ, 100 on every Linux the test runs on.
const clockTicks = 100

func statField(file, key string) (float64, bool) {
	f, err := os.Open(file) //nolint:gosec // cgroup file
	if err != nil {
		return 0, false
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), " ")
		if ok && k == key {
			x, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
			return x, err == nil
		}
	}
	return 0, false
}

func (s *sampler) once(ctx context.Context) {
	for _, r := range s.roles() {
		if smp, ok := readSample(s.path(ctx, r)); ok {
			s.mu.Lock()
			s.data[r] = append(s.data[r], smp)
			s.mu.Unlock()
		}
	}
}

func (s *sampler) loop(ctx context.Context) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		s.once(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// snapshot is the anonymous memory of each replica before the load starts.
func (s *sampler) snapshot(ctx context.Context) map[string]float64 {
	out := map[string]float64{}
	for _, e := range s.w.plan.Replicas {
		if smp, ok := readSample(s.path(ctx, e.Name)); ok {
			out[e.Name] = smp.anon
		}
	}
	return out
}

// Resources of one container over the measured window.
type Resources struct {
	Role         string  `json:"role"`
	CPUCoresMean float64 `json:"cpu_cores_mean"`
	CPUCoresMax  float64 `json:"cpu_cores_max"`
	MemMaxMiB    float64 `json:"memory_max_mib"`
	AnonMaxMiB   float64 `json:"anon_max_mib"`
	IdleAnonMiB  float64 `json:"anon_idle_mib,omitempty"`
	PeakMiB      float64 `json:"memory_peak_mib"`
	LimitMiB     float64 `json:"memory_limit_mib"`
	CPULimit     string  `json:"cpu_limit"`
	// CPUByProcess is the mean CPU of each process name over the window.
	CPUByProcess map[string]float64 `json:"cpu_cores_by_process,omitempty"`
	OOMKills     float64            `json:"oom_kills"`
}

func (s *sampler) resources(role string, from, to time.Time, idle float64, limit int64, cpus string) Resources {
	s.mu.Lock()
	data := s.data[role]
	dir := s.paths[role]
	s.mu.Unlock()
	r := Resources{Role: role, LimitMiB: round3(float64(limit) / (1 << 20)), CPULimit: cpus, IdleAnonMiB: round3(idle / (1 << 20))}
	var prev *sample
	sum, n := 0.0, 0
	for i := range data {
		d := data[i]
		if d.t.Before(from) || d.t.After(to.Add(time.Second)) {
			prev = &data[i]
			continue
		}
		r.MemMaxMiB = max(r.MemMaxMiB, round3(d.mem/(1<<20)))
		r.AnonMaxMiB = max(r.AnonMaxMiB, round3(d.anon/(1<<20)))
		if prev != nil {
			if dt := d.t.Sub(prev.t).Seconds(); dt > 0 {
				c := (d.cpuUsec - prev.cpuUsec) / 1e6 / dt
				sum += c
				n++
				r.CPUCoresMax = max(r.CPUCoresMax, round3(c))
			}
		}
		prev = &data[i]
	}
	if n > 0 {
		r.CPUCoresMean = round3(sum / float64(n))
	}
	var first, last *sample
	for i := range data {
		if data[i].t.Before(from) || data[i].t.After(to.Add(time.Second)) {
			continue
		}
		if first == nil {
			first = &data[i]
		}
		last = &data[i]
	}
	if first != nil && last != first {
		dt := last.t.Sub(first.t).Seconds()
		r.CPUByProcess = map[string]float64{}
		for k, v := range last.procs {
			r.CPUByProcess[k] = round3((v - first.procs[k]) / dt)
		}
	}
	if b, err := os.ReadFile(filepath.Join(dir, "memory.peak")); err == nil && dir != "" { //nolint:gosec // cgroup file
		v, _ := strconv.ParseFloat(strings.TrimSpace(string(b)), 64)
		r.PeakMiB = round3(v / (1 << 20))
	}
	if dir != "" {
		r.OOMKills, _ = statField(filepath.Join(dir, "memory.events"), "oom_kill")
	}
	return r
}
