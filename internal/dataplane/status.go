// SPDX-License-Identifier: AGPL-3.0-only

package dataplane

import (
	"context"
	"fmt"
	"strings"
	"time"

	pb "github.com/heliopsy/scrim/internal/dataplane/dataplanev1"
	"github.com/heliopsy/scrim/internal/status"
)

// DataPlaneStatus implements status.DataPlaneSource for the supervised
// data plane of this process.
func (s *Supervisor) DataPlaneStatus(ctx context.Context) status.DataPlane {
	s.mu.Lock()
	p, hello, since, lastErr := s.cur, s.hello, s.since, s.lastErr
	s.mu.Unlock()
	if p == nil {
		detail := "data plane is not running"
		if lastErr != nil {
			detail += ": " + lastErr.Error()
		}
		if n := s.Restarts(); n > 0 {
			detail += fmt.Sprintf(" (%d restarts)", n)
		}
		return status.DataPlane{Detail: detail}
	}
	dp := status.DataPlane{Running: true, PID: p.Pid(), Version: hello.GetDataPlaneVersion(), Uptime: time.Since(since)}
	cctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	st, err := p.Client.Status(cctx, &pb.StatusRequest{Protocol: Protocol})
	if err != nil {
		dp.Detail = "status call failed: " + err.Error()
		return dp
	}
	dp.Healthy = st.GetReady() && s.Ready()
	dp.Detail = describe(st, p.How)
	return dp
}

// describe summarises a data plane status in one line.
func describe(st *pb.StatusResponse, how string) string {
	parts := []string{
		fmt.Sprintf("run from %s", how),
		fmt.Sprintf("snapshot %d with %d values", st.GetAppliedSnapshotVersion(), st.GetValueCount()),
	}
	if !st.GetMemoryLocked() {
		parts = append(parts, "memory not locked")
	}
	if st.GetDumpable() {
		parts = append(parts, "core dumps possible")
	}
	for _, l := range st.GetListeners() {
		if l.GetBound() {
			parts = append(parts, fmt.Sprintf("%s on %s", l.GetName(), l.GetAddress()))
		} else {
			parts = append(parts, fmt.Sprintf("%s not bound: %s", l.GetName(), l.GetError()))
		}
	}
	if tp := st.GetToolProxy(); tp != nil {
		for dest, why := range tp.GetUnsupportedDestinations() {
			parts = append(parts, fmt.Sprintf("client refused interception for %s: %s", dest, why))
		}
	}
	return strings.Join(parts, "; ")
}

// Probe is a status.DataPlaneSource for a command that runs no data plane
// of its own (`scrim status`, `scrim doctor`): it launches the configured
// binary once, handshakes, reads its status and stops it. It proves the data
// plane can start here; it says nothing about a long-running scrim.
type Probe struct {
	// Path is dataplane.path; empty uses the embedded binary.
	Path    string
	Options StartOptions
	Timeout time.Duration
}

// DataPlaneStatus implements status.DataPlaneSource.
func (pr Probe) DataPlaneStatus(ctx context.Context) status.DataPlane {
	b, err := Resolve(pr.Path)
	if err != nil {
		return status.DataPlane{Detail: err.Error()}
	}
	timeout := pr.Timeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	p, err := Start(b, pr.Options)
	if err != nil {
		return status.DataPlane{Detail: "data plane does not start: " + err.Error()}
	}
	defer p.Stop(2 * time.Second)
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	hello, err := p.Client.Hello(cctx, &pb.HelloRequest{Protocol: Protocol})
	if err != nil {
		return status.DataPlane{Detail: "data plane started but the handshake failed: " + err.Error()}
	}
	if hello.GetProtocol() != Protocol {
		return status.DataPlane{Detail: fmt.Sprintf("data plane speaks protocol %d, this scrim %d", hello.GetProtocol(), Protocol)}
	}
	st, err := p.Client.Status(cctx, &pb.StatusRequest{Protocol: Protocol})
	if err != nil {
		return status.DataPlane{Detail: "data plane status failed: " + err.Error()}
	}
	return status.DataPlane{
		Running: true,
		PID:     p.Pid(),
		Version: hello.GetDataPlaneVersion(),
		Healthy: true,
		Detail:  "checked by starting it from this command (" + describe(st, p.How) + "); a running scrim reports its own through the admin API",
	}
}
