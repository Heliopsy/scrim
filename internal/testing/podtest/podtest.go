// SPDX-License-Identifier: AGPL-3.0-only

// Package podtest gives integration tests a throwaway service container
// (Valkey, NATS, Loki, an OpenTelemetry collector, Redpanda) through rootless
// podman. A [Service] names an environment variable that points tests at an
// existing server instead (CI service containers); otherwise the first
// [Service.Addr] starts the container, memory-limited, and [Service.Stop]
// removes it with its anonymous volumes. When neither is possible every
// caller skips with the recorded reason; SCRIM_TEST_PODMAN=0 skips without
// trying and SCRIM_TEST_PODMAN=1 turns the skip into a failure (CI). A package using it calls Stop from
// TestMain after m.Run.
//
// Containers are named "<prefix>-<name>-<random>", where the prefix is
// SCRIM_TEST_CONTAINER_PREFIX or "scrim-test", so a developer can find and
// remove what a run left behind.
package podtest

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/heliopsy/scrim/internal/testing/testpodman"
)

// Service describes one container.
type Service struct {
	// Name is a short name: "valkey", "nats", "loki".
	Name string
	// Env is the variable that holds the address of an existing server;
	// when set, no container is started.
	Env string
	// Image is the default image; ImageEnv, when set in the environment,
	// overrides it.
	Image    string
	ImageEnv string
	// Port is the container port Addr reports, as "6379/tcp". Extra are
	// further container ports to publish, reported by [Service.Port].
	Port  string
	Extra []string
	// Memory is the container's memory limit, as podman takes it ("256m").
	Memory string
	// Args go after the image; RunArgs before it (environment, mounts).
	Args    []string
	RunArgs []string
	// HostPorts, when set, publishes Port on this fixed host port, for
	// services that advertise their own address (Kafka); it gets "{port}"
	// substituted in Args.
	HostPorts bool
	// Ready reports whether the service answers at addr.
	Ready func(ctx context.Context, addr string) error
	// ReadyTimeout bounds the wait; default 90s.
	ReadyTimeout time.Duration

	once   sync.Once
	addr   string
	ports  map[string]string
	skip   string
	name   string
	stopMu sync.Mutex
}

// Prefix is the container name prefix.
func Prefix() string {
	if p := os.Getenv("SCRIM_TEST_CONTAINER_PREFIX"); p != "" {
		return p
	}
	return "scrim-test"
}

func (s *Service) setup() {
	if v := os.Getenv(s.Env); v != "" {
		s.addr = v
		return
	}
	if os.Getenv("SCRIM_TEST_PODMAN") == "0" {
		s.skip = "SCRIM_TEST_PODMAN=0 and " + s.Env + " not set"
		return
	}
	if _, err := exec.LookPath("podman"); err != nil {
		s.skip = "podman not found and " + s.Env + " not set"
		return
	}
	image := s.Image
	if s.ImageEnv != "" {
		if v := os.Getenv(s.ImageEnv); v != "" {
			image = v
		}
	}
	s.name = Prefix() + "-" + s.Name + "-" + RandHex(4)
	args := []string{"run", "-d", "--rm", "--name", s.name}
	if s.Memory != "" {
		args = append(args, "--memory", s.Memory, "--memory-swap", s.Memory)
	}
	extra := s.Args
	if s.HostPorts {
		port, err := freePort()
		if err != nil {
			s.skip = "no free port: " + err.Error()
			return
		}
		args = append(args, "-p", "127.0.0.1:"+port+":"+strings.TrimSuffix(s.Port, "/tcp"))
		extra = make([]string, len(s.Args))
		for i, a := range s.Args {
			extra[i] = strings.ReplaceAll(a, "{port}", port)
		}
	} else {
		args = append(args, "-p", "127.0.0.1::"+strings.TrimSuffix(s.Port, "/tcp"))
	}
	for _, p := range s.Extra {
		args = append(args, "-p", "127.0.0.1::"+strings.TrimSuffix(p, "/tcp"))
	}
	args = append(args, s.RunArgs...)
	args = append(args, image)
	args = append(args, extra...)
	out, err := testpodman.Command(args...).CombinedOutput()
	if err != nil {
		s.skip = fmt.Sprintf("podman run %s failed: %v: %s", image, err, strings.TrimSpace(string(out)))
		return
	}
	s.ports = map[string]string{}
	for _, p := range append([]string{s.Port}, s.Extra...) {
		hp, err := testpodman.Command("port", s.name, p).Output()
		if err != nil {
			s.Stop()
			s.skip = fmt.Sprintf("podman port %s %s: %v", s.name, p, err)
			return
		}
		s.ports[p] = strings.TrimSpace(strings.Split(string(hp), "\n")[0])
	}
	s.addr = s.ports[s.Port]
	if s.Ready != nil {
		d := s.ReadyTimeout
		if d == 0 {
			d = 90 * time.Second
		}
		if err := waitReady(s.Ready, s.addr, d); err != nil {
			logs, _ := testpodman.Command("logs", "--tail", "20", s.name).CombinedOutput()
			s.Stop()
			s.addr = ""
			s.skip = fmt.Sprintf("%s in %s never became ready: %v\n%s", s.Name, s.name, err, bytes.TrimSpace(logs))
			return
		}
	}
}

func waitReady(ready func(context.Context, string) error, addr string, d time.Duration) error {
	deadline := time.Now().Add(d)
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		err := ready(ctx, addr)
		cancel()
		if err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return err
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// Addr returns host:port of the service, starting it on first use, and
// skips t when no server is available.
func (s *Service) Addr(t testing.TB) string {
	t.Helper()
	s.once.Do(s.setup)
	if s.addr == "" {
		if os.Getenv("SCRIM_TEST_PODMAN") == "1" {
			t.Fatal(s.Name + " unavailable but SCRIM_TEST_PODMAN=1 requires it: " + s.skip)
		}
		t.Skip(s.Name + " unavailable: " + s.skip)
	}
	return s.addr
}

// HostPort returns the host address of another published container port; it
// is empty for a server given through Env.
func (s *Service) HostPort(t testing.TB, port string) string {
	t.Helper()
	s.Addr(t)
	return s.ports[port]
}

// Container is the started container's name, empty for a server given
// through Env.
func (s *Service) Container() string { return s.name }

// Pause freezes the container (podman pause) until the returned function
// runs, to make a service slow without closing its connections. It skips t
// for a server given through Env.
func (s *Service) Pause(t testing.TB) (resume func()) {
	t.Helper()
	s.Addr(t)
	if s.name == "" {
		t.Skip("pausing needs a container this test started; " + s.Env + " points at an external server")
	}
	if out, err := testpodman.Command("pause", s.name).CombinedOutput(); err != nil {
		t.Skipf("podman pause %s: %v: %s (rootless pause needs cgroup v2 with the freezer)", s.name, err, out)
	}
	var once sync.Once
	resume = func() {
		once.Do(func() { _ = testpodman.Command("unpause", s.name).Run() })
	}
	t.Cleanup(resume)
	return resume
}

// Stop removes the container the package started, if any.
func (s *Service) Stop() {
	s.stopMu.Lock()
	defer s.stopMu.Unlock()
	if s.name != "" {
		_ = testpodman.Command("rm", "-f", "-v", s.name).Run()
	}
}

// RandHex returns 2n random hex characters.
func RandHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
