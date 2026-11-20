// SPDX-License-Identifier: AGPL-3.0-only

// Package podmantest runs throwaway store containers for integration tests
// with rootless podman. Docker is deliberately not supported.
//
// Tests that need a container call [Require], which skips the test with a
// clear reason when podman is missing or SCRIM_TEST_PODMAN=0, and fails it
// when SCRIM_TEST_PODMAN=1 demands the integration run (as CI does). Every
// container and pod is named with the scrim-stores- prefix and removed,
// with its anonymous volumes, in t.Cleanup.
package podmantest

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// NamePrefix starts the name of every container and pod this package makes.
const NamePrefix = "scrim-stores-"

// Require skips t unless podman can run containers. With SCRIM_TEST_PODMAN=1
// a missing podman fails the test instead, so CI cannot silently skip the
// integration suite.
func Require(t testing.TB) {
	t.Helper()
	if testing.Short() {
		t.Skip("integration test skipped in -short mode")
	}
	mode := os.Getenv("SCRIM_TEST_PODMAN")
	if mode == "0" {
		t.Skip("integration test skipped: SCRIM_TEST_PODMAN=0")
	}
	if _, err := exec.LookPath("podman"); err != nil {
		if mode == "1" {
			t.Fatalf("SCRIM_TEST_PODMAN=1 but podman is not installed")
		}
		t.Skip("integration test skipped: podman is not installed (set SCRIM_TEST_PODMAN=1 to require it)")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if out, err := exec.CommandContext(ctx, "podman", "info", "--format", "{{.Host.Security.Rootless}}").CombinedOutput(); err != nil {
		if mode == "1" {
			t.Fatalf("SCRIM_TEST_PODMAN=1 but podman does not work: %v: %s", err, bytes.TrimSpace(out))
		}
		t.Skipf("integration test skipped: podman does not work: %v", err)
	}
}

// Podman runs podman with args and returns its trimmed stdout. Stderr is
// included in the error. Arguments must not contain secret values: they show
// up in the process list.
func Podman(ctx context.Context, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "podman", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("podman %s: %w: %s", args[0], err, strings.TrimSpace(stderr.String()))
	}
	return strings.TrimSpace(stdout.String()), nil
}

// MustPodman is [Podman] that fails t.
func MustPodman(t testing.TB, args ...string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	out, err := Podman(ctx, args...)
	if err != nil {
		t.Fatalf("%v", err)
	}
	return out
}

// FreePort returns a TCP port on 127.0.0.1 that was free a moment ago.
func FreePort(t testing.TB) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("free port: %v", err)
	}
	defer func() { _ = l.Close() }()
	return l.Addr().(*net.TCPAddr).Port
}

// Name returns a unique container or pod name for what.
func Name(t testing.TB, what string) string {
	t.Helper()
	return fmt.Sprintf("%s%s-%d-%d", NamePrefix, what, os.Getpid(), time.Now().UnixNano()%1_000_000)
}

// Container is a running container.
type Container struct {
	Name string
	// Port is the host port mapped to the container port.
	Port int
}

// Run starts image detached as a container published on 127.0.0.1, with env
// passed through the environment of the podman process rather than its
// arguments, and registers removal in t.Cleanup. containerPort is the port
// inside the container.
func Run(t testing.TB, what, image string, containerPort int, env map[string]string, args ...string) *Container {
	t.Helper()
	c := &Container{Name: Name(t, what), Port: FreePort(t)}
	cmdArgs := []string{"run", "-d", "--rm=false", "--name", c.Name,
		"--label", "app.kubernetes.io/part-of=scrim-stores-test",
		"-p", fmt.Sprintf("127.0.0.1:%d:%d", c.Port, containerPort)}
	// `-e NAME` without a value makes podman copy NAME from its own
	// environment, so values never appear on a command line.
	procEnv := os.Environ()
	for k, v := range env {
		cmdArgs = append(cmdArgs, "-e", k)
		procEnv = append(procEnv, k+"="+v)
	}
	cmdArgs = append(cmdArgs, image)
	cmdArgs = append(cmdArgs, args...)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "podman", cmdArgs...)
	cmd.Env = procEnv
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("podman run %s: %v: %s", image, err, strings.TrimSpace(stderr.String()))
	}
	t.Cleanup(func() { Remove(t, c.Name) })
	return c
}

// Remove force-removes a container and its anonymous volumes.
func Remove(t testing.TB, name string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if _, err := Podman(ctx, "rm", "-f", "-v", "-t", "2", name); err != nil {
		t.Logf("cleanup: %v", err)
	}
}

// Stop pauses the store by stopping its container; Start brings it back.
// Used by outage tests.
func (c *Container) Stop(t testing.TB) {
	t.Helper()
	MustPodman(t, "stop", "-t", "2", c.Name)
}

// Start restarts a stopped container.
func (c *Container) Start(t testing.TB) {
	t.Helper()
	MustPodman(t, "start", c.Name)
}

// Pause freezes the container's processes: connections hang or are
// refused, depending on timing, which is how a store outage usually looks.
func (c *Container) Pause(t testing.TB) {
	t.Helper()
	MustPodman(t, "pause", c.Name)
}

// Unpause resumes a paused container.
func (c *Container) Unpause(t testing.TB) {
	t.Helper()
	MustPodman(t, "unpause", c.Name)
}

// WaitHTTP polls url until it answers with a status accepted by ok, or
// fails t after timeout.
func WaitHTTP(t testing.TB, url string, timeout time.Duration, ok func(status int) bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	client := &http.Client{Timeout: 2 * time.Second}
	var last string
	for time.Now().Before(deadline) {
		resp, err := client.Get(url)
		if err == nil {
			_ = resp.Body.Close()
			if ok(resp.StatusCode) {
				return
			}
			last = resp.Status
		} else {
			last = err.Error()
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("%s not ready after %s: %s", url, timeout, last)
}

// KubePlay plays a kube YAML (a pod with its containers) with
// `podman kube play`, publishing publish ("127.0.0.1:<host>:<container>"),
// and registers `podman kube down` in t.Cleanup. The YAML is written to a
// private temporary file because it may hold generated test credentials.
func KubePlay(t testing.TB, yaml []byte, publish ...string) {
	t.Helper()
	path := t.TempDir() + "/pod.yaml"
	if err := os.WriteFile(path, yaml, 0o600); err != nil {
		t.Fatalf("write pod yaml: %v", err)
	}
	args := []string{"kube", "play", "--replace"}
	for _, p := range publish {
		args = append(args, "--publish", p)
	}
	args = append(args, path)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		if _, err := Podman(ctx, "kube", "down", path); err != nil {
			t.Logf("cleanup: %v", err)
		}
	})
	MustPodman(t, args...)
}
