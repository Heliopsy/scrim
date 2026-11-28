// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package fsview

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// envNetChild makes the test binary the agent of TestNetworkNamespace: it
// dials each address in the variable's value and prints what came back.
const envNetChild = "SCRIM_FSVIEW_TEST_NET"

// netChild dials "tcp:<addr>" and "unix:<path>" targets, one result line
// each: "ok <greeting>" or "fail <error>".
func netChild() int {
	for _, target := range strings.Split(os.Getenv(envNetChild), ",") {
		network, addr, _ := strings.Cut(target, ":")
		c, err := net.DialTimeout(network, addr, 3*time.Second)
		if err != nil {
			fmt.Printf("%s fail %v\n", target, err)
			continue
		}
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))
		line, err := bufio.NewReader(c).ReadString('\n')
		_ = c.Close()
		if err != nil {
			fmt.Printf("%s fail %v\n", target, err)
			continue
		}
		fmt.Printf("%s ok %s", target, line)
	}
	return 0
}

func requireNetns(t *testing.T) {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if a := ProbeNetwork(context.Background(), exe); !a.Namespace {
		if os.Getenv("SCRIM_TEST_REQUIRE_USERNS") == "1" {
			t.Fatalf("network namespaces required: %s", a.Reason)
		}
		t.Skipf("no unprivileged network namespace here: %s", a.Reason)
	}
}

// greet serves one line on every connection to ln.
func greet(t *testing.T, ln net.Listener, line string) {
	t.Helper()
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = c.Write([]byte(line + "\n"))
			_ = c.Close()
		}
	}()
}

// TestNetworkNamespace: an agent in the network namespace reaches the
// address scrim run serves (through the handed-over listener), not another
// loopback listener of the host, and not a masked Unix socket, whether the
// socket itself or its directory is masked.
func TestNetworkNamespace(t *testing.T) {
	requireNetns(t)
	served, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	greet(t, served, "host-side")
	other, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	greet(t, other, "other")
	dir, err := os.MkdirTemp("", "scrim-netns-") // short: Unix socket paths
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	bus := filepath.Join(dir, "bus")
	if err := os.Mkdir(filepath.Join(dir, "podman"), 0o700); err != nil {
		t.Fatal(err)
	}
	podman := filepath.Join(dir, "podman", "podman.sock")
	visible := filepath.Join(dir, "visible")
	for _, p := range []string{bus, podman, visible} {
		ln, err := net.Listen("unix", p)
		if err != nil {
			t.Fatal(err)
		}
		greet(t, ln, "unix")
	}

	exe, _ := os.Executable()
	targets := []string{"tcp:" + served.Addr().String(), "tcp:" + other.Addr().String(), "unix:" + bus, "unix:" + podman, "unix:" + visible}
	cmd := exec.Command(exe)
	cmd.Env = []string{envNetChild + "=" + strings.Join(targets, ",")}
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	l, err := Wrap(cmd, exe, nil, &Network{
		Listen: []Listen{{Addr: served.Addr().String()}, {Addr: "[::1]:1", Optional: true}},
		Mask:   []string{bus, filepath.Join(dir, "podman"), filepath.Join(dir, "absent")},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	if err := l.Started(); err != nil {
		_ = cmd.Wait()
		t.Fatalf("started: %v\n%s", err, errb.String())
	}
	lns := l.Listeners()
	if len(lns) == 0 || lns[0].Addr != served.Addr().String() {
		t.Fatalf("listeners = %+v", lns)
	}
	for _, ln := range lns {
		greet(t, ln.Listener, "bridged")
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("agent: %v\n%s", err, errb.String())
	}
	got := out.String()
	t.Logf("agent saw:\n%s", got)
	want := map[string]string{
		targets[0]: "ok bridged", // the namespace's own listener, not the host's
		targets[1]: "fail",
		targets[2]: "fail",
		targets[3]: "fail",
		targets[4]: "ok unix",
	}
	for target, prefix := range want {
		if !strings.Contains(got, target+" "+prefix) {
			t.Errorf("%s: want %q", target, prefix)
		}
	}
}

// TestNetworkListenFailsClosed: a listener that cannot be bound inside the
// namespace refuses the start, and the agent never runs.
func TestNetworkListenFailsClosed(t *testing.T) {
	requireNetns(t)
	exe, _ := os.Executable()
	cmd := exec.Command(exe)
	cmd.Env = []string{envNetChild + "=tcp:127.0.0.1:1"}
	var out bytes.Buffer
	cmd.Stdout = &out
	l, err := Wrap(cmd, exe, nil, &Network{Listen: []Listen{{Addr: "192.0.2.1:80"}}})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	err = l.Started()
	_ = cmd.Wait()
	if err == nil || !strings.Contains(err.Error(), "192.0.2.1:80") {
		t.Fatalf("want a refusal naming the address, got %v", err)
	}
	if out.Len() != 0 {
		t.Errorf("the agent ran: %q", out.String())
	}
}
