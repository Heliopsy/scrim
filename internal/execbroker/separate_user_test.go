// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package execbroker

import (
	"context"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestSeparateUser runs the broker as root with exec.user set, the way a
// system service runs it, and checks the command runs as that user with the
// secret while a process of the calling agent's user cannot read the
// command's environment. It needs root, so it runs in a container
// (test/exec/separate-user.sh); elsewhere it is skipped.
func TestSeparateUser(t *testing.T) {
	execUID, agentUID := os.Getenv("SCRIM_TEST_EXEC_UID"), os.Getenv("SCRIM_TEST_AGENT_UID")
	if os.Geteuid() != 0 || execUID == "" || agentUID == "" {
		t.Skip("needs root and SCRIM_TEST_EXEC_UID, SCRIM_TEST_AGENT_UID; run test/exec/separate-user.sh")
	}
	euid, _ := strconv.Atoi(execUID)
	auid, _ := strconv.Atoi(agentUID)
	r := newRig(t, nil)
	r.cfg.User = execUID
	caller := agent()
	caller.Peer.UID = uint32(auid) //nolint:gosec // test

	// Running as root is refused outright.
	r.cfg.User = "0"
	if _, err := r.b.Run(context.Background(), caller, Request{Command: []string{"helper"}, Env: map[string]string{"TOKEN": formGH}}); err == nil ||
		!strings.Contains(err.Error(), "never run as root") {
		t.Fatalf("root: %v", err)
	}
	r.cfg.User = execUID

	res, err := r.b.Run(context.Background(), caller, Request{
		Command: []string{"helper", "uid", "hash=TOKEN:" + sum(r.val)}, Env: map[string]string{"TOKEN": formGH},
	})
	r.leakCheck(t, res, err)
	if err != nil {
		t.Fatal(err)
	}
	if res.Stdout != "uid "+execUID+"\nmatch TOKEN\n" {
		t.Fatalf("stdout = %q", res.Stdout)
	}

	// While a command runs, the agent's user cannot read its environment.
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = r.b.Run(context.Background(), caller, Request{
			Command: []string{"helper", "marker-" + strconv.Itoa(os.Getpid()), "sleep=5s"}, Env: map[string]string{"TOKEN": formGH},
		})
	}()
	pid := waitForProcess(t, "marker-"+strconv.Itoa(os.Getpid()))
	if st, err := os.Stat("/proc/" + strconv.Itoa(pid)); err != nil || st.Sys().(*syscall.Stat_t).Uid != uint32(euid) { //nolint:gosec // test
		t.Fatalf("command process %d is not owned by %d", pid, euid)
	}
	self, _ := os.Executable()
	reader := exec.Command(self, "readenv="+strconv.Itoa(pid)) // #nosec G204 -- the test binary
	reader.Env = []string{"SCRIM_EXEC_HELPER=1"}
	reader.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(auid), Gid: uint32(auid), Groups: []uint32{}}} //nolint:gosec // test
	out, _ := reader.CombinedOutput()
	if strings.TrimSpace(string(out)) != "denied" {
		t.Fatalf("the agent's user read the command's environment: %q", out)
	}
	<-done
}

func waitForProcess(t *testing.T, marker string) int {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		ents, _ := os.ReadDir("/proc")
		for _, e := range ents {
			pid, err := strconv.Atoi(e.Name())
			if err != nil {
				continue
			}
			cmd, _ := os.ReadFile("/proc/" + e.Name() + "/cmdline")
			if strings.Contains(string(cmd), marker) && pid != os.Getpid() {
				return pid
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("the command did not start")
	return 0
}
