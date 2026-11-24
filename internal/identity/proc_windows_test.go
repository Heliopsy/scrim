// SPDX-License-Identifier: AGPL-3.0-only

package identity

import (
	"os"
	"os/exec"
	"testing"
)

// The test process is its parent's descendant, and a child it starts is
// its own: the process-tree binding of session tokens works on Windows.
func TestWindowsProcessTree(t *testing.T) {
	self, err := lookupProc(int32(os.Getpid())) // #nosec G115 -- Windows PIDs fit in 32 bits
	if err != nil {
		t.Fatal(err)
	}
	if self.PPID != int32(os.Getppid()) || self.Start == 0 { // #nosec G115 -- as above
		t.Fatalf("lookupProc(self) = %+v, want parent %d and a start time", self, os.Getppid())
	}
	cmd := exec.Command("cmd.exe", "/c", "ping -n 5 127.0.0.1 >NUL")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	child := int32(cmd.Process.Pid) // #nosec G115 -- as above
	ok, err := descends(OSProcs{}, child, self)
	if err != nil || !ok {
		t.Fatalf("descends(child, self) = %v, %v; want true", ok, err)
	}
	// A root with the right PID but another start time is a reused PID.
	ok, err = descends(OSProcs{}, child, Proc{PID: self.PID, Start: self.Start + 1})
	if err != nil || ok {
		t.Fatalf("descends(child, reused self) = %v, %v; want false", ok, err)
	}
	if _, err := lookupProc(0); err == nil {
		t.Fatal("lookupProc(0) succeeded")
	}
}
