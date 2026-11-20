// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package cli

import (
	"bytes"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/heliopsy/scrim/internal/agenttools/agenttoolstest"
)

// openPTY returns the controller and terminal ends of a new pseudo-terminal.
func openPTY(t *testing.T) (*os.File, *os.File) {
	t.Helper()
	// Non-blocking, so the runtime poller handles it and read deadlines work.
	fd, err := unix.Open("/dev/ptmx", unix.O_RDWR|unix.O_NOCTTY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Skip("no pseudo-terminals:", err)
	}
	ptmx := os.NewFile(uintptr(fd), "/dev/ptmx")
	if err := unix.IoctlSetPointerInt(int(ptmx.Fd()), unix.TIOCSPTLCK, 0); err != nil {
		t.Skip("unlockpt:", err)
	}
	n, err := unix.IoctlGetUint32(int(ptmx.Fd()), unix.TIOCGPTN)
	if err != nil {
		t.Skip("ptsname:", err)
	}
	tty, err := os.OpenFile("/dev/pts/"+strconv.FormatUint(uint64(n), 10), os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Skip("open pts:", err)
	}
	t.Cleanup(func() { _ = tty.Close(); _ = ptmx.Close() })
	return ptmx, tty
}

// TestPutOnATerminalTurnsEchoOff types a value into a real pseudo-terminal
// and checks the terminal never echoed it: whatever the terminal displayed
// is read back from the controller side.
func TestPutOnATerminalTurnsEchoOff(t *testing.T) {
	ts := cliServer(t)
	ptmx, tty := openPTY(t)

	done := make(chan result, 1)
	go func() { done <- runCLI(ts, tty, "secret", "put", "bao://kv/agents/typed", "--stdin") }()

	// Type only once the command has switched echo off, as a person would
	// after the prompt appears.
	deadline := time.Now().Add(5 * time.Second)
	for {
		tio, err := unix.IoctlGetTermios(int(tty.Fd()), unix.TCGETS)
		if err != nil {
			t.Fatal(err)
		}
		if tio.Lflag&unix.ECHO == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("echo was never turned off")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if _, err := ptmx.Write(append(append([]byte(nil), cliPiped...), '\r')); err != nil {
		t.Fatal(err)
	}
	var res result
	select {
	case res = <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("put did not finish")
	}
	if res.code != 0 {
		t.Fatalf("exit %d: %s", res.code, res.stderr)
	}
	if !strings.Contains(res.stderr, "input is hidden") {
		t.Fatalf("no prompt: %q", res.stderr)
	}
	if v, _ := ts.Store.Value("bao://kv/agents/typed"); !bytes.Equal(v, cliPiped) {
		t.Fatal("typed value not stored")
	}

	// Everything the terminal displayed.
	_ = ptmx.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	shown := make([]byte, 4096)
	n, err := ptmx.Read(shown)
	if err != nil && !os.IsTimeout(err) {
		t.Fatal(err)
	}
	agenttoolstest.AssertNoValues(t, "terminal display", shown[:n], cliPiped)
	agenttoolstest.AssertNoValues(t, "command output", []byte(res.stdout+res.stderr), cliPiped)
	tio, _ := unix.IoctlGetTermios(int(tty.Fd()), unix.TCGETS)
	if tio.Lflag&unix.ECHO == 0 {
		t.Error("echo was not restored")
	}
}
