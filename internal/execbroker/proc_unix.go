// SPDX-License-Identifier: AGPL-3.0-only

//go:build unix

package execbroker

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"syscall"
	"time"
	"unsafe"
)

// start runs a process to completion in its own process group, as who,
// with nothing inherited, and collects its output.
func start(ctx context.Context, s spec) (outcome, error) {
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, s.path)
	cmd.Args = strs(s.argv)
	cmd.Env = strs(s.env)
	cmd.Dir = s.dir
	cmd.Stdin = bytes.NewReader(s.stdin)
	stdout, stderr := &capped{limit: s.maxOutput}, &capped{limit: s.maxOutput}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	cmd.SysProcAttr = sysProcAttr(s.who)
	cmd.Cancel = func() error {
		// The whole group, so a child the command started dies with it.
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	cmd.WaitDelay = 2 * time.Second
	err := cmd.Run()
	out := outcome{exitCode: -1, bufs: []*capped{stdout, stderr}}
	if cmd.ProcessState == nil {
		out.wipe()
		return outcome{}, err
	}
	var exitErr *exec.ExitError
	if err != nil && !errors.As(err, &exitErr) && !errors.Is(err, exec.ErrWaitDelay) && ctx.Err() == nil {
		out.wipe()
		return outcome{}, err
	}
	out.exitCode = cmd.ProcessState.ExitCode()
	out.timedOut = ctx.Err() != nil
	out.stdoutOver, out.stderrOver = stdout.over, stderr.over
	if !stdout.over {
		out.stdout = stdout.b
	}
	if !stderr.over {
		out.stderr = stderr.b
	}
	return out, nil
}

// sysProcAttr starts the process in a new process group, as who when that
// is another identity than scrim's, with no supplementary groups.
func sysProcAttr(who account) *syscall.SysProcAttr {
	a := &syscall.SysProcAttr{Setpgid: true}
	if who.UID != uint32(os.Geteuid()) || who.GID != uint32(os.Getegid()) { //nolint:gosec // IDs are non-negative
		a.Credential = &syscall.Credential{Uid: who.UID, Gid: who.GID, Groups: []uint32{}}
	}
	platformAttr(a)
	return a
}

// strs views buffers as strings without copying them, so the only copies a
// value has in this process are buffers the broker wipes (and the ones the
// runtime makes while forking, which are garbage once the child runs). The
// strings must not be used after the buffers are wiped: exec.Cmd reads
// Args and Env only in Start.
func strs(bufs [][]byte) []string {
	out := make([]string, len(bufs))
	for i, b := range bufs {
		if len(b) > 0 {
			out[i] = unsafe.String(&b[0], len(b)) //nolint:gosec // see the comment above: views of buffers wiped after Start
		}
	}
	return out
}
