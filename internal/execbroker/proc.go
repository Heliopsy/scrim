// SPDX-License-Identifier: AGPL-3.0-only

package execbroker

import (
	"bytes"
	"context"
	"errors"
	"math"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"syscall"
	"time"
	"unsafe"

	"github.com/heliopsy/scrim/internal/secret"
)

// account is the operating-system identity a command runs as.
type account struct {
	UID, GID uint32
	Name     string
	Home     string
}

// runAs resolves exec.user; empty is scrim's own user.
func runAs(spec string) (account, error) {
	if spec == "" {
		a := account{UID: uint32(os.Geteuid()), GID: uint32(os.Getegid()), Home: "/"} //nolint:gosec // IDs are non-negative
		if u, err := user.LookupId(strconv.Itoa(os.Geteuid())); err == nil {
			a.Name, a.Home = u.Username, u.HomeDir
		}
		return a, nil
	}
	u, err := user.Lookup(spec)
	if err != nil {
		u, err = user.LookupId(spec)
	}
	if err != nil {
		// A numeric ID without a passwd entry (a container's nobody).
		id, perr := strconv.ParseUint(spec, 10, 32)
		if perr != nil {
			return account{}, err
		}
		return account{UID: uint32(id), GID: uint32(id), Home: "/"}, nil
	}
	uid, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return account{}, err
	}
	gid, err := strconv.ParseUint(u.Gid, 10, 32)
	if err != nil {
		return account{}, err
	}
	return account{UID: uint32(uid), GID: uint32(gid), Name: u.Username, Home: u.HomeDir}, nil
}

// baseEnv is every command's environment before its own: nothing of
// scrim's or the agent's environment is inherited.
func baseEnv(cfg Config, who account) [][]byte {
	home := who.Home
	if home == "" {
		home = "/"
	}
	env := [][]byte{[]byte("PATH=" + cfg.Path), []byte("HOME=" + home), []byte("LANG=C.UTF-8"), []byte("TERM=dumb")}
	if who.Name != "" {
		env = append(env, []byte("USER="+who.Name), []byte("LOGNAME="+who.Name))
	}
	return env
}

// scratchDir is a fresh, empty working directory owned by who.
func scratchDir(who account) (string, error) {
	dir, err := os.MkdirTemp("", "scrim-exec-")
	if err != nil {
		return "", err
	}
	if who.UID != uint32(os.Geteuid()) { //nolint:gosec // IDs are non-negative
		if who.UID > math.MaxInt32 || who.GID > math.MaxInt32 {
			_ = os.RemoveAll(dir)
			return "", errors.New("exec.user has an out-of-range user or group ID")
		}
		if err := os.Chown(dir, int(who.UID), int(who.GID)); err != nil {
			_ = os.RemoveAll(dir)
			return "", err
		}
	}
	return dir, nil
}

// spec is one process to start. argv, env and stdin may hold values; the
// broker wipes them after start returns.
type spec struct {
	path      string
	argv      [][]byte
	env       [][]byte
	stdin     []byte
	dir       string
	who       account
	timeout   time.Duration
	maxOutput int
}

// outcome is what a process left. A stream larger than the limit is
// marked over and left empty.
type outcome struct {
	exitCode   int
	timedOut   bool
	stdout     []byte
	stderr     []byte
	stdoutOver bool
	stderrOver bool
	bufs       []*capped
}

func (o outcome) wipe() {
	for _, b := range o.bufs {
		b.wipe()
	}
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

// capped collects up to limit bytes and drops the rest. When it grows, it
// wipes the buffer it leaves behind.
type capped struct {
	b     []byte
	limit int
	over  bool
}

func (c *capped) Write(p []byte) (int, error) {
	n := len(p)
	if room := c.limit - len(c.b); len(p) > room {
		c.over = true
		p = p[:max(room, 0)]
	}
	if len(c.b)+len(p) > cap(c.b) {
		// Never beyond the limit: len(c.b)+len(p) is at most limit here, and
		// the buffer only doubles while it is below half the limit.
		size := c.limit
		if cap(c.b) < c.limit/2 {
			size = min(max(2*cap(c.b), len(c.b)+len(p), 4096), c.limit)
		}
		grown := make([]byte, len(c.b), size)
		copy(grown, c.b)
		secret.WipeBytes(c.b[:cap(c.b)])
		c.b = grown
	}
	c.b = append(c.b, p...)
	return n, nil
}

func (c *capped) wipe() { secret.WipeBytes(c.b[:cap(c.b)]) }
