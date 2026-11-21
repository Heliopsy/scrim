// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package fsview

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// HelperName is argv[0] of the scrim executable started to set up the
// namespace view; ProbeName of the one that only checks it can.
const (
	HelperName = "scrim-fsview"
	ProbeName  = "scrim-fsview-probe"
)

// Status bytes on the helper's status pipe: ready is written just before
// the agent is executed (the pipe then closes on exec), failed precedes an
// error message.
const (
	statusReady  = 'R'
	statusFailed = 'E'
	probeOK      = "scrim-fsview-ok"
)

// Inherited descriptors in the helper.
const (
	fdSpec   = 3
	fdStatus = 4
)

// spec is what the helper receives on fdSpec.
type spec struct {
	Path   string   `json:"path"`
	Args   []string `json:"args"`
	Mounts []mount  `json:"mounts"`
}

type mount struct {
	Source string `json:"source"`
	Target string `json:"target"`
	// ReadOnly remounts the bind read-only (hidden paths).
	ReadOnly bool `json:"read_only,omitempty"`
}

// Main runs the helper when this process was started as one, and never
// returns then. Call it first thing in main and in TestMain.
func Main() {
	switch filepath.Base(os.Args[0]) {
	case HelperName:
		os.Exit(helper())
	case ProbeName:
		os.Exit(probe())
	}
}

// probe checks it can make the mount tree private and bind-mount a file in
// its new namespace: what the helper does.
func probe() int {
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "making the mount tree private: %v\n", err)
		return 1
	}
	exe, err := os.Executable()
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "%v\n", err)
		return 1
	}
	if err := unix.Mount(exe, exe, "", unix.MS_BIND, ""); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "bind mount: %v\n", err)
		return 1
	}
	_, _ = fmt.Fprintln(os.Stdout, probeOK)
	return 0
}

func helper() int {
	statusOut := os.NewFile(fdStatus, "status")
	fail := func(format string, a ...any) int {
		if statusOut != nil {
			_, _ = statusOut.Write(append([]byte{statusFailed}, fmt.Sprintf(format, a...)...))
		}
		return 125
	}
	in := os.NewFile(fdSpec, "spec")
	if in == nil || statusOut == nil {
		return fail("the filesystem view helper was started without its descriptors")
	}
	data, err := io.ReadAll(in)
	_ = in.Close()
	if err != nil {
		return fail("reading the view: %v", err)
	}
	var s spec
	if err := json.Unmarshal(data, &s); err != nil || s.Path == "" || len(s.Args) == 0 {
		return fail("the filesystem view helper got no usable view")
	}
	// The thread that drops the capabilities is the one that executes the
	// agent.
	runtime.LockOSThread()
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		return fail("making the session's mount tree private failed: %v", err)
	}
	for _, m := range s.Mounts {
		if err := unix.Mount(m.Source, m.Target, "", unix.MS_BIND, ""); err != nil {
			return fail("mounting the session's view over %s failed: %v", m.Target, err)
		}
		if m.ReadOnly {
			// Keep the flags the kernel locked (nosuid, nodev, ...) and
			// add rdonly.
			flags := uintptr(0)
			var st unix.Statfs_t
			if err := unix.Statfs(m.Target, &st); err == nil {
				for stf, msf := range map[int64]uintptr{unix.ST_NOSUID: unix.MS_NOSUID, unix.ST_NODEV: unix.MS_NODEV,
					unix.ST_NOEXEC: unix.MS_NOEXEC, unix.ST_NOATIME: unix.MS_NOATIME, unix.ST_NODIRATIME: unix.MS_NODIRATIME,
					unix.ST_RELATIME: unix.MS_RELATIME} {
					if st.Flags&stf != 0 {
						flags |= msf
					}
				}
			}
			if err := unix.Mount("", m.Target, "", unix.MS_REMOUNT|unix.MS_BIND|unix.MS_RDONLY|flags, ""); err != nil {
				return fail("making the hidden %s read-only failed: %v", m.Target, err)
			}
		}
	}
	// The agent runs with no capability: it cannot unmount the view, and
	// the kernel locks the mounts against a namespace it creates itself.
	if err := unix.Prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0); err != nil {
		return fail("dropping capabilities failed: %v", err)
	}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fail("setting no_new_privs failed: %v", err)
	}
	unix.CloseOnExec(fdStatus)
	if _, err := statusOut.Write([]byte{statusReady}); err != nil {
		return 125
	}
	err = unix.Exec(s.Path, s.Args, os.Environ())
	// The ready byte is already written; a second message follows it.
	return fail("starting %s failed: %v", s.Args[0], err)
}

// Probe reports whether exe, started as the probe in a new user and mount
// namespace, can set up the view on this host.
func Probe(ctx context.Context, exe string) Availability {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var out, errb bytes.Buffer
	cmd := exec.CommandContext(ctx, exe) //nolint:gosec // scrim's own executable
	cmd.Args = []string{ProbeName}
	cmd.Env = []string{}
	cmd.Stdout, cmd.Stderr = &out, &errb
	cmd.SysProcAttr = sysProcAttr()
	err := cmd.Run()
	if err == nil && strings.TrimSpace(out.String()) == probeOK {
		return Availability{Namespace: true}
	}
	reason := strings.TrimSpace(errb.String())
	switch {
	case err != nil && reason == "":
		reason = err.Error()
	case err == nil:
		reason = "the probe did not run as the filesystem view helper"
	}
	if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.ENOSPC) || errors.Is(err, syscall.EINVAL) {
		reason = "creating a user namespace is not allowed: " + reason
	}
	return Availability{Reason: reason + availabilityHint()}
}

func availabilityHint() string {
	if b, err := os.ReadFile("/proc/sys/kernel/apparmor_restrict_unprivileged_userns"); err == nil && strings.TrimSpace(string(b)) == "1" {
		return " (AppArmor restricts unprivileged user namespaces: kernel.apparmor_restrict_unprivileged_userns=1)"
	}
	if b, err := os.ReadFile("/proc/sys/user/max_user_namespaces"); err == nil && strings.TrimSpace(string(b)) == "0" {
		return " (user.max_user_namespaces=0)"
	}
	if b, err := os.ReadFile("/proc/sys/kernel/unprivileged_userns_clone"); err == nil && strings.TrimSpace(string(b)) == "0" {
		return " (kernel.unprivileged_userns_clone=0)"
	}
	return ""
}

func sysProcAttr() *syscall.SysProcAttr {
	uid, gid := os.Getuid(), os.Getgid()
	return &syscall.SysProcAttr{
		Cloneflags:                 syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS,
		UidMappings:                []syscall.SysProcIDMap{{ContainerID: uid, HostID: uid, Size: 1}},
		GidMappings:                []syscall.SysProcIDMap{{ContainerID: gid, HostID: gid, Size: 1}},
		GidMappingsEnableSetgroups: false,
		AmbientCaps:                []uintptr{unix.CAP_SYS_ADMIN},
	}
}

// Launch is a command wrapped by [Wrap].
type Launch struct {
	spec, status *os.File // the parent's ends
	child        []*os.File
}

// Wrap turns cmd (Path the resolved agent, Args its command line) into a
// start of the helper exe in a new user and mount namespace, which mounts
// the plan's entries and then executes the agent in place. Call Started
// right after cmd.Start, and Close when done.
func Wrap(cmd *exec.Cmd, exe string, p *Plan) (*Launch, error) {
	if p == nil || p.Mode != ModeNamespace {
		return nil, errors.New("the plan is not a namespace view")
	}
	s := spec{Path: cmd.Path, Args: cmd.Args}
	for _, e := range p.Entries {
		m := mount{Source: e.Source, Target: e.Target}
		if e.Hidden() {
			m.Source, m.ReadOnly = filepath.Join(p.dir, hiddenFile), true
			if e.Dir {
				m.Source = filepath.Join(p.dir, hiddenDir)
			}
		}
		s.Mounts = append(s.Mounts, m)
	}
	data, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}
	specR, specW, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	statusR, statusW, err := os.Pipe()
	if err != nil {
		_ = specR.Close()
		_ = specW.Close()
		return nil, err
	}
	l := &Launch{spec: specW, status: statusR, child: []*os.File{specR, statusW}}
	go func() {
		_, _ = specW.Write(data)
		_ = specW.Close()
	}()
	if len(cmd.ExtraFiles) > 0 {
		l.Close()
		return nil, errors.New("the filesystem view cannot wrap a command with extra descriptors")
	}
	cmd.Path, cmd.Args = exe, []string{HelperName}
	cmd.ExtraFiles = []*os.File{specR, statusW}
	cmd.SysProcAttr = sysProcAttr()
	return l, nil
}

// Started waits until the helper executed the agent, or returns why it did
// not.
func (l *Launch) Started() error {
	for _, f := range l.child {
		_ = f.Close()
	}
	l.child = nil
	b, err := io.ReadAll(l.status)
	_ = l.status.Close()
	if err != nil {
		return fmt.Errorf("reading the filesystem view helper's status: %w", err)
	}
	switch {
	case len(b) == 0:
		return errors.New("the filesystem view helper did not run (the executable does not call fsview.Main)")
	case b[0] == statusReady && len(b) == 1:
		return nil
	case b[0] == statusReady:
		b = b[1:]
	}
	return errors.New(strings.TrimPrefix(string(b), string(rune(statusFailed))))
}

// Close releases the descriptors.
func (l *Launch) Close() {
	for _, f := range append(l.child, l.spec, l.status) {
		if f != nil {
			_ = f.Close()
		}
	}
	l.child = nil
}
