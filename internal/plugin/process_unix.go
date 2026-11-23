// SPDX-License-Identifier: AGPL-3.0-only

//go:build unix

package plugin

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"sync"
	"syscall"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	pb "github.com/heliopsy/scrim/pkg/plugin/pluginv1"
)

// spawn starts the plugin at path with one end of a socketpair as fd 3,
// stdin and stdout on /dev/null and stderr relayed into log. It inherits no
// other descriptor and only the environment Config gives it.
func spawn(path string, c Config, log *slog.Logger) (*proc, error) {
	// ForkLock keeps a concurrent exec elsewhere in the process from
	// inheriting the pair before it is close-on-exec.
	syscall.ForkLock.RLock()
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err == nil {
		syscall.CloseOnExec(fds[0])
		syscall.CloseOnExec(fds[1])
	}
	syscall.ForkLock.RUnlock()
	if err != nil {
		return nil, fmt.Errorf("socketpair: %w", err)
	}
	ours := os.NewFile(uintptr(fds[0]), "plugin-scrim")
	theirs := os.NewFile(uintptr(fds[1]), "plugin-child")
	defer func() { _ = theirs.Close() }()

	logR, logW, err := os.Pipe()
	if err != nil {
		_ = ours.Close()
		return nil, err
	}
	cmd := &exec.Cmd{
		Path:        path,
		Args:        append([]string{path}, c.Args...),
		Env:         c.environ(),
		Dir:         "/",
		Stderr:      logW,
		ExtraFiles:  []*os.File{theirs}, // fd 3
		SysProcAttr: sysProcAttr(),
	}
	err = cmd.Start()
	_ = logW.Close()
	if err != nil {
		_ = logR.Close()
		_ = ours.Close()
		return nil, fmt.Errorf("start: %w", err)
	}
	go func() {
		relay(logR, log)
		_ = logR.Close()
	}()
	nc, err := net.FileConn(ours)
	_ = ours.Close()
	if err != nil {
		killGroup(cmd.Process.Pid)
		_ = cmd.Wait()
		return nil, err
	}
	conn, err := clientConn(nc)
	if err != nil {
		_ = nc.Close()
		killGroup(cmd.Process.Pid)
		_ = cmd.Wait()
		return nil, err
	}
	p := &proc{conn: conn, pid: cmd.Process.Pid, done: make(chan struct{})}
	go func() {
		p.err = cmd.Wait()
		// Whatever the plugin started in its process group goes with it.
		killGroup(p.pid)
		_ = conn.Close()
		close(p.done)
	}()
	return p, nil
}

// clientConn returns a gRPC client over nc. The dialer hands nc out once;
// a plugin that is gone has nothing to reconnect to.
func clientConn(nc net.Conn) (*grpc.ClientConn, error) {
	var once sync.Once
	dial := func(context.Context, string) (net.Conn, error) {
		var c net.Conn
		once.Do(func() { c = nc })
		if c == nil {
			return nil, errors.New("plugin connection already used")
		}
		return c, nil
	}
	return grpc.NewClient("passthrough:///plugin",
		grpc.WithContextDialer(dial),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(grpc.ForceCodecV2(pb.Codec())),
	)
}

func killGroup(pid int) {
	if pid > 0 {
		_ = syscall.Kill(-pid, syscall.SIGKILL)
	}
}
