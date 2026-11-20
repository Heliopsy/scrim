// SPDX-License-Identifier: AGPL-3.0-only

package dataplane

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	pb "github.com/heliopsy/scrim/internal/dataplane/dataplanev1"
)

// StartOptions configures [Start].
type StartOptions struct {
	// Mlock is passed as SCRIM_DP_MLOCK: "auto" or "require".
	Mlock string
	// UpstreamCAFile is passed as SCRIM_DP_EXTRA_CA_FILE when set: extra
	// roots for upstream TLS.
	UpstreamCAFile string
	// LogFilter is passed as SCRIM_DP_LOG; default "info".
	LogFilter string
	// Log receives the data plane's log lines, tagged component=dataplane.
	Log *slog.Logger
	// ExtraEnv is appended to the child's environment. For tests.
	ExtraEnv []string
	// forceFile skips the memfd, to test the fallback.
	forceFile bool
}

// Process is a running data plane.
type Process struct {
	// Client calls the data plane.
	Client pb.DataPlaneClient
	// How says how the binary was run: "memfd" or "file".
	How string

	cmd  *exec.Cmd
	conn *grpc.ClientConn
	done chan struct{}
	err  error
	stop sync.Once
}

// Start launches b. The child gets one end of a socketpair as fd 3 and an
// environment holding only its own settings; it inherits nothing else.
func Start(b Binary, o StartOptions) (*Process, error) {
	log := o.Log
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	exe, err := prepare(b, o.forceFile)
	if err != nil && !o.forceFile {
		log.Warn("cannot run the data plane from memory, using a file", "err", err)
		exe, err = prepare(b, true)
	}
	if err != nil {
		return nil, fmt.Errorf("dataplane: preparing %s binary: %w", b.Source, err)
	}
	p, err := spawn(exe, o, log)
	if err != nil && exe.how == "memfd" && execRefused(err) {
		exe.Close()
		log.Warn("the kernel refused to execute the data plane from memory (vm.memfd_noexec?), using a file", "err", err)
		if exe, err = prepare(b, true); err != nil {
			return nil, fmt.Errorf("dataplane: preparing file fallback: %w", err)
		}
		p, err = spawn(exe, o, log)
	}
	exe.Close()
	if err != nil {
		return nil, err
	}
	return p, nil
}

func spawn(exe *executable, o StartOptions, log *slog.Logger) (*Process, error) {
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
		return nil, fmt.Errorf("dataplane: socketpair: %w", err)
	}
	ours := os.NewFile(uintptr(fds[0]), "dataplane-control")
	theirs := os.NewFile(uintptr(fds[1]), "dataplane-child")
	defer func() { _ = theirs.Close() }()

	mlock := o.Mlock
	if mlock == "" {
		mlock = "auto"
	}
	filter := o.LogFilter
	if filter == "" {
		filter = "info"
	}
	env := []string{"SCRIM_DP_FD=" + strconv.Itoa(ChildFD), "SCRIM_DP_MLOCK=" + mlock, "SCRIM_DP_LOG=" + filter}
	if o.UpstreamCAFile != "" {
		env = append(env, "SCRIM_DP_EXTRA_CA_FILE="+o.UpstreamCAFile)
	}
	cmd := &exec.Cmd{
		Path:       exe.path,
		Args:       []string{"scrim-dataplane", "--fd", strconv.Itoa(ChildFD)},
		Env:        append(env, o.ExtraEnv...),
		ExtraFiles: []*os.File{theirs}, // fd 3
	}
	// A plain pipe rather than StderrPipe, so Wait does not race the relay
	// and the last lines before an exit are kept.
	logR, logW, err := os.Pipe()
	if err != nil {
		_ = ours.Close()
		return nil, err
	}
	cmd.Stderr = logW
	err = cmd.Start()
	_ = logW.Close()
	if err != nil {
		_ = logR.Close()
		_ = ours.Close()
		return nil, fmt.Errorf("dataplane: start (%s): %w", exe.how, err)
	}
	go func() {
		relayLogs(logR, log)
		_ = logR.Close()
	}()

	nc, err := net.FileConn(ours)
	_ = ours.Close()
	if err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return nil, fmt.Errorf("dataplane: %w", err)
	}
	conn, err := clientConn(nc)
	if err != nil {
		_ = nc.Close()
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return nil, err
	}
	p := &Process{Client: pb.NewDataPlaneClient(conn), How: exe.how, cmd: cmd, conn: conn, done: make(chan struct{})}
	go func() {
		p.err = cmd.Wait()
		_ = conn.Close()
		close(p.done)
	}()
	return p, nil
}

// clientConn returns a gRPC client over nc. The dialer hands out nc once;
// after the data plane is gone there is nothing to reconnect to, so later
// dials fail and calls return Unavailable.
func clientConn(nc net.Conn) (*grpc.ClientConn, error) {
	var once sync.Once
	dial := func(context.Context, string) (net.Conn, error) {
		var c net.Conn
		once.Do(func() { c = nc })
		if c == nil {
			return nil, errors.New("dataplane: connection already used")
		}
		return c, nil
	}
	return grpc.NewClient("passthrough:///dataplane",
		grpc.WithContextDialer(dial),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
}

// Done is closed when the process has exited.
func (p *Process) Done() <-chan struct{} { return p.done }

// Err is the exit error once Done is closed.
func (p *Process) Err() error { <-p.done; return p.err }

// Pid is the child's process id.
func (p *Process) Pid() int { return p.cmd.Process.Pid }

// Stop closes the socket, which makes the data plane exit, and kills it if
// it has not exited within grace.
func (p *Process) Stop(grace time.Duration) {
	p.stop.Do(func() {
		_ = p.conn.Close()
		select {
		case <-p.done:
		case <-time.After(grace):
			_ = p.cmd.Process.Kill()
			<-p.done
		}
	})
}

// relayLogs forwards the data plane's JSON log lines into log. Lines that
// are not JSON are forwarded as they are. The data plane never logs values,
// and the control plane's logger scrubs known values again.
func relayLogs(r io.Reader, log *slog.Logger) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 4096), 1<<20)
	for sc.Scan() {
		var rec struct {
			Level  string         `json:"level"`
			Target string         `json:"target"`
			Fields map[string]any `json:"fields"`
		}
		line := sc.Bytes()
		if json.Unmarshal(line, &rec) != nil {
			log.Info(string(line), "component", "dataplane")
			continue
		}
		msg, _ := rec.Fields["message"].(string)
		delete(rec.Fields, "message")
		attrs := []any{"component", "dataplane", "target", rec.Target}
		for k, v := range rec.Fields {
			attrs = append(attrs, k, v)
		}
		log.Log(context.Background(), level(rec.Level), msg, attrs...)
	}
}

func level(s string) slog.Level {
	switch s {
	case "ERROR":
		return slog.LevelError
	case "WARN":
		return slog.LevelWarn
	case "DEBUG", "TRACE":
		return slog.LevelDebug
	}
	return slog.LevelInfo
}
