// SPDX-License-Identifier: AGPL-3.0-only

//go:build unix

package dataplane

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"syscall"
)

// channel is the boundary connection: one end of a socketpair for each
// side. The child finds its end as fd 3 (ChildFD).
type channel struct {
	ours, theirs *os.File
}

func newChannel() (*channel, error) {
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
	return &channel{
		ours:   os.NewFile(uintptr(fds[0]), "dataplane-control"),
		theirs: os.NewFile(uintptr(fds[1]), "dataplane-child"),
	}, nil
}

func (c *channel) args() []string { return []string{"--fd", strconv.Itoa(ChildFD)} }

func (c *channel) env() []string { return []string{"SCRIM_DP_FD=" + strconv.Itoa(ChildFD)} }

func (c *channel) attach(cmd *exec.Cmd) { cmd.ExtraFiles = []*os.File{c.theirs} } // fd 3

func (c *channel) closeChild() { _ = c.theirs.Close() }

func (c *channel) closeParent() { _ = c.ours.Close() }

// conn turns our end into a net.Conn; the file itself is closed either way.
func (c *channel) conn() (net.Conn, error) {
	nc, err := net.FileConn(c.ours)
	_ = c.ours.Close()
	return nc, err
}
