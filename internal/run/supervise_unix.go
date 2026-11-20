// SPDX-License-Identifier: AGPL-3.0-only

//go:build unix

package run

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"golang.org/x/sys/unix"
)

// forwarded are the signals scrim run passes to the agent.
var forwarded = []os.Signal{syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT, syscall.SIGUSR1, syscall.SIGUSR2}

// fromTerminal are the signals a terminal sends to its whole foreground
// process group, the agent included.
var fromTerminal = map[os.Signal]bool{syscall.SIGINT: true, syscall.SIGQUIT: true}

// supervise starts cmd and waits for it, forwarding signals. It does not
// stop the agent when the command's context ends: the context is cancelled
// by Ctrl-C, which the agent handles itself (Claude Code, for one, treats
// the first Ctrl-C as "clear the input").
func supervise(cmd *exec.Cmd, sigs <-chan os.Signal, stderr io.Writer) error {
	if sigs == nil {
		own := make(chan os.Signal, 8)
		signal.Notify(own, forwarded...)
		defer signal.Stop(own)
		sigs = own
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("%w: starting %s failed: %w", ErrRefused, cmd.Args[0], err)
	}
	// When the agent shares our foreground process group on a terminal, a
	// Ctrl-C reaches it directly; forwarding it again would deliver it twice.
	shared := sharesForeground()
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	for {
		select {
		case s := <-sigs:
			if shared && fromTerminal[s] {
				continue
			}
			if err := cmd.Process.Signal(s); err != nil && !errors.Is(err, os.ErrProcessDone) {
				_, _ = fmt.Fprintf(stderr, "scrim run: forwarding %v failed: %v\n", s, err)
			}
		case err := <-done:
			return exitStatus(err)
		}
	}
}

func sharesForeground() bool {
	fg, err := unix.IoctlGetInt(0, unix.TIOCGPGRP)
	return err == nil && fg == unix.Getpgrp()
}

// exitStatus maps the agent's end to an *ExitError, using the shell's
// 128+signal convention for a signal death.
func exitStatus(err error) error {
	if err == nil {
		return nil
	}
	var xe *exec.ExitError
	if !errors.As(err, &xe) {
		return err
	}
	if ws, ok := xe.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		return &ExitError{Code: 128 + int(ws.Signal()), Signal: unix.SignalName(ws.Signal())}
	}
	return &ExitError{Code: xe.ExitCode()}
}
