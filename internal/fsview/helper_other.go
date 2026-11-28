// SPDX-License-Identifier: AGPL-3.0-only

//go:build !linux

package fsview

import (
	"context"
	"errors"
	"os/exec"
	"runtime"
)

// HelperName and ProbeName exist on Linux only; see helper_linux.go.
const (
	HelperName = "scrim-fsview"
	ProbeName  = "scrim-fsview-probe"
)

// Main does nothing: there is no namespace helper on this platform.
func Main() {}

// Probe reports that this platform has no mount namespaces.
func Probe(context.Context, string) Availability {
	return Availability{Reason: runtime.GOOS + " has no user or mount namespaces"}
}

// ProbeNetwork reports that this platform has no network namespaces.
func ProbeNetwork(context.Context, string) Availability {
	return Availability{Reason: runtime.GOOS + " has no unprivileged network namespaces"}
}

// Launch is not used on this platform.
type Launch struct{}

// Wrap always fails: the namespace view exists on Linux only.
func Wrap(*exec.Cmd, string, *Plan, *Network) (*Launch, error) {
	return nil, errors.New("the namespace filesystem view and network namespace need Linux")
}

// Listeners is never reached.
func (*Launch) Listeners() []Listener { return nil }

// Started is never reached.
func (*Launch) Started() error { return nil }

// Close does nothing.
func (*Launch) Close() {}
