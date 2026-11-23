// SPDX-License-Identifier: AGPL-3.0-only

//go:build unix && !linux

package plugin

import "syscall"

// sysProcAttr puts the plugin in its own process group. The plugin exits
// when its socket closes, which is also what happens when scrim dies.
func sysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setpgid: true}
}
