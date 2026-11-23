// SPDX-License-Identifier: AGPL-3.0-only

package plugin

import "syscall"

// sysProcAttr puts the plugin in its own process group and kills it if
// scrim dies first.
func sysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
}
