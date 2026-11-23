// SPDX-License-Identifier: AGPL-3.0-only

package execbroker

import "syscall"

// platformAttr kills the command when scrim dies, so no brokered process
// outlives the broker that holds its output.
func platformAttr(a *syscall.SysProcAttr) { a.Pdeathsig = syscall.SIGKILL }
