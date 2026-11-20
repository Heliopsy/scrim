// SPDX-License-Identifier: AGPL-3.0-only

//go:build darwin

package identity

import (
	"errors"
	"fmt"

	"golang.org/x/sys/unix"
)

// lookupProc asks sysctl kern.proc.pid for the parent and start time.
func lookupProc(pid int32) (Proc, error) {
	k, err := unix.SysctlKinfoProc("kern.proc.pid", int(pid))
	if err != nil {
		if errors.Is(err, unix.ESRCH) {
			return Proc{}, errNoProcess
		}
		return Proc{}, fmt.Errorf("%w: %w", ErrNoProcessInfo, err)
	}
	if k.Proc.P_pid != pid {
		// sysctl answers with an empty record for a missing PID.
		return Proc{}, errNoProcess
	}
	st := k.Proc.P_starttime
	start := uint64(st.Sec)*1_000_000 + uint64(st.Usec) // #nosec G115 -- times after 1970 are positive
	return Proc{PID: pid, PPID: k.Eproc.Ppid, Start: start}, nil
}
