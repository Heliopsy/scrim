// SPDX-License-Identifier: AGPL-3.0-only

package identity

import (
	"errors"
	"fmt"
)

// ErrNoProcessInfo is returned where the platform cannot report a process's
// parent and start time. Session tokens bound to a process tree are refused
// there, never accepted unchecked.
var ErrNoProcessInfo = errors.New("identity: process information is not available")

// errNoProcess means the process does not exist (any more).
var errNoProcess = errors.New("identity: no such process")

// Proc is what the binding of a session to a process tree needs to know
// about one process. Start is an opaque, platform-specific start time used to
// tell a process from a later one that reused its PID.
type Proc struct {
	PID   int32
	PPID  int32
	Start uint64
}

// ProcInfo reports processes. The real implementation reads the operating
// system; tests substitute their own tree.
type ProcInfo interface {
	Lookup(pid int32) (Proc, error)
}

// OSProcs is the operating system's process table.
type OSProcs struct{}

// Lookup reports one process.
func (OSProcs) Lookup(pid int32) (Proc, error) { return lookupProc(pid) }

// maxDepth bounds the walk up the process tree.
const maxDepth = 256

// descends reports whether pid is root or one of its descendants. It walks
// pid's parents up to init. root is identified by PID and start time, so a
// new process that reused root's PID does not count as root.
func descends(pi ProcInfo, pid int32, root Proc) (bool, error) {
	if pid <= 0 || root.PID <= 0 {
		return false, nil
	}
	cur := pid
	for range maxDepth {
		p, err := pi.Lookup(cur)
		if err != nil {
			if errors.Is(err, errNoProcess) {
				return false, nil
			}
			return false, err
		}
		if p.PID == root.PID {
			return p.Start == root.Start, nil
		}
		if p.PPID <= 0 || p.PPID == p.PID {
			return false, nil
		}
		cur = p.PPID
	}
	return false, fmt.Errorf("identity: process tree of %d deeper than %d", pid, maxDepth)
}
