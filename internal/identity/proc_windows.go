// SPDX-License-Identifier: AGPL-3.0-only

package identity

import (
	"errors"
	"fmt"
	"math"
	"unsafe"

	"golang.org/x/sys/windows"
)

// lookupProc reads the parent from a process snapshot and the start time
// from the process's creation time (100 ns units since 1601).
//
// Windows keeps a process's parent PID after the parent exits, and that PID
// can be reused by an unrelated process. A parent created after its child
// is such a reuse, so the link is cut there (PPID 0) instead of walking into
// another process tree.
func lookupProc(pid int32) (Proc, error) {
	if pid <= 0 {
		return Proc{}, errNoProcess
	}
	start, err := creationTime(uint32(pid))
	if err != nil {
		return Proc{}, err
	}
	ppid, err := parentOf(uint32(pid))
	if err != nil {
		return Proc{}, err
	}
	p := Proc{PID: pid, Start: start}
	if ppid > 0 && ppid <= math.MaxInt32 {
		if ps, err := creationTime(ppid); err == nil && ps <= start {
			p.PPID = int32(ppid)
		}
	}
	return p, nil
}

func creationTime(pid uint32) (uint64, error) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		if errors.Is(err, windows.ERROR_INVALID_PARAMETER) {
			return 0, errNoProcess
		}
		return 0, fmt.Errorf("%w: %w", ErrNoProcessInfo, err)
	}
	defer func() { _ = windows.CloseHandle(h) }()
	var created, exited, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(h, &created, &exited, &kernel, &user); err != nil {
		return 0, fmt.Errorf("%w: %w", ErrNoProcessInfo, err)
	}
	var code uint32
	if err := windows.GetExitCodeProcess(h, &code); err == nil && code != stillActive {
		return 0, errNoProcess // exited; the handle only keeps its record
	}
	return uint64(created.HighDateTime)<<32 | uint64(created.LowDateTime), nil
}

// stillActive is STILL_ACTIVE, the exit code of a running process.
const stillActive = 259

func parentOf(pid uint32) (uint32, error) {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return 0, fmt.Errorf("%w: %w", ErrNoProcessInfo, err)
	}
	defer func() { _ = windows.CloseHandle(snap) }()
	var e windows.ProcessEntry32
	e.Size = uint32(unsafe.Sizeof(e))
	for err = windows.Process32First(snap, &e); err == nil; err = windows.Process32Next(snap, &e) {
		if e.ProcessID == pid {
			return e.ParentProcessID, nil
		}
	}
	if errors.Is(err, windows.ERROR_NO_MORE_FILES) {
		return 0, errNoProcess
	}
	return 0, fmt.Errorf("%w: %w", ErrNoProcessInfo, err)
}
