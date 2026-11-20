// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package identity

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strconv"
)

// lookupProc reads /proc/<pid>/stat. The command name in field 2 may hold
// spaces and parentheses, so fields are counted from the last ')'.
func lookupProc(pid int32) (Proc, error) {
	raw, err := os.ReadFile("/proc/" + strconv.FormatInt(int64(pid), 10) + "/stat")
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return Proc{}, errNoProcess
		}
		return Proc{}, fmt.Errorf("%w: %w", ErrNoProcessInfo, err)
	}
	return parseStat(pid, raw)
}

func parseStat(pid int32, raw []byte) (Proc, error) {
	end := bytes.LastIndexByte(raw, ')')
	if end < 0 {
		return Proc{}, fmt.Errorf("%w: malformed stat for %d", ErrNoProcessInfo, pid)
	}
	// After ") ": field 3 (state) is index 0, field 4 (ppid) index 1,
	// field 22 (starttime) index 19.
	fields := bytes.Fields(raw[end+1:])
	if len(fields) < 20 {
		return Proc{}, fmt.Errorf("%w: short stat for %d", ErrNoProcessInfo, pid)
	}
	ppid, err := strconv.ParseInt(string(fields[1]), 10, 32)
	if err != nil {
		return Proc{}, fmt.Errorf("%w: ppid of %d: %w", ErrNoProcessInfo, pid, err)
	}
	start, err := strconv.ParseUint(string(fields[19]), 10, 64)
	if err != nil {
		return Proc{}, fmt.Errorf("%w: start time of %d: %w", ErrNoProcessInfo, pid, err)
	}
	return Proc{PID: pid, PPID: int32(ppid), Start: start}, nil
}
