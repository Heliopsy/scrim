// SPDX-License-Identifier: AGPL-3.0-only

package sqlite

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/windows"
)

// lockOffsetHigh places the locked byte far past the end of the lock file.
// Windows byte-range locks are mandatory, so locking the PID itself would
// stop a second process from reading who holds the database.
const lockOffsetHigh = 0x7fffffff

// fileLock is an exclusive lock on path+".lock" (LockFileEx), held for the
// life of the store, so a second scrim process cannot open the same database.
type fileLock struct{ f *os.File }

func acquireLock(dbPath string) (*fileLock, error) {
	path := dbPath + ".lock"
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600) // #nosec G304 -- path is the configured state file
	if err != nil {
		return nil, fmt.Errorf("opening lock file %q: %w", path, err)
	}
	ol := windows.Overlapped{OffsetHigh: lockOffsetHigh}
	err = windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &ol)
	if err != nil {
		holder := readHolder(f)
		_ = f.Close()
		if errors.Is(err, windows.ERROR_LOCK_VIOLATION) || errors.Is(err, windows.ERROR_IO_PENDING) {
			return nil, &LockedError{Path: dbPath, PID: holder}
		}
		return nil, fmt.Errorf("locking %q: %w", path, err)
	}
	if err := f.Truncate(0); err == nil {
		_, _ = f.WriteAt([]byte(strconv.Itoa(os.Getpid())+"\n"), 0)
		_ = f.Sync()
	}
	return &fileLock{f: f}, nil
}

func readHolder(f *os.File) int {
	buf := make([]byte, 32)
	n, _ := f.ReadAt(buf, 0)
	pid, err := strconv.Atoi(strings.TrimSpace(string(buf[:n])))
	if err != nil {
		return 0
	}
	return pid
}

func (l *fileLock) release() {
	if l == nil || l.f == nil {
		return
	}
	_ = l.f.Truncate(0)
	ol := windows.Overlapped{OffsetHigh: lockOffsetHigh}
	_ = windows.UnlockFileEx(windows.Handle(l.f.Fd()), 0, 1, 0, &ol)
	_ = l.f.Close()
	l.f = nil
}

// lockHolder reads the PID a holder wrote into dbPath+".lock" without
// locking the file, and checks the process still exists.
func lockHolder(dbPath string) int {
	f, err := os.Open(dbPath + ".lock") // #nosec G304 -- path is the configured state file
	if err != nil {
		return 0
	}
	defer func() { _ = f.Close() }()
	pid := readHolder(f)
	if pid <= 0 || pid > 1<<31-1 {
		return 0
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid)) // #nosec G115 -- checked above
	if err != nil {
		if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
			return pid
		}
		return 0
	}
	defer func() { _ = windows.CloseHandle(h) }()
	var code uint32
	if windows.GetExitCodeProcess(h, &code) == nil && code != 259 { // STILL_ACTIVE
		return 0
	}
	return pid
}
