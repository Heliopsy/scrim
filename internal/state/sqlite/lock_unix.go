// SPDX-License-Identifier: AGPL-3.0-only

//go:build unix

package sqlite

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// fileLock is an exclusive advisory lock on path+".lock", held for the life
// of the store, so a second scrim process cannot open the same database.
type fileLock struct{ f *os.File }

func acquireLock(dbPath string) (*fileLock, error) {
	path := dbPath + ".lock"
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600) // #nosec G304 -- path is the configured state file
	if err != nil {
		return nil, fmt.Errorf("opening lock file %q: %w", path, err)
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil { // #nosec G115 -- fd fits in int
		holder := readHolder(f)
		_ = f.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
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
	_ = unix.Flock(int(l.f.Fd()), unix.LOCK_UN) // #nosec G115 -- fd fits in int
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
	if pid <= 0 {
		return 0
	}
	if err := unix.Kill(pid, 0); err != nil && !errors.Is(err, unix.EPERM) {
		return 0
	}
	return pid
}
