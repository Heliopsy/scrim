// SPDX-License-Identifier: AGPL-3.0-only

//go:build !unix

package sqlite

type fileLock struct{}

// acquireLock is a no-op where advisory file locks are unavailable; SQLite's
// own locking still serialises writers.
func acquireLock(string) (*fileLock, error) { return &fileLock{}, nil }

func (*fileLock) release() {}

func lockHolder(string) int { return 0 }
