// SPDX-License-Identifier: AGPL-3.0-only

//go:build !linux && !darwin

package sqlite

// detectFS cannot classify filesystems on this platform.
func detectFS(string) FSKind { return FSUnknown }
