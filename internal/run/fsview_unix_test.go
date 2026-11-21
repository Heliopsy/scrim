// SPDX-License-Identifier: AGPL-3.0-only

//go:build unix

package run

import "golang.org/x/sys/unix"

// tryUnmount reports what unmounting path gives the agent.
func tryUnmount(path string) string {
	if err := unix.Unmount(path, 0); err != nil {
		return "ERR: " + err.Error()
	}
	return "unmounted"
}
