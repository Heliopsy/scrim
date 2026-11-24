// SPDX-License-Identifier: AGPL-3.0-only

package run

// tryUnmount reports what unmounting path gives the agent: Windows has no
// mounts to undo, and no filesystem view to escape.
func tryUnmount(string) string { return "ERR: not supported on windows" }
