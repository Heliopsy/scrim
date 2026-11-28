// SPDX-License-Identifier: AGPL-3.0-only

package fsview

// readable is never asked on Windows, which has no filesystem view.
func readable(string, bool) bool { return false }
