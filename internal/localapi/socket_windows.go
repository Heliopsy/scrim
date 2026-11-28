// SPDX-License-Identifier: AGPL-3.0-only

package localapi

import "io/fs"

// setMode does nothing on Windows: an AF_UNIX socket file has no mode bits,
// and who may connect is decided by the directory's DACL, which
// fsperm.MkdirPrivate restricted to this account, SYSTEM and Administrators.
// A wider socket mode (api.permissions) is refused at start-up there.
func setMode(string, fs.FileMode) error { return nil }
