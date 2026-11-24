// SPDX-License-Identifier: AGPL-3.0-only

//go:build !windows

package daemon

import "github.com/heliopsy/scrim/internal/config"

// platformRefusals is empty on Linux and macOS: Linux-only features
// (transparent mode, eBPF) report themselves where they are set up.
func platformRefusals(*config.Config) []string { return nil }
