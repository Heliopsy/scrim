// SPDX-License-Identifier: AGPL-3.0-only

//go:build unix && !linux

package execbroker

import "syscall"

func platformAttr(*syscall.SysProcAttr) {}
