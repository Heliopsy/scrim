// SPDX-License-Identifier: AGPL-3.0-only

//go:build !linux

package execbroker

import "syscall"

func platformAttr(*syscall.SysProcAttr) {}
